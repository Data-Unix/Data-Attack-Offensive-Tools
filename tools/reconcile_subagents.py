#!/usr/bin/env python3
"""
reconcile_subagents.py — Backfill DETERMINISTA de `evidence/subagents.jsonl` desde los transcripts.

El hook `SubagentStop` (`.claude/hooks/subagent_stop.py`, control C10) SÍ dispara en modo headless
(`claude -p`) pero de forma NO DETERMINISTA a nivel de SESIÓN: sesiones con subagentes que completaron
de verdad (tienen `tool_result` en su transcript) a veces no dejan NINGUNA línea de auditoría. Es una
limitación upstream de Claude Code (anthropics/claude-code#33049, #20063), no un bug de
`subagent_stop.py` (el hook es correcto: escribe siempre que se le invoca).

Este script NO sustituye al hook — lo COMPLEMENTA. Los transcripts de Claude Code
(`~/.claude/projects/<slug>/<session_id>.jsonl`) registran de forma FIABLE cada invocación del
Agent/Task tool (`type:"assistant"` → `message.content[]` con `{"type":"tool_use","name":"Agent"|
"Task","input":{"subagent_type":…}}`) y su compleción (`{"type":"tool_result","tool_use_id":…}` en un
mensaje `type:"user"`). Cruzando eso con lo ya escrito en `subagents.jsonl`, este script ANEXA
(append-only, nunca reescribe) las líneas que falten, marcadas `"source":"transcript-reconcile"` para
distinguirlas de las del hook en vivo (`"source":"hook-live"` — implícito si el campo no existe, para
no tocar líneas antiguas).

Dedupe: como las líneas del hook no llevan `tool_use_id` (llevan `agent_id`, el id interno del
subagente — no confundir con el `toolu_…` del transcript), el dedupe es por CONTEO: para cada clave
`(session_id, subagent_type)`, si el nº de spawns completados en el transcript supera al nº de líneas
YA registradas para esa clave (hook + backfills previos), se rellena la diferencia. Backfills previos
se identifican por su propio `tool_use_id` (sí lo llevan) → correr esto dos veces NUNCA duplica.

Aislamiento (E3): solo procesa transcripts donde aparece el `engagement_id` objetivo (grep de
substring); nunca mezcla engagements ni vuelca contenido de transcript al blackboard/logs — solo
metadatos (agent_type, ts, ids).

Fail-safe: pensado para enlazarse como paso post-grade de `run_gate.py` (best-effort); un fallo aquí
NUNCA debe afectar al veredicto del gate.

    python tools/reconcile_subagents.py --engagement-id GATE-dockerlabs-injection
    python tools/reconcile_subagents.py --engagement-id GATE-dockerlabs-injection --dry-run
    python tools/reconcile_subagents.py --engagement-id GATE-dockerlabs-injection --json
"""
import argparse
import glob
import json
import os
import re
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENT_TOOL_NAMES = ("Agent", "Task")  # v2.1.220 usa "Agent"; tolerante a "Task" por si cambia.

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass


def engagement_id_from_blackboard():
    """Mismo criterio que el hook: engagement_id del blackboard actual, o None. Resuelve la ruta a
    partir de ROOT en el momento de la llamada (no precomputada) para que apunte al repo correcto
    aunque ROOT se reasigne (tests)."""
    try:
        with open(os.path.join(ROOT, "contracts", "engagement.json"), encoding="utf-8") as f:
            return json.load(f).get("engagement_id")
    except Exception:
        return None


def audit_file_for(root, eid):
    """Ruta de `subagents.jsonl` para este engagement (mismo layout que el hook)."""
    return os.path.join(root, "engagements", str(eid), "evidence", "subagents.jsonl")


def _project_slug(path):
    """Slug de directorio de proyecto de Claude Code: cada carácter no alfanumérico -> '-'."""
    return re.sub(r"[^A-Za-z0-9]", "-", os.path.abspath(path))


def _transcript_matches_cwd(path, root, max_lines=25):
    """Fallback: ¿el transcript declara `cwd` == root en sus primeras líneas?"""
    root_abs = os.path.abspath(root)
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    o = json.loads(line)
                except ValueError:
                    continue
                cwd = o.get("cwd")
                if cwd and os.path.abspath(cwd) == root_abs:
                    return True
    except OSError:
        pass
    return False


def find_transcripts(root):
    """Ficheros `<session_id>.jsonl` candidatos para este repo (slug directo + fallback por cwd)."""
    projects_dir = os.path.join(os.path.expanduser("~"), ".claude", "projects")
    if not os.path.isdir(projects_dir):
        return []
    slug = _project_slug(root)
    direct = os.path.join(projects_dir, slug)
    if os.path.isdir(direct):
        files = glob.glob(os.path.join(direct, "*.jsonl"))
        if files:
            return files
    # Fallback: escanea todos los proyectos y filtra por cwd real (slug pudo diferir por versión/plataforma).
    found = []
    for d in glob.glob(os.path.join(projects_dir, "*")):
        if not os.path.isdir(d):
            continue
        for f in glob.glob(os.path.join(d, "*.jsonl")):
            if _transcript_matches_cwd(f, root):
                found.append(f)
    return found


def parse_transcript(path, engagement_id):
    """(spawns, completed_ids, relevant) de un transcript.
    spawns: [{"tool_use_id","subagent_type","ts","session_id","transcript_path"}].
    Aislamiento E3 a nivel de REGISTRO, no de fichero completo: un spawn solo cuenta si
    `engagement_id` aparece en la MISMA línea (turno `assistant`) que lo contiene — no basta con que
    el id aparezca en cualquier otro punto del transcript. Esto importa porque una sesión larga puede,
    en teoría, tocar más de un engagement (el operador cambia de encargo sin reiniciar la CLI); el
    playbook (AGENTS.md "Directorio de salida") hace que cada delegación real mencione
    `engagements/<engagement_id>/…` en su propio prompt, así que el turno que delega SÍ lleva el id
    consigo — filtrar por línea evita atribuir a este engagement la actividad de otro que solo se
    mencionara en otra parte del mismo fichero. `relevant` = True si ≥1 spawn calificó (para stats)."""
    session_id = os.path.splitext(os.path.basename(path))[0]
    spawns, completed = [], set()
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    o = json.loads(line)
                except ValueError:
                    continue
                rtype = o.get("type")
                msg = o.get("message") or {}
                content = msg.get("content")
                if not isinstance(content, list):
                    continue
                if rtype == "assistant":
                    if not (engagement_id and engagement_id in line):
                        continue  # este turno no menciona el engagement -> sus spawns no cuentan (E3)
                    for c in content:
                        if (isinstance(c, dict) and c.get("type") == "tool_use"
                                and c.get("name") in AGENT_TOOL_NAMES):
                            inp = c.get("input") or {}
                            st = inp.get("subagent_type")
                            if not st:
                                continue
                            spawns.append({
                                "tool_use_id": c.get("id"),
                                "subagent_type": st,
                                "ts": o.get("timestamp"),
                                "session_id": session_id,
                                "transcript_path": path,
                            })
                elif rtype == "user":
                    for c in content:
                        if isinstance(c, dict) and c.get("type") == "tool_result" and c.get("tool_use_id"):
                            completed.add(c["tool_use_id"])
    except OSError:
        return [], set(), False
    return spawns, completed, bool(spawns)


def existing_lines(audit_path):
    """Líneas ya escritas en subagents.jsonl (hook-live + backfills previos). [] si no existe/ilegible."""
    if not os.path.isfile(audit_path):
        return []
    out = []
    try:
        with open(audit_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        pass
    return out


def _iso_ts(ts):
    """Normaliza el timestamp del transcript (ISO con milis+Z) al formato del hook (segundos+Z)."""
    if not ts:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        t = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(t).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:  # noqa: BLE001
        return ts


def reconcile(root, engagement_id, transcript_paths=None):
    """Calcula las líneas de backfill que faltan para `engagement_id`. Devuelve (lineas_nuevas, stats)."""
    audit_path = audit_file_for(root, engagement_id)
    existing = existing_lines(audit_path)

    hook_counts = {}          # (session_id, subagent_type) -> nº de líneas hook-live existentes
    reconciled_ids = set()    # tool_use_id ya backfilleados (idempotencia exacta)
    for rec in existing:
        key = (rec.get("session_id"), rec.get("agent_type"))
        if rec.get("source") == "transcript-reconcile":
            if rec.get("tool_use_id"):
                reconciled_ids.add(rec["tool_use_id"])
        else:
            hook_counts[key] = hook_counts.get(key, 0) + 1

    paths = transcript_paths if transcript_paths is not None else find_transcripts(root)
    spawns_by_key = {}
    scanned, skipped_irrelevant = 0, 0
    for path in paths:
        spawns, completed, relevant = parse_transcript(path, engagement_id)
        scanned += 1
        if not relevant:
            skipped_irrelevant += 1
            continue
        for s in spawns:
            if s["tool_use_id"] not in completed:
                continue  # huérfano (spawn sin tool_result) -> NO se backfillea
            key = (s["session_id"], s["subagent_type"])
            spawns_by_key.setdefault(key, []).append(s)

    new_lines = []
    for key, spawns in spawns_by_key.items():
        spawns.sort(key=lambda s: s.get("ts") or "")
        candidates = [s for s in spawns if s["tool_use_id"] not in reconciled_ids]
        already_covered = hook_counts.get(key, 0) + (len(spawns) - len(candidates))
        need = len(spawns) - already_covered
        if need <= 0:
            continue
        for s in candidates[:need]:
            new_lines.append({
                "ts": _iso_ts(s["ts"]),
                "event": "SubagentStop",
                "agent_type": s["subagent_type"],
                "agent_id": None,
                "session_id": s["session_id"],
                "engagement_id": engagement_id,
                "transcript_path": s["transcript_path"],
                "source": "transcript-reconcile",
                "tool_use_id": s["tool_use_id"],
            })

    stats = {
        "engagement_id": engagement_id,
        "audit_file": audit_path,
        "transcripts_scanned": scanned,
        "transcripts_skipped_irrelevant": skipped_irrelevant,
        "existing_lines": len(existing),
        "backfilled": len(new_lines),
    }
    return new_lines, stats


def write_lines(audit_path, new_lines):
    if not new_lines:
        return
    os.makedirs(os.path.dirname(audit_path), exist_ok=True)
    with open(audit_path, "a", encoding="utf-8") as f:
        for rec in new_lines:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--engagement-id", help="por defecto, el del blackboard actual (contracts/engagement.json)")
    ap.add_argument("--dry-run", action="store_true", help="calcula y muestra, no escribe")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    eid = args.engagement_id or engagement_id_from_blackboard()
    if not eid:
        msg = "Sin engagement_id (ni --engagement-id ni contracts/engagement.json). Nada que reconciliar."
        print(json.dumps({"status": "sin-engagement-id", "detail": msg}, ensure_ascii=False) if args.json
              else f"[i] {msg}")
        sys.exit(0)  # fail-safe: no es un error del gate, solo no hay nada que hacer

    if not re.match(r"^[A-Za-z0-9_.-]+$", eid):
        msg = f"engagement_id {eid!r} tiene caracteres no válidos (evita traversal/inyección de ruta)."
        print(json.dumps({"status": "engagement-id-invalido", "detail": msg}, ensure_ascii=False) if args.json
              else f"[!] {msg}")
        sys.exit(0)  # fail-safe: nunca romper el flujo que nos invoque, solo no reconcilia

    try:
        new_lines, stats = reconcile(ROOT, eid)
    except Exception as exc:  # noqa: BLE001 — fail-safe: nunca romper el flujo que nos invoque
        msg = f"reconcile_subagents: error no fatal ({exc}); no se tocó subagents.jsonl"
        print(json.dumps({"status": "error", "detail": msg}, ensure_ascii=False) if args.json else f"[!] {msg}")
        sys.exit(0)

    if not args.dry_run:
        write_lines(stats["audit_file"], new_lines)

    if args.json:
        print(json.dumps({"status": "ok", "dry_run": args.dry_run, **stats,
                           "new_lines": new_lines if args.dry_run else None}, ensure_ascii=False, indent=2))
    else:
        print(f"[reconcile] engagement={eid}  transcripts={stats['transcripts_scanned']}"
              f" (irrelevantes={stats['transcripts_skipped_irrelevant']})"
              f"  ya-escritas={stats['existing_lines']}  backfill={stats['backfilled']}"
              f"{'  (dry-run, no escrito)' if args.dry_run else ''}")
        if args.dry_run:
            for rec in new_lines:
                print(f"    + {rec['session_id'][:8]}…  {rec['agent_type']}  {rec['ts']}")
    sys.exit(0)


if __name__ == "__main__":
    main()
