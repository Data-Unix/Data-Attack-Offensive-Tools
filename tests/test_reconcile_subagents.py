#!/usr/bin/env python3
"""Tests de `tools/reconcile_subagents.py` (backfill determinista de subagents.jsonl desde transcripts).

Cubre los casos mínimos del ROADMAP: (a) backfill exacto de spawns completados, (b) idempotencia,
(c) huérfanos no se escriben, (d) respeta líneas de hook ya presentes, (e) ignora transcripts de otro
engagement (aislamiento E3).

    python tests/test_reconcile_subagents.py    (sale 1 si algo falla).
"""
import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import reconcile_subagents as rs  # noqa: E402

PASS, FAIL = 0, 0


def ok(cond, msg):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print(f"  [FALLO] {msg}")


def write_transcript(path, records):
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def spawn_rec(tool_use_id, subagent_type, ts, engagement_marker=None):
    """Un record 'assistant' con un tool_use Agent -- opcionalmente con el engagement_id embebido
    en el texto (simula que el prompt de delegación lo mencionaba, como en un transcript real)."""
    content = [{"type": "tool_use", "name": "Agent", "id": tool_use_id,
                "input": {"subagent_type": subagent_type,
                          "prompt": f"engagement={engagement_marker}" if engagement_marker else "x"}}]
    return {"type": "assistant", "timestamp": ts, "message": {"content": content}}


def result_rec(tool_use_id, ts):
    return {"type": "user", "timestamp": ts,
            "message": {"content": [{"type": "tool_result", "tool_use_id": tool_use_id, "content": "ok"}]}}


tmpdir = tempfile.mkdtemp(prefix="reconcile-test-")
_orig_root = rs.ROOT
rs.ROOT = tmpdir
EID = "GATE-synthtest"

try:
    # ── (a) 3 spawns, 2 completados -> backfill escribe exactamente 2 líneas ────────────────────
    t1 = os.path.join(tmpdir, "sessA.jsonl")
    write_transcript(t1, [
        spawn_rec("toolu_1", "active-recon", "2026-01-01T00:00:01.000Z", EID),
        result_rec("toolu_1", "2026-01-01T00:00:02.000Z"),
        spawn_rec("toolu_2", "vuln-triage", "2026-01-01T00:00:03.000Z", EID),
        result_rec("toolu_2", "2026-01-01T00:00:04.000Z"),
        spawn_rec("toolu_3", "web-exploit", "2026-01-01T00:00:05.000Z", EID),
        # toolu_3 SIN tool_result -> huérfano, caso (c)
    ])
    new_lines, stats = rs.reconcile(tmpdir, EID, transcript_paths=[t1])
    ok(len(new_lines) == 2, f"(a) backfill de 2 completados, no 3 (huérfano excluido): {len(new_lines)}")
    ok({l["agent_type"] for l in new_lines} == {"active-recon", "vuln-triage"},
       f"(a) tipos correctos: {[l['agent_type'] for l in new_lines]}")
    ok(all(l["source"] == "transcript-reconcile" for l in new_lines), "(a) source=transcript-reconcile")
    ok(not any(l["agent_type"] == "web-exploit" for l in new_lines), "(c) el huérfano web-exploit NO aparece")

    audit_path = rs.audit_file_for(tmpdir, EID)
    rs.write_lines(audit_path, new_lines)
    ok(os.path.isfile(audit_path), "(a) fichero de auditoría creado")

    # ── (b) idempotencia: reconciliar de nuevo NO duplica ───────────────────────────────────────
    new_lines2, stats2 = rs.reconcile(tmpdir, EID, transcript_paths=[t1])
    ok(len(new_lines2) == 0, f"(b) 2ª pasada no añade líneas nuevas: {len(new_lines2)}")
    rs.write_lines(audit_path, new_lines2)
    with open(audit_path, encoding="utf-8") as f:
        total = sum(1 for _ in f)
    ok(total == 2, f"(b) el fichero sigue con 2 líneas tras re-correr: {total}")

    # ── (d) respeta una línea de hook YA presente (no la duplica) ───────────────────────────────
    t2 = os.path.join(tmpdir, "sessB.jsonl")
    write_transcript(t2, [
        spawn_rec("toolu_10", "network-exploit", "2026-01-02T00:00:01.000Z", EID),
        result_rec("toolu_10", "2026-01-02T00:00:02.000Z"),
        spawn_rec("toolu_11", "network-exploit", "2026-01-02T00:00:03.000Z", EID),
        result_rec("toolu_11", "2026-01-02T00:00:04.000Z"),
    ])
    # simula que el hook YA registró UNA de las dos (sin tool_use_id, como hace el hook real)
    hook_line = {"ts": "2026-01-02T00:00:02Z", "event": "SubagentStop", "agent_type": "network-exploit",
                 "agent_id": "a-real-hook-id", "session_id": "sessB", "engagement_id": EID,
                 "transcript_path": t2}
    with open(audit_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(hook_line, ensure_ascii=False) + "\n")
    new_lines3, _ = rs.reconcile(tmpdir, EID, transcript_paths=[t1, t2])
    ok(len(new_lines3) == 1, f"(d) con 1 ya cubierta por el hook, solo backfillea la otra: {len(new_lines3)}")
    ok(new_lines3[0]["tool_use_id"] in ("toolu_10", "toolu_11"), "(d) backfillea uno de los dos toolu_ids")

    # ── (e) ignora transcripts de OTRO engagement (aislamiento E3) ──────────────────────────────
    t3 = os.path.join(tmpdir, "sessC.jsonl")
    write_transcript(t3, [
        spawn_rec("toolu_99", "mobile-exploit", "2026-01-03T00:00:01.000Z", "GATE-otro-cliente"),
        result_rec("toolu_99", "2026-01-03T00:00:02.000Z"),
    ])
    new_lines4, stats4 = rs.reconcile(tmpdir, EID, transcript_paths=[t3])
    ok(len(new_lines4) == 0, f"(e) transcript de otro engagement no aporta líneas: {len(new_lines4)}")
    ok(stats4["transcripts_skipped_irrelevant"] == 1, "(e) se contabiliza como irrelevante")

    # ── (f) UN MISMO transcript con turnos de DOS engagements -> aislamiento a nivel de REGISTRO ──
    # (una sesión larga que tocara más de un encargo no debe mezclar sus subagentes -- E3).
    t4 = os.path.join(tmpdir, "sessD.jsonl")
    write_transcript(t4, [
        spawn_rec("toolu_200", "active-recon", "2026-01-04T00:00:01.000Z", EID),
        result_rec("toolu_200", "2026-01-04T00:00:02.000Z"),
        spawn_rec("toolu_201", "web-exploit", "2026-01-04T00:00:03.000Z", "GATE-otro-cliente"),
        result_rec("toolu_201", "2026-01-04T00:00:04.000Z"),
    ])
    new_lines5, _ = rs.reconcile(tmpdir, EID, transcript_paths=[t4])
    ok(len(new_lines5) == 1, f"(f) solo el spawn del engagement correcto se backfillea: {len(new_lines5)}")
    ok(new_lines5 and new_lines5[0]["tool_use_id"] == "toolu_200",
       "(f) es el spawn de EID (toolu_200), no el de GATE-otro-cliente")
    new_lines5b, _ = rs.reconcile(tmpdir, "GATE-otro-cliente", transcript_paths=[t4])
    ok(len(new_lines5b) == 1 and new_lines5b[0]["tool_use_id"] == "toolu_201",
       "(f) al reconciliar el OTRO engagement, solo sale su propio spawn (toolu_201)")

    # ── sin engagement_id en blackboard ni --engagement-id -> no rompe, no escribe nada ─────────
    ok(rs.engagement_id_from_blackboard() is None, "sin contracts/engagement.json en el tmp root -> None")

finally:
    rs.ROOT = _orig_root
    shutil.rmtree(tmpdir, ignore_errors=True)

print(f"\n  RESUMEN test_reconcile_subagents:  {PASS} OK   {FAIL} fallos")
sys.exit(1 if FAIL else 0)
