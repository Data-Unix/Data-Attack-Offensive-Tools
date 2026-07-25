#!/usr/bin/env python3
"""seams.py — implementaciones REALES de los seams `rollout`/`reflect` de SkillOpt (LAB-ONLY, build-time).

`optimize.py` deja `rollout_fn`/`reflect_fn` como puntos de inyección porque LANZAN modelo/agente contra labs
vivos (no corren en un build sin entorno). Este módulo los provee para el arnés de Kali:

- `engagement_transcript(eval_id)` — lee los artefactos de un engagement YA CORRIDO (blackboard + veredicto +
  qué vectores se probaron y dónde se atascó) y los resume en un TRANSCRIPT de texto acotado. Es la "señal de
  experiencia" que consume `reflect`. Es independiente del rollout: puede resumir una corrida previa sin lanzar
  nada (así se prueba la maquinaria barato contra un fallo real ya existente).
- `rollout(skill_text, evals, skill_name, runner)` — instala la skill candidata (SkillSwap atómico), corre el
  `runner` (= `scorer.shell_runner`, que lanza `run_gate --canary`) sobre cada eval, y devuelve los transcripts.
- `reflect(skill_text, transcripts, n, provider)` — pide al PROVEEDOR (claude -p / opencode) `n` ediciones de la
  SKILL.md que ayuden a superar los atascos vistos en los transcripts. Devuelve los textos candidatos.

GOBERNANZA: este módulo NO relaja nada. `reflect` LANZA un `claude -p` (o opencode) — no es solo "editar
texto": es un subproceso de modelo. Como el prompt embebe transcript AGENT-AUTHORED (superficie de
prompt-injection), ese subproceso corre con las herramientas de ACCIÓN DENEGADAS (`_REFLECT_DENY_TOOLS`), así
que solo puede generar texto, no escribir/ejecutar en el repo. Los candidatos pasan por `guard.lint_skill` en
`optimize.run` ANTES de puntuarse; el reward SOLO lo da el PASS **canario** (`scorer`); los hooks del motor
(scope_guard/approval_gate) mandan FUERA del prompt; y el candidato se escribe SOLO en `skilltrain/out/`
(gitignored) y NUNCA se auto-aplica (desplegar a `plugin/skills/` exige humano + council). El lint es un
denylist determinista, no un juez semántico: una metodología "plausible-pero-dañina" que NO nombre un guard
podría pasarlo — por eso la revisión HUMANA+COUNCIL es el gate semántico final e innegociable.
"""
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# Importa las piezas hermanas tanto si se ejecuta como módulo (`python -m skilltrain.seams`) como suelto.
sys.path.insert(0, HERE)
import apply_skill  # noqa: E402  (SkillSwap)

_ACCESS_RANK = {"none": 0, "user": 1, "root": 2, "admin": 2, "system": 3, "domain-admin": 3, "da": 3}
_TRANSCRIPT_CAP = 6000   # chars por transcript (acota el prompt de reflect)


def _safe_eval_id(eval_id):
    """Valida el eval_id ANTES de interpolarlo en una ruta (defensa en profundidad, como
    `apply_skill.skill_path`): solo alfanumérico + `._-`, ni `.`/`..`. Hoy los ids vienen de config/repo, pero
    no se confía en ese origen para construir rutas."""
    eid = str(eval_id or "")
    if eid in (".", "..") or not re.fullmatch(r"[A-Za-z0-9._-]+", eid):
        raise ValueError(f"eval_id inválido (posible traversal): {eval_id!r}")
    return eid


def _load_blackboard(eval_id):
    """Devuelve el blackboard del engagement `GATE-<eval_id>`: prefiere el ARCHIVADO en su carpeta (fin de la
    corrida), cae al vivo `contracts/engagement.json`. None si no hay ninguno."""
    eval_id = _safe_eval_id(eval_id)
    for p in (os.path.join(ROOT, "engagements", f"GATE-{eval_id}", "engagement.json"),
              os.path.join(ROOT, "contracts", "engagement.json")):
        if os.path.isfile(p):
            try:
                d = json.load(open(p, encoding="utf-8"))
            except Exception:  # noqa: BLE001
                continue
            if isinstance(d, dict):
                return d, p
    return None, None


def _exploit_artifacts(eval_id, limit=40):
    """Nombres de los artefactos de explotación (QUÉ se intentó). Solo los nombres — nunca el contenido, que
    podría llevar datos de cliente; aquí es un lab, pero la disciplina se mantiene."""
    d = os.path.join(ROOT, "engagements", f"GATE-{_safe_eval_id(eval_id)}", "exploit")
    if not os.path.isdir(d):
        return []
    try:
        return sorted(os.listdir(d))[:limit]
    except OSError:
        return []


def engagement_transcript(eval_id):
    """Resume un engagement YA CORRIDO en un transcript de texto para `reflect`: veredicto, fase/acceso
    alcanzados, findings por estado (con título), y QUÉ vectores se probaron (artefactos). El foco es DÓNDE se
    atascó — eso es lo accionable para editar la metodología de la skill. Acotado a `_TRANSCRIPT_CAP` chars."""
    d, path = _load_blackboard(eval_id)
    if not d:
        return f"[eval {eval_id}] sin blackboard: no hay transcript (¿se corrió el engagement?)."
    targets = d.get("targets", [])
    # Etiqueta = el access_level REAL del host de mayor rango (no un mapa inverso que colapsaría admin→root).
    acc_label = max((t.get("access_level") or "none" for t in targets),
                    key=lambda a: _ACCESS_RANK.get(a, 0), default="none")
    acc = _ACCESS_RANK.get(acc_label, 0)
    by_status = {}
    for f in d.get("findings", []):
        by_status.setdefault(f.get("status", "?"), []).append((f.get("title") or "")[:70])
    lines = [
        f"### Engagement GATE-{eval_id}  (fuente: {os.path.relpath(path, ROOT)})",
        f"veredicto (heurístico): fase={d.get('phase')}  acceso_máx={acc_label}  "
        f"(root_alcanzado={'sí' if acc >= _ACCESS_RANK['root'] else 'NO'})",
        f"targets: {[(t.get('asset'), t.get('access_level')) for t in targets]}",
        "findings por estado:",
    ]
    # Orden útil para reflect: primero lo confirmado/exploited (lo que SÍ funcionó y se puede encadenar),
    # luego candidatos/false_positive (dónde se atascó o descartó).
    for st in ("exploited", "confirmed", "candidate", "false_positive", "?"):
        for title in by_status.get(st, []):
            lines.append(f"  [{st:13}] {title}")
    arts = _exploit_artifacts(eval_id)
    if arts:
        lines.append(f"vectores probados (artefactos exploit/): {', '.join(arts)}")
    lines.append("ATASCO: el objetivo es `root`; si acceso_máx < root, la CADENA no se completó — la mejora de "
                 "metodología debe atacar el salto que faltó (p.ej. de acceso web-autenticado a RCE de OS).")
    return "\n".join(lines)[:_TRANSCRIPT_CAP]


def rollout(skill_text, evals, skill_name, runner):
    """Instala la skill candidata (SkillSwap atómico + restaura) y corre el `runner` (run_gate --canary) sobre
    cada eval; devuelve una lista de dicts {eval, passed, transcript}. El transcript se construye de los
    artefactos que deja la corrida. `runner` es `scorer.shell_runner` (o uno inyectado en tests)."""
    out = []
    with apply_skill.SkillSwap(skill_name, skill_text):
        for ev in evals:
            passed = bool(runner(ev))
            out.append({"eval": ev.get("id"), "passed": passed,
                        "transcript": engagement_transcript(ev.get("id"))})
    return out


# ---- reflect: el proveedor propone ediciones de la skill a partir de los fallos --------------------------------

_REFLECT_INSTR = (
    "Eres un ingeniero de metodología ofensiva. Se te da la SKILL.md ACTUAL (texto de metodología que guía a "
    "un agente de pentest AUTORIZADO) y TRANSCRIPTS de engagements donde el motor FALLÓ o se ATASCÓ. Propón una "
    "SKILL.md MEJORADA que conserve todo lo bueno y AÑADA/AFINE la metodología para superar EXACTAMENTE el "
    "atasco observado (p.ej. encadenar un acceso web-autenticado hacia RCE de OS / escalada). Reglas DURAS: "
    "(1) NO incluyas datos de cliente concretos (IPs, tokens, claves) — la skill es TÉCNICA GENERALIZADA. "
    "(2) NO propongas desactivar/eludir ningún guard del motor ni usar --yolo/--dangerously-skip-permissions ni "
    "approval_mode=auto — eso se rechaza automáticamente. (3) Devuelve la SKILL.md COMPLETA (no un diff), entre "
    "los marcadores exactos <<<SKILL>>> y <<<END>>>, sin nada más fuera de ellos."
)


_PROMPT_TX_BUDGET = 60000   # techo del bloque de transcripts en el prompt: el prompt va como UN argv, y superar
                            # ~128KB (MAX_ARG_STRLEN de Linux) daría E2BIG → '' → cero candidatos SILENCIOSO.


def _build_reflect_prompt(skill_text, transcripts):
    tx = "\n\n".join(t["transcript"] if isinstance(t, dict) else str(t) for t in transcripts)
    if len(tx) > _PROMPT_TX_BUDGET:   # acota deterministamente (deja sitio para skill_text + instrucciones)
        tx = tx[:_PROMPT_TX_BUDGET] + "\n\n[...transcripts truncados por presupuesto de prompt...]"
    return (
        f"{_REFLECT_INSTR}\n\n=== SKILL.md ACTUAL ===\n{skill_text}\n\n"
        f"=== TRANSCRIPTS DE FALLO/ATASCO ===\n{tx}\n\n"
        f"Devuelve SOLO la SKILL.md mejorada entre <<<SKILL>>> y <<<END>>>."
    )


# El transcript que se embebe en el prompt de reflect proviene de artefactos AGENT-AUTHORED (títulos de
# findings, assets, nombres de fichero): superficie de prompt-injection. reflect es SOLO generación de texto,
# así que el subproceso `claude -p` corre con las herramientas de ACCIÓN DENEGADAS — un transcript inyectado no
# puede empujarlo a escribir/ejecutar en el repo (defensa en profundidad; además el candidato pasa
# guard.lint_skill + GATE canario + humano/council y nunca se auto-aplica).
_REFLECT_DENY_TOOLS = ["Bash", "Edit", "Write", "Task", "WebFetch", "WebSearch", "Read", "Grep", "Glob"]


def _call_provider(prompt, provider="claude", model=None, timeout=600):
    """Una llamada de GENERACIÓN DE TEXTO al proveedor (sin herramientas de acción). `claude` = CLI `claude -p`
    (logueado) con `--disallowedTools` sobre todo lo que escribe/ejecuta/red; `opencode` = CLI opencode (espejo
    LAB, NVIDIA free). Devuelve stdout o '' si falla (fail-safe: sin candidato)."""
    if provider == "claude":
        cli = os.environ.get("CLAUDE_CLI_PATH") or "claude"
        args = [cli, "-p", prompt, "--output-format", "text", "--disallowedTools", *_REFLECT_DENY_TOOLS]
        if model:
            args += ["--model", model]
    elif provider == "opencode":
        cli = os.environ.get("OPENCODE_CLI_PATH") or "opencode"
        args = [cli, "run", prompt]
        if model:
            args += ["--model", model]
    else:
        raise ValueError(f"provider desconocido: {provider!r} (usa 'claude' u 'opencode')")
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False, cwd=ROOT)
    except (OSError, subprocess.SubprocessError) as e:
        print(f"[seams.reflect] fallo llamando a {provider}: {e}", file=sys.stderr)
        return ""
    return r.stdout or ""


def _extract_skill(raw):
    """Saca la SKILL.md de la salida del proveedor: SOLO entre los marcadores <<<SKILL>>>/<<<END>>> que el
    prompt EXIGE; si no están, un bloque cercado ```. Nada más: un fallback laxo (p.ej. "del primer # al final")
    se tragaría el preámbulo/razonamiento del modelo como si fuese skill. '' si no hay nada usable — el bucle
    descarta vacíos y vuelve a pedir."""
    m = re.search(r"<<<SKILL>>>\s*(.+?)\s*<<<END>>>", raw, re.S)
    if m:
        return m.group(1).strip()
    m = re.search(r"```(?:markdown|md)?\s*(.+?)```", raw, re.S)
    if m:
        return m.group(1).strip()
    return ""


def reflect(skill_text, transcripts, n, provider="claude", model=None, _call=None):
    """Pide `n` candidatos de SKILL.md al proveedor a partir de los transcripts de fallo. `_call` inyectable
    (tests): función prompt->texto. Filtra vacíos y duplicados y los que quedan idénticos al original."""
    call = _call or (lambda p: _call_provider(p, provider=provider, model=model))
    prompt = _build_reflect_prompt(skill_text, transcripts)
    cands, seen = [], set()
    for _ in range(max(1, n)):
        cand = _extract_skill(call(prompt))
        if cand and cand != skill_text.strip() and cand not in seen:
            seen.add(cand)
            cands.append(cand)
    return cands


if __name__ == "__main__":
    # Utilidad: imprime el transcript de un engagement ya corrido.  python -m skilltrain.seams <eval_id>
    if len(sys.argv) == 2:
        print(engagement_transcript(sys.argv[1]))
    else:
        print("uso: python -m skilltrain.seams <eval_id>   (imprime el transcript de GATE-<eval_id>)",
              file=sys.stderr)
        sys.exit(2)
