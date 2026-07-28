#!/usr/bin/env python3
"""
blackboard_integrity_check.py — Hook PostToolUse (matcher Task) que DETECTA, de forma automática,
si el blackboard (`contracts/engagement.json`) quedó dañado tras el retorno de un subagente. Control
**C23** (complementa C21 `blackboard_guard.py`).

Motivo (incidente INCIDENT-2026-07-27): un subagente con `Bash` intentó (y en parte logró) escribir
el blackboard esquivando `Write`/`Edit` — el resultado fue `targets[]`/`findings[]` reducidos a nada,
detectado solo porque el Orquestador lo verificó manualmente DESPUÉS de leer el resumen del
subagente. `blackboard_guard.py` (PreToolUse) cierra vías de escritura CONOCIDAS por el TEXTO del
comando; este hook es la red complementaria que mira el RESULTADO, no el comando — detecta el daño
aunque la vía de escritura usada no estuviera en la lista de patrones bloqueados.

Qué comprueba, tras CADA retorno de la tool Task:
1. Que `contracts/engagement.json` siga siendo JSON válido.
2. Que no falte ningún campo obligatorio (reusa `tools/blackboard.validate_engagement`).
3. Que `len(targets)` / `len(findings)` / `len(tasks)` / `len(evidence)` NO hayan ENCOGIDO respecto
   al último estado bueno conocido (watermark en `contracts/.blackboard_watermark`, gitignored,
   mismo patrón que `.action_count` de `budget_guard.py`).

Si algo falla, NO bloquea (un hook PostToolUse no puede deshacer una tool que ya corrió) — inyecta
`additionalContext` con una alerta fuerte para que el Orquestador la vea en su siguiente turno y
decida (verificar, restaurar si hay copia, o preguntar al operador). El watermark es un RATCHET
MONÓTONO por `engagement_id` (nunca baja, aunque los recuentos actuales encojan): si el Orquestador
ignora una alerta, la SIGUIENTE comparación sigue viendo el encogimiento — no se pierde silenciosamente
tras la primera alerta no atendida. Un cambio de `engagement_id` respecto al watermark se trata como
activación legítima de otro engagement (reset silencioso, no alerta).

Protocolo Claude Code (PostToolUse, igual criterio que a2a_router_nudge.py):
- stdin JSON {tool_name, ...}; solo actúa si tool_name == "Task".
- Para alertar: imprime {"hookSpecificOutput": {"hookEventName": "PostToolUse",
  "additionalContext": "..."}} y sale 0.
- Fail-open ante cualquier ambigüedad (sin blackboard, JSON a medio escribir, error de import): sale
  0 sin salida — la detección nunca debe romper el flujo por sí misma. Si falla justo el import de
  `tools/blackboard.validate_engagement`, el hook degrada en silencio a solo-recuentos (sin chequeo
  de esquema) — ver "Límites conocidos" abajo.

Límites conocidos (contrato CONSCIENTE, no una red de seguridad completa — mismo espíritu que
blackboard_guard.py):
- **Solo mira el retorno de `Task`.** Un Bash que el propio Orquestador ejecuta DIRECTAMENTE (fuera
  de una delegación a subagente, p.ej. `tools/diff_scope.py` en recon-prep) no dispara este hook —
  `blackboard_guard.py` (PreToolUse, corre en TODO comando Bash) sigue siendo la barrera dura para
  esos casos; este hook es un complemento, no un sustituto.
- **Race de escritura concurrente sin lock.** `AGENTS.md` autoriza delegaciones `Task` en paralelo
  dentro de un mismo turno; dos retornos casi simultáneos pueden leer/escribir
  `contracts/.blackboard_watermark` sin sincronización (mismo patrón best-effort que `.action_count`/
  `.cmd_history`, sin lock de fichero). El ratchet monótono acota el peor caso a "watermark
  momentáneamente desactualizado" (nunca a enmascarar un encogimiento real de forma permanente), pero
  no elimina la carrera. Riesgo aceptado: esto es una capa de DETECCIÓN, no un gate — el bloqueo duro
  sigue siendo `blackboard_guard.py`.
- **La remediación no asume un backup garantizado.** El mensaje de alerta sugiere restaurar si existe
  una copia (p.ej. la que `run_gate.py` archiva en modo GATE); en un engagement real normal NO hay
  snapshot automático de `contracts/engagement.json` fuera de ese flujo — la alerta es la señal para
  que el operador decida (reconstruir desde `evidence[]`/artefactos en `engagements/<id>/`, o
  preguntar), no una promesa de que el fichero de restauración existe.

Solo stdlib + tools/blackboard.py (ya usado por validate_blackboard.py).
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ENGAGEMENT = os.path.join(ROOT, "contracts", "engagement.json")
WATERMARK = os.path.join(ROOT, "contracts", ".blackboard_watermark")


COUNT_KEYS = ("targets", "findings", "tasks", "evidence")


def counts_of(data):
    """Recuentos de los arrays clave del blackboard. Función pura y testeable."""
    return {k: len(data.get(k, []) or []) for k in COUNT_KEYS}


def evaluate(data, watermark, schema_errors=None):
    """Decide si hay que alertar. Función pura (sin I/O), testeable en aislado.

    Devuelve (alert_message_or_None, new_watermark_dict, is_reset). `is_reset` distingue un cambio
    legítimo de engagement_id (nunca alerta) de una comparación real contra el watermark previo.
    """
    schema_errors = schema_errors or []
    engagement_id = data.get("engagement_id")
    counts = counts_of(data)

    if watermark is None or watermark.get("engagement_id") != engagement_id:
        new_watermark = {"engagement_id": engagement_id, **counts}
        return None, new_watermark, True

    shrunk = {
        k: (watermark.get(k, 0), counts[k])
        for k in COUNT_KEYS
        if counts[k] < watermark.get(k, 0)
    }

    # Ratchet MONÓTONO (hallazgo del council, 2026-07-28): el watermark de un engagement en curso
    # NUNCA baja, aunque los recuentos actuales hayan encogido. La versión original sobrescribía el
    # watermark con los recuentos ACTUALES incondicionalmente — si el Orquestador ignoraba la única
    # alerta, la SIGUIENTE comparación se hacía contra el estado ya dañado y el daño se volvía
    # permanente y silencioso (una alerta perdida = pérdida para siempre). Guardando el máximo
    # histórico por clave, la alerta se repite en CADA retorno de subagente hasta que los recuentos
    # se recuperen de verdad (restauración) o el operador reconozca un reset explícito (engagement_id
    # nuevo). No evita el race de escritura concurrente (ver docstring del módulo), pero acota su
    # peor caso a "watermark momentáneamente desactualizado", no a "encogimiento real enmascarado".
    new_watermark = {
        "engagement_id": engagement_id,
        **{k: max(watermark.get(k, 0), counts[k]) for k in COUNT_KEYS},
    }

    if not shrunk and not schema_errors:
        return None, new_watermark, False

    lines = []
    if shrunk:
        lines.append("Recuentos que ENCOGIERON respecto al ultimo estado bueno conocido:")
        for k, (before, after) in shrunk.items():
            lines.append(f"  - {k}[]: {before} -> {after}")
    if schema_errors:
        lines.append("Violaciones de esquema detectadas:")
        for e in schema_errors[:10]:
            lines.append(f"  - {e}")

    msg = (
        "[ALERTA blackboard_integrity_check] Posible daño en `contracts/engagement.json` tras el "
        "retorno de un subagente.\n" + "\n".join(lines) + "\n"
        "No confies en el resumen del subagente sobre esto: verifica tu mismo con "
        "`python tools/analyze_engagement.py`. Si el daño es real: restaura desde una copia si la "
        "tienes (p.ej. la que archiva `run_gate.py` en modo GATE), o reconstruye a mano lo perdido "
        "a partir de `evidence[]`/artefactos en `engagements/<id>/` antes de delegar nada mas — no "
        "asumas que existe un backup automatico (precedente: incidente INCIDENT-2026-07-27)."
    )
    return msg, new_watermark, False


def invalid_json_alert():
    """Mensaje para el caso mas grave: el blackboard ya ni siquiera parsea como JSON."""
    return (
        "[ALERTA blackboard_integrity_check] `contracts/engagement.json` NO es JSON valido "
        "justo despues de que un subagente retornara. Esto es exactamente el patron del "
        "incidente INCIDENT-2026-07-27: el blackboard quedo danado por una "
        "escritura que esquivo Write/Edit. PARA antes de delegar nada mas: verifica el fichero y, "
        "si tienes una copia valida (p.ej. la que archiva `run_gate.py` en modo GATE), restaura "
        "desde ahi; si no, reconstruye a mano desde `evidence[]`/artefactos en "
        "`engagements/<engagement_id>/` antes de continuar."
    )


def _load_watermark():
    try:
        with open(WATERMARK, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _save_watermark(new_watermark):
    try:
        tmp = WATERMARK + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(new_watermark, f)
        os.replace(tmp, WATERMARK)
    except Exception:
        pass  # si no se puede persistir, no rompemos el flujo por ello


def _emit(msg):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PostToolUse", "additionalContext": msg}}))


def main():
    try:
        event = json.load(sys.stdin)
    except Exception:
        sys.exit(0)
    if event.get("tool_name") != "Task":
        sys.exit(0)

    if not os.path.isfile(ENGAGEMENT):
        sys.exit(0)

    try:
        with open(ENGAGEMENT, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        _emit(invalid_json_alert())
        sys.exit(0)

    if not isinstance(data, dict):
        sys.exit(0)

    schema_errors = []
    try:
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        from blackboard import validate_engagement
        schema_errors = validate_engagement(data)
    except Exception:
        pass  # si el validador no esta disponible, no es motivo para no comprobar el encogimiento

    watermark = _load_watermark()
    msg, new_watermark, _ = evaluate(data, watermark, schema_errors)
    if msg:
        _emit(msg)
    _save_watermark(new_watermark)
    sys.exit(0)


if __name__ == "__main__":
    main()
