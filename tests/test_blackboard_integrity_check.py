#!/usr/bin/env python3
"""Tests de blackboard_integrity_check.py (control C23, detección post-retorno de subagente,
incidente INCIDENT-2026-07-27).

Cubre la lógica pura `evaluate()`/`counts_of()` (sin tocar disco) + el contrato del hook por stdin.

    python tests/test_blackboard_integrity_check.py    (sale 1 si algo falla).
"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, ".claude", "hooks"))
import blackboard_integrity_check as bic  # noqa: E402

PASS, FAIL = 0, 0


def ok(cond, msg):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print(f"  [FALLO] {msg}")


# ── counts_of ─────────────────────────────────────────────────────────────────────────────
ok(bic.counts_of({"targets": [1, 2], "findings": [1]}) ==
   {"targets": 2, "findings": 1, "tasks": 0, "evidence": 0}, "counts_of: recuentos por clave")
ok(bic.counts_of({}) == {"targets": 0, "findings": 0, "tasks": 0, "evidence": 0},
   "counts_of: vacío -> ceros")

# ── evaluate: sin watermark previo (primera vez / engagement nuevo) -> reset, sin alerta ────
data = {"engagement_id": "E-1", "targets": [1] * 5, "findings": [1] * 3}
msg, wm, is_reset = bic.evaluate(data, None)
ok(msg is None, "evaluate: sin watermark previo -> sin alerta")
ok(is_reset, "evaluate: sin watermark previo -> is_reset True")
ok(wm == {"engagement_id": "E-1", "targets": 5, "findings": 3, "tasks": 0, "evidence": 0},
   "evaluate: watermark nuevo refleja los recuentos actuales")

# ── evaluate: cambio de engagement_id -> reset silencioso, NUNCA alerta (activación legítima) ──
old_wm = {"engagement_id": "E-OLD", "targets": 999, "findings": 999, "tasks": 999, "evidence": 999}
msg, wm, is_reset = bic.evaluate({"engagement_id": "E-NEW", "targets": [1]}, old_wm)
ok(msg is None, "evaluate: cambio de engagement_id -> sin alerta pese a recuentos menores")
ok(is_reset, "evaluate: cambio de engagement_id -> is_reset True")

# ── evaluate: mismo engagement, todo creció o igual -> sin alerta, watermark actualizado ────
wm_before = {"engagement_id": "E-1", "targets": 5, "findings": 3, "tasks": 1, "evidence": 2}
data_grown = {"engagement_id": "E-1", "targets": [1] * 6, "findings": [1] * 3,
              "tasks": [1], "evidence": [1, 2]}
msg, wm, is_reset = bic.evaluate(data_grown, wm_before)
ok(msg is None, "evaluate: recuentos crecieron/iguales -> sin alerta")
ok(not is_reset, "evaluate: mismo engagement -> is_reset False")
ok(wm["targets"] == 6, "evaluate: watermark refleja el crecimiento")

# ── evaluate: ENCOGIÓ targets/findings (el incidente real) -> ALERTA con el detalle ─────────
wm_before = {"engagement_id": "INCIDENT-2026-07-27", "targets": 169, "findings": 15, "tasks": 8, "evidence": 5}
data_shrunk = {"engagement_id": "INCIDENT-2026-07-27", "targets": [], "findings": [], "tasks": [1] * 8}
msg, wm, is_reset = bic.evaluate(data_shrunk, wm_before)
ok(msg is not None, "evaluate: encogimiento real -> SÍ alerta")
ok("targets[]: 169 -> 0" in msg, "evaluate: alerta detalla targets 169->0")
ok("findings[]: 15 -> 0" in msg, "evaluate: alerta detalla findings 15->0")
ok(not is_reset, "evaluate: encogimiento real -> is_reset False")

# ── RATCHET (hallazgo del council, 2026-07-28): el watermark persistido NO baja aunque los
# recuentos actuales hayan encogido — guarda el máximo histórico por clave ──────────────────
ok(wm["targets"] == 169, "evaluate: ratchet — el watermark NO baja a 0, conserva el máximo (169)")
ok(wm["findings"] == 15, "evaluate: ratchet — findings conserva el máximo (15)")

# ── Una alerta IGNORADA no borra la evidencia: si se vuelve a comparar contra el watermark YA
# ratcheado (en vez del original), el mismo encogimiento SIGUE disparando alerta (antes del fix,
# el watermark se sobrescribía con los recuentos ya dañados y la 2ª comparación salía limpia) ──
msg2, wm2, is_reset2 = bic.evaluate(data_shrunk, wm)
ok(msg2 is not None, "evaluate: alerta ignorada -> la 2ª comparación SIGUE alertando (no se pierde)")
ok("targets[]: 169 -> 0" in msg2, "evaluate: la 2ª alerta sigue viendo el encogimiento real (169->0)")
ok(wm2["targets"] == 169, "evaluate: el ratchet se mantiene tras la 2ª comparación")

# ── evaluate: violaciones de esquema (aunque no encoja) -> alerta también ───────────────────
wm_before = {"engagement_id": "E-1", "targets": 1, "findings": 1, "tasks": 0, "evidence": 0}
data_ok_size = {"engagement_id": "E-1", "targets": [1], "findings": [1]}
msg, wm, is_reset = bic.evaluate(data_ok_size, wm_before, schema_errors=["finding F-001: falta 'status'"])
ok(msg is not None, "evaluate: violación de esquema sin encogimiento -> igual alerta")
ok("falta 'status'" in msg, "evaluate: el detalle de la violación de esquema aparece en la alerta")

# ── invalid_json_alert ───────────────────────────────────────────────────────────────────────
ok("INCIDENT-2026-07-27" in bic.invalid_json_alert(), "invalid_json_alert: menciona el incidente precedente")

# ── contrato del hook por stdin ──────────────────────────────────────────────────────────────
hook = os.path.join(ROOT, ".claude", "hooks", "blackboard_integrity_check.py")

ev_other = {"tool_name": "Write"}
p = subprocess.run([sys.executable, hook], input=json.dumps(ev_other), capture_output=True, text=True)
ok(p.stdout.strip() == "", "hook: tool_name != Task -> no interfiere")

ev_task = {"tool_name": "Task"}
p2 = subprocess.run([sys.executable, hook], input=json.dumps(ev_task), capture_output=True, text=True)
ok(p2.returncode == 0, "hook: Task contra el blackboard real -> sale 0 (nunca rompe el flujo)")

print(f"\n  RESUMEN test_blackboard_integrity_check:  {PASS} OK   {FAIL} fallos")
sys.exit(1 if FAIL else 0)
