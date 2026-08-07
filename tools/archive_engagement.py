#!/usr/bin/env python3
"""archive_engagement.py — Archiva el blackboard ACTIVO en la carpeta del engagement.

Copia `contracts/engagement.json` (el blackboard del engagement ACTIVO) a
`engagements/<engagement_id>/engagement.json`, para que ese engagement quede AUTOCONTENIDO y
CONSULTABLE como histórico una vez deje de ser el activo (p.ej. por el registro multi-engagement del
dashboard, que lee el blackboard archivado de los históricos; sin archivar, un histórico solo muestra
sus artefactos).

Por qué existe: en PRODUCCIÓN el ciclo de un engagement lo dirige el Orquestador (no hay un driver
Python que "cierre" el engagement, a diferencia del gate `benchmark/run_gate.py`, que ya archiva su
blackboard al graduar con `_snapshot_blackboard`). Este tool es el equivalente de producción de ese
snapshot, invocado en los dos seams del flujo (ver AGENTS.md):
  - Al CIERRE (paso 6): `python tools/archive_engagement.py` deja el blackboard FINAL del engagement
    que se cierra dentro de su carpeta.
  - Al CONMUTAR (paso 1, antes de crear un engagement nuevo que reemplace al activo):
    `python tools/archive_engagement.py --on-switch <nuevo_id>` archiva el SALIENTE solo si su id !=
    <nuevo_id> (si coincide no hay conmutación y no toca nada) — así conmutar nunca pierde el anterior.

Garantías: NO muta el blackboard activo ni el puntero de 'activo' (solo COPIA de lectura). Determinista
e idempotente (re-ejecutar deja el mismo fichero). Escritura ATÓMICA (tmp + os.replace) para que un
lector concurrente —el dashboard— nunca vea un fichero a medias. E3-safe: el destino SIEMPRE cae bajo
`engagements/<id>/` (id validado anti-traversal + cinturón por realpath); `engagements/` está gitignored
(datos de cliente) y el blackboard ya referencia los secretos (nunca en claro; lo imponen
memory_guard/secret_scan). Best-effort: ante cualquier fallo de E/S no revienta el flujo (sale 0).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# id de engagement seguro: primer carácter alfanumérico/_ y sin secuencia de puntos (bloquea "."/".."/
# dot-leading y cualquier `..` que intente escapar de engagements/). Coherente con el validador que el
# council del dashboard (v0.57) fijó para la vista multi-engagement.
_EID_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")


def _safe_eid(eid) -> bool:
    return isinstance(eid, str) and bool(_EID_RE.match(eid)) and ".." not in eid


# Resultados de archive_active (el 1er elemento de la tupla). Distinguirlos importa para el seam de
# CONMUTACIÓN: "noop" = no había nada que preservar (benigno); "error" = HABÍA un blackboard activo pero
# no se pudo archivar (peligroso: si el Orquestador sobrescribe el activo tras un "error", pierde el
# saliente). El código de salida de la CLI lo refleja (main): archived/noop→0, error→2.
ARCHIVED, NOOP, ERROR = "archived", "noop", "error"


def archive_active(root: str, on_switch: str | None = None):
    """Archiva el blackboard activo en engagements/<id>/engagement.json.

    Devuelve (outcome, message, dst) con outcome ∈ {"archived","noop","error"}:
      - "archived": copiado Y verificado byte-idéntico en destino (seguro sobrescribir el activo).
      - "noop": no había nada que archivar (sin blackboard activo, o --on-switch con el mismo id).
      - "error": HABÍA un blackboard activo pero no se pudo archivar (JSON corrupto, id inválido, E/S,
        o verificación post-escritura fallida). En el seam de conmutación, NO sobrescribas el activo.
    """
    bb = os.path.join(root, "contracts", "engagement.json")
    if not os.path.isfile(bb):
        return NOOP, "no hay blackboard activo (contracts/engagement.json) que archivar", None
    try:
        with open(bb, "rb") as f:
            raw = f.read()
        eid = (json.loads(raw.decode("utf-8")) or {}).get("engagement_id")
    except Exception:  # noqa: BLE001 — a medio escribir / no parseable: hay algo pero no es archivable
        return ERROR, "el blackboard activo no es JSON legible; NO se archivó", None

    if not _safe_eid(eid):
        return ERROR, f"engagement_id ausente o inválido ({eid!r}); NO se archivó", None

    if on_switch is not None and eid == on_switch:
        return NOOP, f"el blackboard activo ya es '{eid}': no hay conmutación, nada que archivar", None

    eng_base = os.path.join(root, "engagements")
    dst_dir = os.path.join(eng_base, eid)
    # Cinturón por realpath sobre _safe_eid: el destino DEBE quedar bajo engagements/ (bloquea un symlink
    # pre-plantado en engagements/<id> que resolviera fuera de la zona E3 — lo que la regex no cubre).
    try:
        if os.path.commonpath([os.path.realpath(dst_dir), os.path.realpath(eng_base)]) != os.path.realpath(eng_base):
            return ERROR, f"destino fuera de engagements/ para id '{eid}'; NO se archivó", None
    except (OSError, ValueError):
        return ERROR, f"no se pudo resolver el destino para id '{eid}'; NO se archivó", None

    dst = os.path.join(dst_dir, "engagement.json")
    tmp = dst + ".tmp"
    try:
        os.makedirs(dst_dir, exist_ok=True)
        with open(tmp, "wb") as f:  # escritura atómica: tmp + replace (un lector nunca ve a medias)
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, dst)
    except OSError as e:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        return ERROR, f"fallo de E/S archivando '{eid}': {e}", None

    # Verificación post-escritura: el ÉXITO significa "durable Y byte-idéntico en destino", la señal
    # fiable que el seam de conmutación necesita antes de sobrescribir el activo (council v2.68.7 #1/#2).
    try:
        with open(dst, "rb") as f:
            if f.read() != raw:
                return ERROR, f"verificación post-escritura de '{eid}' falló (destino no coincide); NO fiable", None
    except OSError as e:
        return ERROR, f"no se pudo verificar el archivado de '{eid}': {e}", None

    rel = os.path.relpath(dst, root)
    return ARCHIVED, f"blackboard de '{eid}' archivado y verificado en {rel}", rel


def main() -> int:
    ap = argparse.ArgumentParser(description="Archiva el blackboard activo en engagements/<id>/engagement.json.")
    ap.add_argument("--on-switch", metavar="NUEVO_ID",
                    help="archiva el engagement SALIENTE solo si su id != NUEVO_ID (uso en el seam de "
                         "conmutación, antes de crear el engagement nuevo que reemplaza al activo)")
    ap.add_argument("--root", default=ROOT, help="raíz del repo (def.: la del propio tool)")
    ap.add_argument("--quiet", action="store_true", help="no imprime nada (solo el código de salida)")
    args = ap.parse_args()

    outcome, message, _dst = archive_active(args.root, on_switch=args.on_switch)
    if not args.quiet:
        # "error" a stderr y con prefijo inconfundible: si esto sale en el seam de conmutación, el
        # Orquestador NO debe sobrescribir el activo todavía (perdería el saliente).
        if outcome == ERROR:
            print(f"[archive] AVISO: {message} — NO sobrescribas el engagement activo hasta resolverlo.",
                  file=sys.stderr)
        else:
            print(f"[archive] {message}")
    # archived/noop → 0 (nada que hacer o hecho); error → 2 (había algo y falló: señal para un wrapper
    # determinista o para el propio Orquestador). Un no-op NO es un fallo, por eso no comparte código.
    return 2 if outcome == ERROR else 0


if __name__ == "__main__":
    sys.exit(main())
