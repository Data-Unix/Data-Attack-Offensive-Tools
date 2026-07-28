#!/usr/bin/env python3
"""
blackboard_guard.py — Hook PreToolUse (Bash) que impide ESCRIBIR el blackboard
(`contracts/engagement.json`) por la vía de Bash, forzando que toda mutación pase por las tools
`Write`/`Edit` — que SÍ están gateadas por `validate_blackboard`/`secret_scan`/`a2a_guard` (PostToolUse
sobre Write|Edit|MultiEdit). Cierra el hueco que señalaron los councils de las mejoras A y D: un agente
con `Bash` (p.ej. `auth-recon`, que maneja material de sesión VIVO) podría volcar un secreto al
blackboard con `echo … > engagement.json` / `sed -i` / `python -c "open(...,'w')"` **esquivando** los
guards de secreto. Este guard lo bloquea de forma determinista.

Cobertura (contrato CONSCIENTE, no un sandbox completo): caza los patrones de escritura COMUNES que
nombran el blackboard —redirección `>`/`>>`, `tee`, `sed -i`, `cp`/`mv`/`rm`/`dd`/`install`/`truncate`,
`open(...,'w'/'a')`, `Path(...).write_text/write_bytes`, `shutil.copy*/move`, `os.rename`/`os.replace`/
`os.remove`/`os.unlink` y `Path(...).rename/replace/unlink` de Python, EN AMBAS DIRECCIONES (el
blackboard como objeto que se renombra/reemplaza/borra, o como el destino/argumento que recibe la
escritura). Se añadieron (incidente INCIDENT-2026-07-27) tras confirmar que un agente movía un fichero
preparado aparte hacia `contracts/engagement.json` con `os.replace(...)` para esquivar exactamente este
guard — y tras revisión posterior se cerró también el sentido inverso (`Path(origen).replace(BB)`, que
la primera versión de este fix NO cazaba: solo miraba el blackboard como objeto, no como argumento). El
mismo grupo de patrones protege también el watermark de integridad (`contracts/.blackboard_watermark`,
ver `blackboard_integrity_check.py`, control C23): borrarlo resetea su detección en silencio. Un agente
decidido podría seguir ofuscando (base64, variable con la ruta): el confinamiento DURO es el contenedor
efímero (mejora C) + que las tools nunca emiten material a stdout.
LEER el blackboard (cat/jq/grep/python-read) NO se bloquea. Fail-open ante ambigüedad.

Protocolo Claude Code (igual que scope_guard.py): stdin JSON {tool_name, tool_input.command}; para
BLOQUEAR imprime la decisión PreToolUse (permissionDecision=deny) y sale 0; ambigüedad => sale 0.

Solo stdlib.
"""
import json
import re
import sys

# Nombres protegidos (con o sin el prefijo contracts/, `/` o `\`): el blackboard y su watermark de
# integridad (C23) — borrar este último resetea esa detección en silencio, mismo hueco que escribir
# el blackboard por una vía no cazada.
_BB_NAMES = r"(?:engagement\.json|\.blackboard_watermark)"
_BB = r"(?:contracts[\\/])?" + _BB_NAMES
# Fast-path barato para descartar la mayoría de comandos sin correr los regex completos.
_QUICK_NAMES = ("engagement.json", ".blackboard_watermark")

# Patrones de ESCRITURA/BORRADO que nombran alguno de los ficheros protegidos. Cada uno describe una
# vía de mutación por Bash.
_WRITE_PATTERNS = [
    (re.compile(r">>?\s*[\"']?[^\s|;&>\"']*" + _BB, re.I), "redirección > / >> al blackboard"),
    (re.compile(r"\btee\b[^|;&]*" + _BB, re.I), "tee sobre el blackboard"),
    (re.compile(r"\bsed\b[^|;&]*-i[^|;&]*" + _BB, re.I), "sed -i (edición in-place) del blackboard"),
    (re.compile(r"\b(?:cp|mv|rm|dd|install|rsync|truncate)\b[^|;&]*" + _BB, re.I), "cp/mv/rm/dd/install/truncate sobre el blackboard"),
    (re.compile(r"open\s*\([^)]*" + _BB + r"[^)]*,\s*[\"'][wa]", re.I), "open(..., 'w'/'a') de Python sobre el blackboard"),
    (re.compile(r"\.write\s*\([^)]*\)[^;]*" + _BB, re.I), ".write() de Python sobre el blackboard"),
    # `Path("…engagement.json").write_text/bytes(…)` — la ruta va ANTES del método (el arg es el
    # contenido). NO casamos el blackboard DENTRO de los args de write_* (ahí sería contenido/lectura).
    (re.compile(r"[\"'][^\"']*" + _BB + r"[\"']\s*\)?\s*\.write_(?:text|bytes)", re.I), "Path('…engagement.json').write_text/bytes"),
    (re.compile(r"shutil\.(?:copy\w*|move)\s*\([^)]*" + _BB, re.I), "shutil.copy*/move al blackboard"),
    # `os.rename(origen, 'contracts/engagement.json')` / `os.replace(...)` — mismo hueco que cp/mv
    # pero por la stdlib de Python en vez del binario de shell (incidente 2026-07-27, ver docstring).
    (re.compile(r"os\.(?:rename|replace)\s*\([^)]*" + _BB, re.I), "os.rename/os.replace al blackboard"),
    (re.compile(r"os\.(?:remove|unlink)\s*\([^)]*" + _BB, re.I), "os.remove/os.unlink del blackboard"),
    # `Path('contracts/engagement.json').rename(...)/.replace(...)/.unlink()` — el blackboard es el
    # OBJETO (se renombra/borra/reemplaza-away). La ruta va ANTES del método.
    (re.compile(r"[\"'][^\"']*" + _BB + r"[\"']\s*\)?\s*\.(?:rename|replace|unlink)\s*\(", re.I), "Path('…engagement.json').rename/replace/unlink"),
    # `Path(origen).replace('contracts/engagement.json')` / `.rename(...)` — el blackboard es el
    # ARGUMENTO (destino que recibe la escritura). Dirección que la primera versión de este fix NO
    # cazaba (hallazgo de revisión, 2026-07-28): el patrón de arriba solo mira el blackboard como
    # objeto, nunca dentro de los paréntesis de la llamada.
    (re.compile(r"\.(?:rename|replace)\s*\([^)]*" + _BB, re.I), "Path(origen).rename/replace(blackboard) — blackboard como destino"),
]


def blocking_reason(command):
    """Motivo (str) si `command` escribe/borra el blackboard o su watermark por Bash, o None.
    Función pura y testeable."""
    if not command or not any(n in command for n in _QUICK_NAMES):
        return None
    for rx, label in _WRITE_PATTERNS:
        if rx.search(command):
            return label
    return None


def main():
    try:
        event = json.load(sys.stdin)
    except Exception:  # noqa: BLE001
        sys.exit(0)
    if event.get("tool_name") != "Bash":
        sys.exit(0)
    command = (event.get("tool_input") or {}).get("command", "") or ""
    label = blocking_reason(command)
    if label:
        reason = (
            f"blackboard_guard: BLOQUEADA una escritura del blackboard por Bash ({label}). El blackboard "
            "`contracts/engagement.json` SOLO se muta con las tools `Write`/`Edit` — que pasan por "
            "`validate_blackboard`/`secret_scan`/`a2a_guard`. Escribirlo por Bash esquivaría esos guards "
            "de secreto/esquema. Usa Write/Edit para actualizar el blackboard. (Leerlo con cat/jq está bien.)"
        )
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }))
        sys.exit(0)
    sys.exit(0)


if __name__ == "__main__":
    main()
