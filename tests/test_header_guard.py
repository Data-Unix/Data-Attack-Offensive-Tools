#!/usr/bin/env python3
"""
test_header_guard.py — Pruebas del gate de cabecera HTTP obligatoria (header_guard.py).

Cubre la lógica PURA (`header_gate`) sin stdin ni red: qué comandos deben BLOQUEARSE por no llevar la
cabecera que exige el programa (p.ej. Bugcrowd `BUGCROWD: <handle>`) EN UN FLAG DE CABECERA real, y cuáles
pasan. Incluye los evasores/roturas que destapó el council (v2.48.0): la cabecera debe ir en ‑H/‑‑header
(no cuela por URL/body/user-agent/comentario), continuación de línea `\\`, exención por proxy, herramientas
ejecutadas como script, y lista ampliada. Invariante: fail-closed para herramientas HTTP conocidas; pasivas
(subfinder/gau), port-scan (nmap) y mantenimiento (‑version) NO se bloquean; sin `required_http_header` no-op.

Ejecuta:  python tests/test_header_guard.py   (sale 1 si algo falla).
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, ".claude", "hooks"))

import header_guard  # noqa: E402

PASS, FAIL = 0, 0
HDR = "BUGCROWD: huntr0"


def ok(cond, msg):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print(f"  [FALLO] {msg}")


def allowed(cmd, header=HDR):
    return header_guard.header_gate(cmd, header) is None


def blocked(cmd, header=HDR):
    return header_guard.header_gate(cmd, header) is not None


# --- No-op cuando el programa no exige cabecera -------------------------------------------
ok(header_guard.header_gate("curl https://gateway.acme.example/api", "") is None,
   "sin required_http_header -> no-op")
ok(header_guard.header_gate("curl https://x.acme.example", None) is None, "required None -> no-op")

# --- Cabecera en flag de cabecera real: PASA ---------------------------------------------
ok(allowed('curl -H "BUGCROWD: huntr0" https://gateway.acme.example/api/ai-search'), "curl -H pasa")
ok(allowed('httpx -H "BUGCROWD: huntr0" -u https://webmail.acmenet.example/'), "httpx -H pasa")
ok(allowed('ffuf -H "BUGCROWD: huntr0" -u https://www.acme.example/FUZZ -w wl.txt'), "ffuf -H pasa")
ok(allowed('nuclei -header "BUGCROWD: huntr0" -u https://oes.acmenet.example/'), "nuclei -header pasa")
ok(allowed('sqlmap --header="BUGCROWD: huntr0" -u "https://www.acme.example/x?id=1"'),
   "sqlmap --header= pasa")
ok(allowed('wget --header="BUGCROWD: huntr0" https://www.acme.example/'), "wget --header= pasa")

# --- Normalización: sin espacio y case-insensitive ---------------------------------------
ok(allowed("httpx -H 'BUGCROWD:huntr0' -u https://www.acme.example/"), "cabecera sin espacio pasa")
ok(allowed('curl -H "bugcrowd: huntr0" https://www.acme.example/'), "cabecera minúsculas pasa")

# --- [council] La cabecera SOLO cuenta si va en un flag de cabecera: BLOQUEA --------------
ok(blocked('curl "https://www.acme.example/?x=BUGCROWD:huntr0"'),
   "cabecera en la URL NO cuenta (se bloquea)")
ok(blocked('curl -d "BUGCROWD: huntr0" https://www.acme.example/'),
   "cabecera en el body -d NO cuenta")
ok(blocked('curl -A "BUGCROWD: huntr0" https://www.acme.example/'),
   "cabecera en el user-agent -A NO cuenta")
ok(blocked('curl https://www.acme.example/ # BUGCROWD: huntr0'),
   "cabecera en un comentario NO cuenta")
ok(blocked('curl -o "BUGCROWD: huntr0.txt" https://www.acme.example/'),
   "cabecera en un nombre de fichero NO cuenta")

# --- Herramientas HTTP sin cabecera: BLOQUEA ----------------------------------------------
ok(blocked("curl https://gateway.acme.example/api/ai-search"), "curl sin cabecera se bloquea")
ok(blocked("httpx -l urls.txt -sc"), "httpx -l (lista) sin cabecera se bloquea")
ok(blocked('ffuf -u https://www.acme.example/FUZZ -w wl.txt'), "ffuf sin cabecera se bloquea")
ok(blocked('curl -H "BUGCROWD: otrousuario" https://www.acme.example/'), "handle equivocado se bloquea")

# --- [council] Herramienta ejecutada como script ------------------------------------------
ok(blocked("python3 sqlmap.py -u https://www.acme.example/x?id=1 --batch"),
   "python3 sqlmap.py sin cabecera se bloquea")
ok(allowed('python3 sqlmap.py --header="BUGCROWD: huntr0" -u https://www.acme.example/'),
   "python3 sqlmap.py con --header= pasa")

# --- [council] Lista ampliada (solo-proxy sin -H) -----------------------------------------
ok(blocked("nikto -host https://www.acme.example/"), "nikto directo sin proxy se bloquea")
ok(blocked("whatweb https://www.acme.example/"), "whatweb directo se bloquea")

# --- [council] Continuación de línea `\\`+salto: PASA (no falso positivo) -----------------
ok(allowed('curl https://www.acme.example/ \\\n  -H "BUGCROWD: huntr0"'),
   "continuación de línea con -H en la 2ª línea pasa")

# --- [council] Exención por proxy explícito (operador inyecta la cabecera) ----------------
ok(allowed("curl -x 127.0.0.1:8080 https://www.acme.example/"), "curl -x proxy exento")
ok(allowed("proxychains4 nikto -host https://www.acme.example/"), "proxychains nikto exento")

# --- Pipelines y separadores --------------------------------------------------------------
ok(blocked('subfinder -d acme.example -silent | httpx -sc'), "pipe subfinder|httpx sin cabecera bloquea")
ok(allowed('subfinder -d acme.example -silent | httpx -H "BUGCROWD: huntr0" -sc'),
   "pipe subfinder|httpx con -H pasa")
ok(blocked('curl https://a.acme.example & curl -H "BUGCROWD: huntr0" https://b.acme.example'),
   "separador & : el primer curl sin cabecera bloquea")

# --- No HTTP / pasivas / mantenimiento: PASA ----------------------------------------------
ok(allowed("nmap -p80,443 -sV www.acme.example"), "nmap no exige cabecera")
ok(allowed("subfinder -d acme.example -silent"), "subfinder pasivo no exige cabecera")
ok(allowed("gau acme.example"), "gau pasivo no exige cabecera")
ok(allowed("nuclei -update-templates"), "nuclei -update-templates exento")
ok(allowed("curl --version"), "curl --version exento")
ok(allowed("cat contracts/scope.json"), "comando no ofensivo pasa")
ok(allowed('echo "corre curl mas tarde"'), "mención de curl en un string no dispara")

# --- El motivo de bloqueo NO ecoa el comando (no filtra secretos) ------------------------
reason = header_guard.header_gate('curl -H "Authorization: Bearer SECRETO123" https://www.acme.example/', HDR)
ok(reason is not None and "SECRETO123" not in reason and "Bearer" not in reason,
   "el motivo de bloqueo no filtra el token del comando")


print(f"\n  RESUMEN test_header_guard:  {PASS} OK   {FAIL} fallos\n")
sys.exit(1 if FAIL else 0)
