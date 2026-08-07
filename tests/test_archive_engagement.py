#!/usr/bin/env python3
"""Tests de archive_engagement.py — archivado del blackboard activo en engagements/<id>/ (Fase 5b).

Cubre, con un repo TEMPORAL sintético (nunca toca el repo real):
- Archiva el blackboard activo → engagements/<id>/engagement.json byte-idéntico; NO muta el activo.
- Idempotente (re-ejecutar deja el mismo contenido).
- --on-switch: no-op si el id activo == nuevo id; archiva si son distintos.
- Fail-safe: sin blackboard activo, con JSON corrupto, o con engagement_id inválido/traversal → no
  archiva y no revienta (archived=False).
- El destino queda SIEMPRE confinado bajo engagements/ (un id con '..' o dot-leading se rechaza).
- AGENTS.md cablea el tool en el Cierre y en la conmutación (paso 1/paso 6).

Sin pytest: asserts planos, `python tests/test_archive_engagement.py` (sale 1 si algo falla).
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import archive_engagement as ae  # noqa: E402

_fail = []


def check(name, cond):
    print(("  ok  " if cond else " FAIL ") + name)
    if not cond:
        _fail.append(name)


def _mkrepo(engagement_id="LAB-TEST-1", extra=None):
    """Crea un repo temporal con contracts/engagement.json activo. Devuelve la raíz."""
    root = tempfile.mkdtemp(prefix="da-archive-test-")
    os.makedirs(os.path.join(root, "contracts"))
    data = {"engagement_id": engagement_id, "phase": "reporting",
            "targets": [{"id": "t1"}], "findings": []}
    if extra:
        data.update(extra)
    with open(os.path.join(root, "contracts", "engagement.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return root


def _archived_path(root, eid):
    return os.path.join(root, "engagements", eid, "engagement.json")


def t_archives_and_preserves():
    root = _mkrepo("LAB-2026-009")
    try:
        bb = os.path.join(root, "contracts", "engagement.json")
        before = open(bb, "rb").read()
        outcome, msg, dst = ae.archive_active(root)
        check("archive_active devuelve outcome='archived'", outcome == ae.ARCHIVED)
        dstp = _archived_path(root, "LAB-2026-009")
        check("crea engagements/<id>/engagement.json", os.path.isfile(dstp))
        if os.path.isfile(dstp):
            check("archivo byte-idéntico al blackboard activo", open(dstp, "rb").read() == before)
        check("NO muta el blackboard activo", open(bb, "rb").read() == before)
        check("dst devuelto es relativo bajo engagements/",
              dst is not None and dst.replace("\\", "/").startswith("engagements/"))
        # sin fichero .tmp huérfano
        check("no deja engagement.json.tmp huérfano", not os.path.exists(dstp + ".tmp"))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_idempotent():
    root = _mkrepo("LAB-2026-009")
    try:
        ae.archive_active(root)
        first = open(_archived_path(root, "LAB-2026-009"), "rb").read()
        outcome2, _, _ = ae.archive_active(root)
        second = open(_archived_path(root, "LAB-2026-009"), "rb").read()
        check("re-archivar es idempotente (mismo contenido)", first == second and outcome2 == ae.ARCHIVED)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_on_switch():
    # mismo id => no-op (no hay conmutación)
    root = _mkrepo("SAME-ID")
    try:
        outcome, msg, _ = ae.archive_active(root, on_switch="SAME-ID")
        check("--on-switch con el MISMO id = no-op (outcome='noop')", outcome == ae.NOOP)
        check("no-op no crea la carpeta del histórico", not os.path.exists(_archived_path(root, "SAME-ID")))
    finally:
        shutil.rmtree(root, ignore_errors=True)
    # id distinto => archiva el saliente, SIN mutar el activo (council #3)
    root = _mkrepo("OUTGOING")
    try:
        bb = os.path.join(root, "contracts", "engagement.json")
        before = open(bb, "rb").read()
        outcome, _, _ = ae.archive_active(root, on_switch="NEW-ONE")
        check("--on-switch con id DISTINTO archiva el saliente", outcome == ae.ARCHIVED)
        check("archiva el saliente por su propio id", os.path.isfile(_archived_path(root, "OUTGOING")))
        check("--on-switch NO muta el blackboard activo", open(bb, "rb").read() == before)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_no_active():
    root = tempfile.mkdtemp(prefix="da-archive-test-")
    try:
        outcome, msg, dst = ae.archive_active(root)
        check("sin blackboard activo => outcome='noop', no revienta", outcome == ae.NOOP and dst is None)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_corrupt_json():
    root = tempfile.mkdtemp(prefix="da-archive-test-")
    os.makedirs(os.path.join(root, "contracts"))
    with open(os.path.join(root, "contracts", "engagement.json"), "w", encoding="utf-8") as f:
        f.write("{ esto no es json ")
    try:
        outcome, _, _ = ae.archive_active(root)
        # HAY un blackboard pero no es archivable => 'error' (no 'noop'): en conmutación NO clobbers
        check("blackboard corrupto => outcome='error' (fail-safe, distinguible del no-op)", outcome == ae.ERROR)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_invalid_or_traversal_id():
    for bad in (".", "..", "...", "../evil", "a/b", "a\\b", "..no", "a..b", "", None, 123):
        root = _mkrepo("PLACEHOLDER", extra={"engagement_id": bad})
        try:
            outcome, _, _ = ae.archive_active(root)
            check(f"id inválido/traversal {bad!r} => outcome='error'", outcome == ae.ERROR)
            # y no ha creado NADA fuera de contracts/
            check(f"id {bad!r} no crea engagements/", not os.path.isdir(os.path.join(root, "engagements")))
        finally:
            shutil.rmtree(root, ignore_errors=True)


def t_realpath_belt_symlink():
    """El cinturón realpath rechaza un symlink pre-plantado en engagements/<id> que resuelva FUERA de la
    zona E3 (lo que _safe_eid no cubre). Solo Linux/priv: si el SO no deja crear symlinks, se omite."""
    root = _mkrepo("LINKED")
    outside = tempfile.mkdtemp(prefix="da-archive-outside-")
    try:
        eng_base = os.path.join(root, "engagements")
        os.makedirs(eng_base)
        link = os.path.join(eng_base, "LINKED")
        try:
            os.symlink(outside, link, target_is_directory=True)
        except (OSError, NotImplementedError, AttributeError):
            check("(omitido) symlink no soportado en este SO — el belt corre en Linux", True)
            return
        outcome, _, _ = ae.archive_active(root)
        check("symlink que escapa de engagements/ => outcome='error' (belt realpath)", outcome == ae.ERROR)
        check("el belt NO escribió fuera de la zona E3",
              not os.path.exists(os.path.join(outside, "engagement.json")))
    finally:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(outside, ignore_errors=True)


def t_oserror_branch():
    """engagements/ como FICHERO (no dir) => makedirs falla => outcome='error', sin .tmp huérfano."""
    root = _mkrepo("IOFAIL")
    try:
        with open(os.path.join(root, "engagements"), "w", encoding="utf-8") as f:
            f.write("no soy un directorio")
        outcome, _, _ = ae.archive_active(root)
        check("engagements/ es fichero => outcome='error' (rama OSError)", outcome == ae.ERROR)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_cli_exit_codes():
    """La CLI: archived/no-op => 0, error => 2 (señal para un wrapper determinista o el Orquestador)."""
    tool = os.path.join(ROOT, "tools", "archive_engagement.py")
    # éxito
    root = _mkrepo("EXIT-OK")
    try:
        rc = subprocess.run([sys.executable, tool, "--root", root, "--quiet"]).returncode
        check("CLI éxito => exit 0", rc == 0)
    finally:
        shutil.rmtree(root, ignore_errors=True)
    # no-op (sin blackboard)
    root = tempfile.mkdtemp(prefix="da-archive-test-")
    try:
        rc = subprocess.run([sys.executable, tool, "--root", root, "--quiet"]).returncode
        check("CLI no-op => exit 0", rc == 0)
    finally:
        shutil.rmtree(root, ignore_errors=True)
    # error (corrupto)
    root = tempfile.mkdtemp(prefix="da-archive-test-")
    os.makedirs(os.path.join(root, "contracts"))
    with open(os.path.join(root, "contracts", "engagement.json"), "w", encoding="utf-8") as f:
        f.write("{ roto ")
    try:
        rc = subprocess.run([sys.executable, tool, "--root", root, "--quiet"]).returncode
        check("CLI error genuino => exit 2 (distinguible del no-op)", rc == 2)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def t_safe_eid_unit():
    check("_safe_eid acepta ids normales",
          all(ae._safe_eid(x) for x in ("LAB-2026-009", "GATE-x", "a_b.c", "A1")))
    check("_safe_eid rechaza dot-leading / traversal / vacío / no-str",
          not any(ae._safe_eid(x) for x in (".", "..", "...", "a..b", "..no", "a/b", "a\\b", "", None, 5)))


def t_agents_md_wired():
    with open(os.path.join(ROOT, "AGENTS.md"), encoding="utf-8") as f:
        agents = f.read()
    check("AGENTS.md menciona tools/archive_engagement.py", "tools/archive_engagement.py" in agents)
    check("AGENTS.md documenta el seam --on-switch", "--on-switch" in agents)


def main():
    t_archives_and_preserves()
    t_idempotent()
    t_on_switch()
    t_no_active()
    t_corrupt_json()
    t_invalid_or_traversal_id()
    t_realpath_belt_symlink()
    t_oserror_branch()
    t_cli_exit_codes()
    t_safe_eid_unit()
    t_agents_md_wired()
    print()
    if _fail:
        print(f"{len(_fail)} FALLO(S): " + "; ".join(_fail))
        return 1
    print("OK — archive_engagement")
    return 0


if __name__ == "__main__":
    sys.exit(main())
