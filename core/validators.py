# -*- coding: utf-8 -*-
from pathlib import Path

def validate_environment(state):
    workdir = Path(state.var_workdir.get())
    rows = []
    checks = [
        ("Python executable", bool(state.var_python.get()), state.var_python.get()),
        ("Working directory", workdir.is_dir(), str(workdir)),
        ("yarGen.py", Path(state.var_yargen.get()).is_file(), state.var_yargen.get()),
        ("requirements.txt", (workdir / "requirements.txt").is_file(), str(workdir / "requirements.txt")),
        ("dbs folder", (workdir / "dbs").is_dir(), str(workdir / "dbs")),
        ("3rdparty/strings.xml", (workdir / "3rdparty" / "strings.xml").is_file(), str(workdir / "3rdparty" / "strings.xml")),
    ]
    ok = True
    for name, result, detail in checks:
        rows.append((name, "OK" if result else "Missing", detail))
        ok = ok and bool(result)
    for mod in ["pefile", "lxml", "yara"]:
        try:
            __import__(mod)
            rows.append((f"Python module {mod}", "OK", "importable"))
        except Exception as e:
            rows.append((f"Python module {mod}", "Warning", str(e)))
    db_count = len(list((workdir / "dbs").glob("*.db"))) if (workdir / "dbs").exists() else 0
    rows.append(("DB files", "OK" if db_count else "Warning", str(db_count)))
    return ok, rows
