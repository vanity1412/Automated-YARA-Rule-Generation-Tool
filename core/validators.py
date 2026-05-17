# -*- coding: utf-8 -*-
from pathlib import Path
from core.yara_engine import YaraEngine, describe_local_yara_source, describe_local_yara_x_source, describe_local_yara_cli


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
        describe_local_yara_source(workdir),
        describe_local_yara_cli(workdir),
        describe_local_yara_x_source(workdir),
        YaraEngine(workdir, prefer_yara_x=False, prefer_cli=True).as_row(),
    ]
    ok = True
    for name, result, detail in checks:
        if isinstance(result, bool):
            status = "OK" if result else "Missing"
            ok = ok and bool(result)
        else:
            status = result
            if status == "Missing":
                ok = False
        rows.append((name, status, detail))
    for mod in ["pefile", "lxml", "yara_x", "yara"]:
        try:
            __import__(mod)
            rows.append((f"Python module {mod}", "OK", "importable"))
        except Exception as e:
            rows.append((f"Python module {mod}", "Warning", str(e)))
    db_count = len(list((workdir / "dbs").glob("*.db"))) if (workdir / "dbs").exists() else 0
    rows.append(("DB files", "OK" if db_count else "Warning", str(db_count)))
    return ok, rows
