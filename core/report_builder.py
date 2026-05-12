# -*- coding: utf-8 -*-
import csv, html as html_lib
from pathlib import Path

def export_test_csv(rows, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["dataset", "file", "rule", "is_false_positive", "notes"]
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fields})

def export_test_html(rows, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    trs = []
    for r in rows:
        trs.append("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            html_lib.escape(r.get("dataset", "")),
            html_lib.escape(r.get("rule", "")),
            html_lib.escape(r.get("file", "")),
            html_lib.escape(r.get("is_false_positive", "")),
            html_lib.escape(r.get("notes", "")),
        ))
    doc = """<!doctype html><meta charset='utf-8'>
    <title>YARA Test Report</title>
    <style>body{font-family:Segoe UI,Arial;margin:24px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:6px}th{background:#f3f4f6}</style>
    <h1>YARA Test Report</h1>
    <table><tr><th>Dataset</th><th>Rule</th><th>File</th><th>False Positive</th><th>Notes</th></tr>{}</table>
    """.format("".join(trs))
    path.write_text(doc, encoding="utf-8")
