# -*- coding: utf-8 -*-
import re
from pathlib import Path
from .analysis_common import printable_strings, iter_input_files, write_csv, markdown_table

RULES = [
    (r"powershell", "T1059.001", "PowerShell", "Execution", "high"),
    (r"cmd\.exe|\bcmd\b", "T1059.003", "Windows Command Shell", "Execution", "high"),
    (r"wscript|cscript|\.vbs", "T1059.005", "Visual Basic", "Execution", "medium"),
    (r"schtasks", "T1053.005", "Scheduled Task", "Persistence", "high"),
    (r"startup|RunOnce|CurrentVersion\\Run", "T1547.001", "Registry Run Keys / Startup Folder", "Persistence", "high"),
    (r"VirtualAlloc|WriteProcessMemory|CreateRemoteThread", "T1055", "Process Injection", "Defense Evasion", "medium"),
    (r"ReflectiveLoader", "T1620", "Reflective Code Loading", "Defense Evasion", "high"),
    (r"password|Chrome|Firefox|browser", "T1555", "Credentials from Password Stores", "Credential Access", "low"),
    (r"https?://|\b(?:\d{1,3}\.){3}\d{1,3}\b|[a-z0-9.-]+\.(?:com|net|org|ru|cn|top|xyz|io|vn)\b", "T1071.001", "Web Protocols", "Command and Control", "medium"),
    (r"\\\\\.\\pipe\\", "T1106", "Native API / IPC named pipe indicator", "Execution", "medium"),
    (r"AppData|Temp|ProgramData", "T1105", "Ingress Tool Transfer / file staging indicator", "Command and Control", "low"),
    (r"rundll32|regsvr32", "T1218", "System Binary Proxy Execution", "Defense Evasion", "high"),
]

def collect_text(source, iocs=None):
    parts=[]
    for r in iocs or []:
        parts.append(str(r.get("value", "")))
    for f in iter_input_files(source, True, True, True)[:1000]:
        parts.extend(printable_strings(f)[:3000])
        if f.suffix.lower() in {".yar", ".yara", ".txt", ".log", ".md"}:
            try: parts.append(f.read_text(encoding="utf-8", errors="replace")[:5*1024*1024])
            except Exception: pass
    return "\n".join(parts)

def map_mitre(source=None, iocs=None):
    text=collect_text(source, iocs)
    rows=[]; seen=set()
    for pat, tid, name, tactic, conf in RULES:
        rx=re.compile(pat, re.I)
        for m in rx.finditer(text):
            ev=m.group(0)[:180]
            key=(tid, ev.lower())
            if key in seen: continue
            seen.add(key)
            rows.append({"indicator":ev,"technique_id":tid,"technique_name":name,"tactic":tactic,"evidence":ev,"confidence":conf})
            if len(rows) > 500: return rows
    return rows

def export_mitre_reports(rows, report_dir):
    report_dir=Path(report_dir); report_dir.mkdir(parents=True, exist_ok=True)
    csv_path=report_dir/"mitre_mapping_report.csv"; md_path=report_dir/"mitre_mapping_report.md"
    write_csv(csv_path, rows, ["indicator","technique_id","technique_name","tactic","evidence","confidence"])
    lines=["# MITRE ATT&CK Mapping Report", "", "MITRE mapping is heuristic and should be reviewed by analyst.", "", f"Total mapping: {len(rows)}", "", markdown_table(["Indicator","Technique ID","Technique Name","Tactic","Evidence","Confidence"], [[r.get("indicator"),r.get("technique_id"),r.get("technique_name"),r.get("tactic"),r.get("evidence"),r.get("confidence")] for r in rows])]
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return md_path, csv_path
