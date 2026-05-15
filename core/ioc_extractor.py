# -*- coding: utf-8 -*-
import re
from collections import OrderedDict
from pathlib import Path
from .analysis_common import printable_strings, iter_input_files, write_csv, markdown_table

PATTERNS = [
    ("URL", re.compile(r"https?://[^\s\"'<>]+", re.I), "high"),
    ("Email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), "medium"),
    ("IPv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), "medium"),
    ("Registry", re.compile(r"\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\s\"']+", re.I), "high"),
    ("Named Pipe", re.compile(r"\\\\\.\\pipe\\[^\s\"']+", re.I), "high"),
    ("Windows Path", re.compile(r"(?:[A-Z]:\\|%[A-Z0-9_]+%\\|\\\\)[^\s\"'<>|]{4,}", re.I), "medium"),
    ("User-Agent", re.compile(r"(?:User-Agent|Mozilla/5\.0|Chrome/\d+|Firefox/\d+|MSIE\s\d+)[^\r\n\"']*", re.I), "medium"),
    ("Command", re.compile(r"\b(?:powershell(?:\.exe)?|cmd\.exe|wscript(?:\.exe)?|cscript(?:\.exe)?|schtasks(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?)\b", re.I), "high"),
    ("Crypto/Wallet", re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b|\b0x[a-fA-F0-9]{40}\b|wallet|bitcoin|monero|ethereum", re.I), "low"),
    ("Suspicious Path", re.compile(r"\b(?:AppData|Temp|Startup|ProgramData)\b", re.I), "medium"),
    ("Mutex-like", re.compile(r"\b(?:Global|Local)\\[A-Za-z0-9_.$-]{6,}\b|\bMutex[A-Za-z0-9_.$-]{4,}\b", re.I), "medium"),
    ("Domain", re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|info|biz|ru|cn|top|xyz|site|online|io|me|vn|co|uk|de|pw)\b", re.I), "medium"),
]

def extract_iocs(source, include_rules=True, include_samples=True, include_logs=True, max_files=2000):
    rows=[]; seen=set(); files=iter_input_files(source, include_rules, include_samples, include_logs)[:max_files]
    for f in files:
        content = "\n".join(printable_strings(f))
        if f.suffix.lower() in {".yar", ".yara", ".txt", ".log", ".md", ".csv", ".json"}:
            try: content += "\n" + f.read_text(encoding="utf-8", errors="replace")[:5*1024*1024]
            except Exception: pass
        for typ, pat, conf in PATTERNS:
            for m in pat.finditer(content):
                val=m.group(0).strip().strip('"\'`;,.')
                if len(val) < 4 or len(val) > 500: continue
                key=(typ,val,str(f))
                if key in seen: continue
                seen.add(key)
                note = "heuristic static extraction"
                rows.append({"type":typ,"value":val,"source_file":str(f),"confidence":conf,"note":note})
                if len(rows) > 10000: return rows
    return rows

def export_ioc_reports(rows, report_dir):
    report_dir=Path(report_dir); report_dir.mkdir(parents=True, exist_ok=True)
    csv_path=report_dir/"ioc_report.csv"; md_path=report_dir/"ioc_report.md"
    write_csv(csv_path, rows, ["type","value","source_file","confidence","note"])
    md=["# IOC Extractor Report", "", f"Total IOC: {len(rows)}", "", markdown_table(["Type","Value","Source file","Confidence","Note"], [[r.get("type"), r.get("value"), r.get("source_file"), r.get("confidence"), r.get("note")] for r in rows])]
    md_path.write_text("\n".join(md), encoding="utf-8")
    return md_path, csv_path
