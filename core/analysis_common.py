# -*- coding: utf-8 -*-
import csv, hashlib, html, re, mimetypes
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

MAX_READ_BYTES = 5 * 1024 * 1024
TEXT_RE = re.compile(rb"[\x20-\x7e]{4,}")
RULE_RE = re.compile(r"^\s*(?:global\s+)?(?:private\s+)?rule\s+([A-Za-z_][A-Za-z0-9_]*)\b", re.M)
STRING_LINE_RE = re.compile(r"(?m)^\s*(\$[A-Za-z0-9_*]+)\s*=\s*(.+)$")
COMMON_GENERIC = [
    "kernel32.dll", "user32.dll", "advapi32.dll", "GetProcAddress", "LoadLibrary",
    "VirtualAlloc", "This program cannot be run in DOS mode", "mscoree.dll", "v4.0.30319",
    "System.", "publickeytoken"
]
ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".gz", ".tgz", ".tar", ".bz2", ".xz", ".cab", ".iso"}
SCRIPT_EXTS = {".ps1", ".js", ".vbs", ".vbe", ".bat", ".cmd", ".php", ".asp", ".aspx", ".jsp", ".py"}

def ensure_report_dir(path):
    p = Path(path or "reports")
    p.mkdir(parents=True, exist_ok=True)
    return p

def safe_read_text(path, limit=MAX_READ_BYTES):
    try:
        data = Path(path).read_bytes()[:limit]
    except Exception:
        return ""
    return data.decode("utf-8", errors="replace")

def printable_strings(path, limit=MAX_READ_BYTES):
    try:
        data = Path(path).read_bytes()[:limit]
    except Exception:
        return []
    out = []
    for m in TEXT_RE.finditer(data):
        try:
            s = m.group(0).decode("ascii", errors="ignore")
        except Exception:
            continue
        if s:
            out.append(s)
        if len(out) > 20000:
            break
    return out

def iter_input_files(source, include_rules=True, include_samples=True, include_logs=True):
    p = Path(source)
    if not source or not p.exists():
        return []
    exts_rule = {".yar", ".yara"}
    exts_log = {".txt", ".log", ".md", ".csv", ".json", ".html", ".htm"}
    if p.is_file():
        return [p]
    files = []
    for f in p.rglob("*"):
        if not f.is_file():
            continue
        ext = f.suffix.lower()
        if ext in exts_rule and include_rules:
            files.append(f)
        elif ext in exts_log and include_logs:
            files.append(f)
        elif include_samples and ext not in exts_rule | exts_log:
            files.append(f)
        if len(files) >= 3000:
            break
    return files

def extract_rule_blocks(text):
    blocks=[]; name=None; lines=[]; depth=0; in_rule=False
    for line in text.splitlines():
        if not in_rule:
            m = re.search(r"^\s*(?:global\s+)?(?:private\s+)?rule\s+([A-Za-z_][A-Za-z0-9_]*)\b", line)
            if m:
                in_rule=True; name=m.group(1); lines=[line]; depth=line.count("{")-line.count("}")
            continue
        lines.append(line); depth += line.count("{")-line.count("}")
        if depth <= 0 and "}" in line:
            blocks.append((name or "unknown_rule", "\n".join(lines)))
            name=None; lines=[]; depth=0; in_rule=False
    return blocks

def parse_yara_summary(path):
    text = safe_read_text(path)
    blocks = extract_rule_blocks(text)
    scores=[]; strings=0; goodware=0; negative=0; loose=[]; super_rules=0; generic=0
    per=[]
    for name, block in blocks:
        str_lines = STRING_LINE_RE.findall(block)
        rule_scores=[]
        for raw in re.findall(r"score:\s*['\"]?(-?\d+(?:\.\d+)?)", block, flags=re.I):
            try: rule_scores.append(float(raw))
            except Exception: pass
        gw = len(re.findall(r"Goodware String", block, flags=re.I))
        cond = re.search(r"condition\s*:\s*(.*?)(?:\n\s*}\s*$)", block, flags=re.I|re.S)
        cond_text = cond.group(1) if cond else ""
        is_loose = bool(re.search(r"\b(any\s+of\s+them|1\s+of\s+them)\b", cond_text, flags=re.I))
        is_super = "super_rule" in block.lower() or len(re.findall(r"(?m)^\s*hash\d+\s*=", block)) > 1 or "SUPER" in name.upper()
        gen = sum(1 for g in COMMON_GENERIC if g.lower() in block.lower())
        strings += len(str_lines); scores += rule_scores; goodware += gw; negative += sum(1 for s in rule_scores if s < 0)
        if is_loose: loose.append(name)
        if is_super: super_rules += 1
        generic += gen
        per.append({"name":name,"string_count":len(str_lines),"score_count":len(rule_scores),"scores":rule_scores,"goodware_count":gw,"loose":is_loose,"is_super":is_super,"generic_count":gen,"block":block})
    return {"path":str(path),"text":text,"rule_count":len(blocks),"string_count":strings,"score_count":len(scores),"max_score":max(scores) if scores else None,"avg_score":sum(scores)/len(scores) if scores else None,"min_score":min(scores) if scores else None,"negative_score_count":negative,"goodware_count":goodware,"super_rule_count":super_rules,"loose_conditions":loose,"generic_count":generic,"rules":per}

def validate_yara_syntax(path):
    p=Path(path)
    if not p.exists():
        return False, "file not found"
    try:
        import yara
        yara.compile(filepath=str(p))
        return True, "OK"
    except ImportError:
        # fallback: balanced braces and at least parseable rule keyword. This is conservative UI feedback, not a real compiler.
        text=safe_read_text(p)
        if "rule " in text and text.count("{") == text.count("}"):
            return True, "OK (basic parser; install yara-python for full validation)"
        return False, "yara-python not installed and basic parser found syntax problems"
    except Exception as e:
        return False, str(e)

def test_result_counts(rows):
    malware_total=malware_matches=goodware_fp=0
    for r in rows or []:
        ds=str(r.get("dataset","")).lower()
        if ds == "malware":
            malware_matches += 1
        elif ds == "goodware":
            goodware_fp += 1
    malware_total = malware_matches if malware_matches else 0
    return {"malware_matches": malware_matches, "malware_total": malware_total, "goodware_fp": goodware_fp, "has_test": bool(rows)}

def write_csv(path, rows, fields):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with Path(path).open("w", newline="", encoding="utf-8-sig") as fh:
        w=csv.DictWriter(fh, fieldnames=fields); w.writeheader()
        for r in rows: w.writerow({k:r.get(k,"") for k in fields})

def markdown_table(headers, rows):
    out=["| " + " | ".join(headers) + " |", "|" + "|".join(["---"]*len(headers)) + "|"]
    for row in rows:
        out.append("| " + " | ".join(str(x).replace("\n","<br>") for x in row) + " |")
    return "\n".join(out)

def file_kind(path):
    p=Path(path); ext=p.suffix.lower()
    try: head=p.read_bytes()[:8]
    except Exception: head=b""
    if head.startswith(b"MZ"): return "PE"
    if ext in SCRIPT_EXTS: return "script"
    if ext in ARCHIVE_EXTS: return "archive"
    return mimetypes.guess_type(str(p))[0] or ext or "unknown"

def hash_file(path, limit=None):
    md5=hashlib.md5(); sha256=hashlib.sha256(); read=0
    try:
        with Path(path).open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024*1024), b""):
                md5.update(chunk); sha256.update(chunk); read += len(chunk)
                if limit and read >= limit: break
        return md5.hexdigest(), sha256.hexdigest()
    except Exception:
        return "", ""

def simple_html(title, body):
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title><style>
body{{font-family:Segoe UI,Arial,sans-serif;margin:28px;background:#f6f7fb;color:#111827}} .card{{background:white;border:1px solid #e5e7eb;border-radius:12px;padding:16px;margin:14px 0;box-shadow:0 1px 3px #ddd}} table{{border-collapse:collapse;width:100%;background:white}} th,td{{border:1px solid #e5e7eb;padding:8px;text-align:left;vertical-align:top}} th{{background:#f3f4f6}} .badge{{display:inline-block;padding:8px 14px;border-radius:999px;font-weight:700}} .PASS{{background:#dcfce7;color:#166534}} .WARNING{{background:#fef3c7;color:#92400e}} .FAIL{{background:#fee2e2;color:#991b1b}} code{{background:#f3f4f6;padding:2px 4px;border-radius:4px}}
</style></head><body>{body}</body></html>"""
