# -*- coding: utf-8 -*-
"""Offline static malware sample analyzer used by the GUI.

This module does not execute the sample. It extracts static indicators,
optionally runs official VirusTotal/YARA CLI rules, and can render a quick
reviewable YARA rule from suspicious strings.  It is intentionally conservative:
it produces an analyst assessment, not a final AV verdict.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import math
import mimetypes
import re
from collections import Counter
from pathlib import Path
from typing import Iterable

SUSPICIOUS_KEYWORDS = [
    "powershell", " -enc", "frombase64string", "cmd.exe", "wscript", "cscript",
    "rundll32", "regsvr32", "schtasks", "wmic", "vssadmin", "bcdedit",
    "delete shadows", "shadowcopy", "wevtutil", "netsh", "startup", "runonce",
    "appdata", "temp\\", "\\temp", "/tmp", "http://", "https://", ".onion",
    "tor", "wallet", "bitcoin", "monero", "ransom", "decrypt", "encrypt",
    "mutex", "keylogger", "screenshot", "clipboard", "telegram", "bot",
    "panel", "gate", "inject", "processhacker", "mimikatz", "lsass",
]

SUSPICIOUS_IMPORTS = {
    "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
    "OpenProcess", "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    "WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW",
    "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
    "HttpOpenRequestA", "HttpOpenRequestW", "URLDownloadToFileA", "URLDownloadToFileW",
    "CryptEncrypt", "CryptDecrypt", "CryptAcquireContextA", "CryptAcquireContextW",
    "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
}

COMMON_RULE_NOISE = {
    "this program cannot be run in dos mode", "microsoft", "windows", "kernel32.dll",
    "user32.dll", "advapi32.dll", "ntdll.dll", "msvcrt.dll", "getprocaddress",
    "loadlibrarya", "loadlibraryw", "virtualalloc", "createfilea", "createfilew",
}

MAX_READ = 24 * 1024 * 1024


def sha_hashes(path: Path) -> dict[str, str]:
    md5 = hashlib.md5(); sha1 = hashlib.sha1(); sha256 = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _decode_wide(data: bytes) -> bytes:
    out = bytearray(); i = 0
    while i + 1 < len(data):
        if data[i + 1] == 0 and 32 <= data[i] <= 126:
            out.append(data[i]); i += 2
        else:
            if len(out) >= 5:
                out.append(0x0A)
            i += 1
    return bytes(out)


def extract_strings(path: Path, min_len: int = 5, limit: int = 5000) -> list[str]:
    try:
        data = path.read_bytes()[:MAX_READ]
    except Exception:
        return []
    strings: list[str] = []
    seen: set[str] = set()
    for blob in (data, _decode_wide(data)):
        for m in re.finditer(rb"[\x20-\x7e]{%d,}" % max(4, min_len), blob):
            s = m.group(0).decode("latin-1", errors="ignore").strip()
            s = re.sub(r"\s+", " ", s)
            if s and s not in seen:
                seen.add(s); strings.append(s[:240])
            if len(strings) >= limit:
                return strings
    return strings


def file_type(path: Path, data: bytes) -> str:
    head = data[:16]
    if head.startswith(b"MZ"):
        return "PE executable/library"
    if head.startswith(b"\x7fELF"):
        return "ELF binary"
    if head.startswith(b"PK"):
        return "ZIP/Office/Archive"
    if head.startswith(b"%PDF"):
        return "PDF document"
    guessed = mimetypes.guess_type(str(path))[0]
    return guessed or path.suffix.lower().lstrip(".") or "unknown"


def _score_string(s: str) -> int:
    low = s.lower()
    score = min(30, len(s) // 4)
    if any(k in low for k in SUSPICIOUS_KEYWORDS):
        score += 35
    if re.search(r'https?://|[a-z0-9.-]+\.[a-z]{2,}[/:"]', low):
        score += 20
    if re.search(r"[a-z]:\\|\\appdata\\|/tmp|/var/tmp", low):
        score += 12
    if re.search(r"[{}%$^]|[A-Za-z0-9+/]{24,}={0,2}", s):
        score += 5
    if low.strip() in COMMON_RULE_NOISE:
        score -= 50
    if re.fullmatch(r"[0-9a-fA-F]{24,}", s):
        score -= 20
    return score


def suspicious_strings(strings: Iterable[str], max_items: int = 40) -> list[dict]:
    rows = []
    for s in strings:
        score = _score_string(s)
        if score >= 25:
            reason = []
            low = s.lower()
            for k in SUSPICIOUS_KEYWORDS:
                if k in low:
                    reason.append(k)
                    if len(reason) >= 3:
                        break
            rows.append({"value": s, "score": score, "reason": ", ".join(reason) or "rare/suspicious string"})
    rows.sort(key=lambda r: (-r["score"], -len(r["value"]), r["value"].lower()))
    return rows[:max_items]


def pe_info(path: Path) -> dict:
    info = {"is_pe": False, "sections": [], "imports": [], "warnings": []}
    try:
        import pefile  # type: ignore
    except Exception as exc:
        info["warnings"].append(f"pefile not installed: {exc}")
        return info
    try:
        pe = pefile.PE(str(path), fast_load=False)
        info["is_pe"] = True
        try:
            ts = int(getattr(pe.FILE_HEADER, "TimeDateStamp", 0))
            if ts:
                info["compile_time"] = _dt.datetime.utcfromtimestamp(ts).isoformat() + "Z"
        except Exception:
            pass
        for sec in pe.sections:
            name = sec.Name.decode("latin-1", errors="ignore").rstrip("\x00") or "<unnamed>"
            try:
                sdata = sec.get_data()
                sent = entropy(sdata)
            except Exception:
                sent = 0.0
            info["sections"].append({
                "name": name,
                "virtual_size": int(getattr(sec, "Misc_VirtualSize", 0)),
                "raw_size": int(getattr(sec, "SizeOfRawData", 0)),
                "entropy": round(sent, 3),
            })
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("latin-1", errors="ignore") if entry.dll else ""
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode("latin-1", errors="ignore")
                        info["imports"].append(f"{dll}!{name}" if dll else name)
        pe.close()
    except Exception as exc:
        info["warnings"].append(str(exc))
    return info


def assess(profile: dict) -> dict:
    score = 0
    reasons = []
    if profile.get("file_type", "").startswith("PE"):
        score += 10; reasons.append("PE executable/library")
    if profile.get("entropy", 0) >= 7.2:
        score += 25; reasons.append("high entropy, possible packed/encrypted content")
    if profile.get("yara_matches"):
        score += 40; reasons.append("matched existing YARA rule(s)")
    susp = profile.get("suspicious_strings") or []
    if susp:
        score += min(30, len(susp) * 4); reasons.append(f"{len(susp)} suspicious string indicator(s)")
    imports = profile.get("suspicious_imports") or []
    if imports:
        score += min(25, len(imports) * 3); reasons.append(f"{len(imports)} suspicious import/API indicator(s)")
    sections = profile.get("pe", {}).get("sections", [])
    high_sections = [s for s in sections if s.get("entropy", 0) >= 7.2]
    if high_sections:
        score += min(20, len(high_sections) * 5); reasons.append("high-entropy PE section(s)")
    score = max(0, min(100, score))
    if score >= 75:
        label = "High risk / likely malicious indicators"
    elif score >= 45:
        label = "Suspicious / needs analyst review"
    elif score >= 20:
        label = "Low-to-medium suspicion"
    else:
        label = "No strong static indicators found"
    return {"score": score, "label": label, "reasons": reasons}


def safe_rule_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_]+", "_", value or "sample")
    value = re.sub(r"_+", "_", value).strip("_") or "sample"
    if value[0].isdigit():
        value = "sample_" + value
    return value[:80]


def escape_yara_string(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\\": out.append("\\\\")
        elif ch == '"': out.append('\\"')
        elif ch == "\t": out.append("\\t")
        elif 32 <= o <= 126: out.append(ch)
        else: out.append(f"\\x{o:02x}")
    return "".join(out)


def render_quick_rule(profile: dict, max_strings: int = 12) -> str:
    sha = profile.get("hashes", {}).get("sha256", "")
    base = safe_rule_name(Path(profile.get("path", "sample")).stem)
    strings = list(profile.get("suspicious_strings") or [])[:max_strings]
    if not strings:
        strings = [{"value": s, "score": 0, "reason": "selected printable string"} for s in profile.get("strings_preview", [])[:max_strings]]
    needed = 1 if len(strings) <= 2 else min(len(strings), max(2, math.ceil(len(strings) * 0.35)))
    today = _dt.date.today().isoformat()
    lines = [
        "/* Auto-generated quick triage rule from one sample.",
        "   Review before using in production. For family signatures, use Generate Family Rule with multiple samples. */",
        f"rule {base}_AutoTriage",
        "{",
        "    meta:",
        f"        description = \"Auto triage rule generated from uploaded malware sample\"",
        f"        sha256 = \"{sha}\"",
        f"        date = \"{today}\"",
        "        source = \"Analyze Malware Sample screen\"",
        "    strings:",
    ]
    if strings:
        for i, row in enumerate(strings, 1):
            val = escape_yara_string(str(row.get("value", ""))[:180])
            lines.append(f"        $s{i:02d} = \"{val}\" ascii wide nocase // {row.get('reason','indicator')} score={row.get('score',0)}")
    else:
        lines.append("        $placeholder = \"no_static_string_found_review_manually\" ascii")
    lines += [
        "    condition:",
        "        uint16(0) == 0x5A4D and " + (f"{needed} of ($s*)" if strings else "$placeholder"),
        "}",
        "",
    ]
    return "\n".join(lines)


def analyze_file(path: str | Path, rule_files: Iterable[str | Path] | None = None, engine=None) -> dict:
    path = Path(path)
    data = path.read_bytes()[:MAX_READ]
    hashes = sha_hashes(path)
    strs = extract_strings(path)
    susp = suspicious_strings(strs)
    pe = pe_info(path)
    imports = pe.get("imports", []) or []
    suspicious_imports = [i for i in imports if i.split("!")[-1] in SUSPICIOUS_IMPORTS]
    profile = {
        "path": str(path),
        "name": path.name,
        "size": path.stat().st_size,
        "file_type": file_type(path, data),
        "entropy": round(entropy(data), 3),
        "hashes": hashes,
        "strings_count": len(strs),
        "strings_preview": strs[:80],
        "suspicious_strings": susp,
        "pe": pe,
        "suspicious_imports": suspicious_imports[:60],
        "yara_matches": [],
        "yara_errors": [],
    }
    if rule_files and engine and getattr(engine, "available", lambda: False)():
        for rp in rule_files:
            rp = Path(rp)
            if not rp.exists() or not rp.is_file():
                continue
            try:
                matches = engine.scan_file(rp, path)
                for rule in matches:
                    profile["yara_matches"].append({"rule_file": str(rp), "rule": rule})
            except Exception as exc:
                profile["yara_errors"].append({"rule_file": str(rp), "error": str(exc)})
    profile["assessment"] = assess(profile)
    return profile


def discover_rule_files(path: str | Path) -> list[Path]:
    p = Path(path)
    if not str(path).strip():
        return []
    if p.is_file() and p.suffix.lower() in {".yar", ".yara"}:
        return [p]
    if p.is_dir():
        return sorted([x for x in p.rglob("*") if x.is_file() and x.suffix.lower() in {".yar", ".yara"}])
    return []


def render_markdown_report(profile: dict) -> str:
    a = profile.get("assessment", {})
    h = profile.get("hashes", {})
    lines = [
        f"# Malware sample assessment: {profile.get('name')}",
        "",
        "## File",
        f"- Path: `{profile.get('path')}`",
        f"- Size: **{profile.get('size')} bytes**",
        f"- Type: **{profile.get('file_type')}**",
        f"- Entropy: **{profile.get('entropy')}**",
        f"- MD5: `{h.get('md5','')}`",
        f"- SHA1: `{h.get('sha1','')}`",
        f"- SHA256: `{h.get('sha256','')}`",
        "",
        "## Assessment",
        f"- Score: **{a.get('score', 0)}/100**",
        f"- Label: **{a.get('label', '')}**",
    ]
    for r in a.get("reasons", []):
        lines.append(f"- Reason: {r}")
    lines += ["", "## YARA matches"]
    if profile.get("yara_matches"):
        for m in profile["yara_matches"]:
            lines.append(f"- `{m.get('rule')}` from `{m.get('rule_file')}`")
    else:
        lines.append("- No YARA rule matched, or no rule folder was selected.")
    lines += ["", "## Suspicious strings"]
    for row in profile.get("suspicious_strings", [])[:30]:
        val = str(row.get("value", "")).replace("`", "'")
        lines.append(f"- score={row.get('score')} reason={row.get('reason')}: `{val}`")
    if not profile.get("suspicious_strings"):
        lines.append("- No strong suspicious strings extracted.")
    lines += ["", "## Suspicious imports"]
    for imp in profile.get("suspicious_imports", [])[:50]:
        lines.append(f"- `{imp}`")
    if not profile.get("suspicious_imports"):
        lines.append("- No suspicious PE imports found or file is not PE.")
    lines += ["", "## PE sections"]
    for sec in profile.get("pe", {}).get("sections", [])[:30]:
        lines.append(f"- `{sec.get('name')}` raw={sec.get('raw_size')} virtual={sec.get('virtual_size')} entropy={sec.get('entropy')}")
    if not profile.get("pe", {}).get("sections"):
        lines.append("- No PE section information available.")
    lines += ["", "## Suggested quick YARA rule", "```yara", render_quick_rule(profile), "```", ""]
    return "\n".join(lines)
