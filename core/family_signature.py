# -*- coding: utf-8 -*-
"""Build YARA signatures from common features of one malware family.

This module complements yarGen:
- yarGen generates scored YARA rules from samples.
- This module extracts strings shared by many samples in the same family and
  writes a compact, reviewable YARA rule that can be validated/scanned by the
  official YARA engine through yara-python or CLI.
"""
from __future__ import annotations

import csv
import datetime as _dt
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

MIN_DEFAULT_LEN = 6
MAX_READ_BYTES = 12 * 1024 * 1024

_GENERIC_TOKENS = {
    "this program cannot be run in dos mode", "microsoft", "windows", "system32",
    "kernel32.dll", "user32.dll", "advapi32.dll", "ntdll.dll", "shell32.dll",
    "msvcrt.dll", "getprocaddress", "loadlibrary", "virtualalloc", "createfile",
    "readfile", "writefile", "closehandle", "software", "version", "debug",
    "sample", "test", "null", "true", "false", "error", "warning",
}

_SUSPICIOUS_HINTS = (
    "http://", "https://", ".onion", "powershell", "cmd.exe", "wscript",
    "cscript", "rundll32", "regsvr32", "schtasks", "startup", "appdata",
    "temp\\", "\\temp", "/tmp", "mutex", "bitcoin", "wallet", "encrypt",
    "decrypt", "keylogger", "bot", "gate", "panel", "payload", "inject",
    "process", "privilege", "autorun", "registry", "beacon",
)


def _iter_files(folder: Path) -> list[Path]:
    if not folder.exists():
        return []
    return [p for p in folder.rglob("*") if p.is_file()]


def _decode_wide(data: bytes) -> bytes:
    # Turn simple UTF-16LE ASCII-ish strings into normal bytes for tokenization.
    out = bytearray()
    i = 0
    while i + 1 < len(data):
        if data[i + 1] == 0 and 32 <= data[i] <= 126:
            out.append(data[i])
            i += 2
        else:
            if len(out) >= MIN_DEFAULT_LEN:
                out.append(0x0A)
            i += 1
    return bytes(out)


def extract_strings(path: Path, min_len: int = MIN_DEFAULT_LEN) -> set[str]:
    try:
        data = path.read_bytes()[:MAX_READ_BYTES]
    except Exception:
        return set()
    candidates: set[str] = set()
    for blob in (data, _decode_wide(data)):
        pattern = rb"[\x20-\x7e]{%d,}" % max(3, int(min_len))
        for m in re.finditer(pattern, blob):
            raw = m.group(0).decode("latin-1", errors="ignore").strip()
            raw = re.sub(r"\s+", " ", raw)
            if _keep_string(raw, min_len):
                candidates.add(raw[:180])
            # Also keep meaningful URL/path/config tokens inside long lines.
            for token in re.split(r"[^A-Za-z0-9_./:@$%+\-=\\]+", raw):
                token = token.strip()
                if _keep_string(token, min_len):
                    candidates.add(token[:160])
            if len(candidates) > 7000:
                break
    return candidates


def _keep_string(s: str, min_len: int) -> bool:
    if len(s) < min_len or len(s) > 220:
        return False
    low = s.lower().strip()
    if low in _GENERIC_TOKENS:
        return False
    if len(set(low)) <= 3:
        return False
    if re.fullmatch(r"[0-9a-fA-F]{16,}", s):
        return False
    if re.fullmatch(r"[0-9.]+", s):
        return False
    return True


def _string_score(s: str, count: int, total: int) -> int:
    low = s.lower()
    score = min(30, len(s) // 3) + count * 4
    if any(h in low for h in _SUSPICIOUS_HINTS):
        score += 25
    if re.search(r"[A-Za-z]:\\|/usr/|/var/|/tmp/|\\appdata\\", low):
        score += 8
    if re.search(r'https?://|[a-z0-9.-]+\.[a-z]{2,}[/:"]', low):
        score += 15
    if count == total:
        score += 10
    return score


def build_common_profile(
    sample_dir: str | Path,
    family_name: str,
    goodware_dir: str | Path | None = None,
    min_coverage_ratio: float = 0.60,
    min_len: int = MIN_DEFAULT_LEN,
    max_features: int = 40,
) -> dict:
    sample_dir = Path(sample_dir)
    files = _iter_files(sample_dir)
    per_file: list[tuple[Path, set[str]]] = []
    counter: Counter[str] = Counter()
    examples: dict[str, list[str]] = defaultdict(list)

    for p in files:
        strings = extract_strings(p, min_len=min_len)
        if not strings:
            continue
        per_file.append((p, strings))
        for s in strings:
            counter[s] += 1
            if len(examples[s]) < 3:
                examples[s].append(p.name)

    goodware_strings: set[str] = set()
    if goodware_dir:
        gd = Path(goodware_dir)
        for gp in _iter_files(gd)[:300]:
            goodware_strings |= extract_strings(gp, min_len=min_len)
            if len(goodware_strings) > 100000:
                break

    total = len(per_file)
    min_count = max(2, int(math.ceil(total * float(min_coverage_ratio)))) if total else 0
    rows = []
    for s, count in counter.items():
        if count < min_count:
            continue
        if s in goodware_strings:
            continue
        rows.append({
            "value": s,
            "count": count,
            "coverage": (count / total) if total else 0.0,
            "score": _string_score(s, count, total),
            "examples": ", ".join(examples.get(s, [])[:3]),
        })
    rows.sort(key=lambda r: (-r["score"], -r["coverage"], -len(r["value"]), r["value"].lower()))
    rows = rows[:max(1, int(max_features))]
    return {
        "family_name": family_name,
        "sample_dir": str(sample_dir),
        "sample_count": len(files),
        "analyzed_count": total,
        "min_count": min_count,
        "min_coverage_ratio": float(min_coverage_ratio),
        "min_len": int(min_len),
        "features": rows,
    }


def _escape_yara_string(s: str) -> str:
    out = []
    for ch in s:
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\t":
            out.append("\\t")
        elif 32 <= code <= 126:
            out.append(ch)
        else:
            out.append(f"\\x{code:02x}")
    return "".join(out)


def _safe_identifier(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_]+", "_", (value or "").strip())
    value = re.sub(r"_+", "_", value).strip("_")
    if not value:
        value = "malware_family"
    if value[0].isdigit():
        value = "family_" + value
    return value


def render_yara_rule(profile: dict, author: str = "", reference: str = "", license_text: str = "") -> str:
    family = _safe_identifier(profile.get("family_name") or "malware_family")
    features = list(profile.get("features") or [])
    today = _dt.date.today().isoformat()
    needed = (1 if len(features) <= 1 else min(len(features), max(2, int(math.ceil(len(features) * 0.35))))) if features else 1
    lines = [
        "/*",
        "  Auto-generated supplemental family rule.",
        "  Source: common features across samples from the same malware family.",
        "  Use together with yarGen output, then validate with the YARA engine.",
        "*/",
        f"rule {family}_CommonFamilyFeatures",
        "{",
        "    meta:",
        f"        family = \"{_escape_yara_string(family)}\"",
        f"        description = \"Common strings shared by {profile.get('analyzed_count', 0)} analyzed samples\"",
        f"        author = \"{_escape_yara_string(author or 'yarGen GUI')}\"",
        f"        date = \"{today}\"",
        f"        reference = \"{_escape_yara_string(reference or '')}\"",
        f"        license = \"{_escape_yara_string(license_text or '')}\"",
        f"        min_coverage = \"{profile.get('min_coverage_ratio', 0):.2f}\"",
        "    strings:",
    ]
    if not features:
        lines.append("        $placeholder = \"no_common_feature_found_review_samples\" ascii")
    for idx, feat in enumerate(features, 1):
        value = _escape_yara_string(str(feat.get("value", "")))
        lines.append(
            f"        $s{idx:02d} = \"{value}\" ascii wide nocase // coverage={feat.get('coverage', 0):.2f} score={feat.get('score', 0)}"
        )
    lines += [
        "    condition:",
        f"        {needed} of ($s*)",
        "}",
        "",
    ]
    return "\n".join(lines)


def write_profile_reports(profile: dict, output_rule: str | Path, report_dir: str | Path | None = None, author: str = "", reference: str = "", license_text: str = "") -> tuple[Path, Path, Path]:
    output_rule = Path(output_rule)
    output_rule.parent.mkdir(parents=True, exist_ok=True)
    output_rule.write_text(render_yara_rule(profile, author, reference, license_text), encoding="utf-8")

    report_dir = Path(report_dir) if report_dir else output_rule.parent
    report_dir.mkdir(parents=True, exist_ok=True)
    csv_path = report_dir / f"{output_rule.stem}_common_features.csv"
    md_path = report_dir / f"{output_rule.stem}_common_features.md"

    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["value", "count", "coverage", "score", "examples"])
        writer.writeheader()
        for row in profile.get("features", []):
            writer.writerow(row)

    lines = [
        f"# Common family features: {profile.get('family_name')}",
        "",
        f"Sample folder: `{profile.get('sample_dir')}`",
        f"Files found: **{profile.get('sample_count')}**",
        f"Files analyzed: **{profile.get('analyzed_count')}**",
        f"Minimum coverage: **{profile.get('min_coverage_ratio'):.2f}** / min count **{profile.get('min_count')}**",
        f"Generated rule: `{output_rule}`",
        "",
        "| # | Coverage | Count | Score | Feature | Example files |",
        "|---:|---:|---:|---:|---|---|",
    ]
    for i, row in enumerate(profile.get("features", []), 1):
        value = str(row.get("value", "")).replace("|", "\\|")
        examples = str(row.get("examples", "")).replace("|", "\\|")
        lines.append(f"| {i} | {row.get('coverage', 0):.2f} | {row.get('count', 0)} | {row.get('score', 0)} | `{value}` | {examples} |")
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output_rule, csv_path, md_path


def append_rule_file(base_rule: str | Path, supplemental_rule: str | Path, merged_output: str | Path) -> Path:
    base_rule = Path(base_rule)
    supplemental_rule = Path(supplemental_rule)
    merged_output = Path(merged_output)
    merged_output.parent.mkdir(parents=True, exist_ok=True)
    chunks = []
    if base_rule.exists():
        chunks.append(base_rule.read_text(encoding="utf-8", errors="ignore"))
    if supplemental_rule.exists():
        chunks.append(supplemental_rule.read_text(encoding="utf-8", errors="ignore"))
    merged_output.write_text("\n\n".join(chunks).strip() + "\n", encoding="utf-8")
    return merged_output
