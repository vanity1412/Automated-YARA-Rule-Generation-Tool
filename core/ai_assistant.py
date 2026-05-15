# -*- coding: utf-8 -*-
"""Deterministic local AI-style assistant for yarGen GUI.

No online LLM is required. The assistant gives grounded answers from:
- local yarGen goodware DB files
- selected YARA rule file
- selected sample folder
- latest rule score report
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Dict, Iterable, List

from core.db_knowledge import GoodwareDBKnowledge
from core.yara_score import parse_rule_score_report, build_markdown

ASCII_RE = re.compile(rb"[\x20-\x7e]{5,}")
IOC_PATTERNS = {
    "url": re.compile(r"https?://[A-Za-z0-9./_:%?=&+\-]+", re.I),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|info|biz|ru|cn|top|xyz|site|online|io|me)\b", re.I),
    "registry": re.compile(r"\bHK(?:CU|LM|CR|U|CC)\\[^\s\"']+", re.I),
    "windows_path": re.compile(r"[A-Za-z]:\\[^\r\n\"']+"),
    "pipe": re.compile(r"\\\\\.\\pipe\\[^\s\"']+", re.I),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
}

SUSPICIOUS_KEYWORDS = {
    "powershell": "Execution / command scripting",
    "cmd.exe": "Execution / command shell",
    "wscript.shell": "Script execution",
    "startup": "Persistence",
    "runonce": "Persistence",
    "currentversion\\run": "Persistence",
    "reflectiveloader": "Reflective loading / evasion",
    "chrome": "Credential/browser artifact",
    "firefox": "Credential/browser artifact",
    "password": "Credential access",
    "wallet": "Credential/financial target",
    "keylog": "Credential access / collection",
    "\\.\\pipe\\": "Named pipe / IPC",
    "user-agent": "Network/C2 indicator",
    "http://": "Network indicator",
    "https://": "Network indicator",
}

GENERIC_STRINGS = {
    "this program cannot be run in dos mode",
    "kernel32.dll",
    "getprocaddress",
    "loadlibrarya",
    "virtualalloc",
    "mscoree.dll",
    "system.drawing",
    "publickeytoken",
    "v4.0.30319",
}


class LocalAIAssistant:
    def __init__(self, db: GoodwareDBKnowledge) -> None:
        self.db = db

    def answer(self, question: str, rule_path: Path | None = None, sample_dir: Path | None = None) -> str:
        q = (question or "").strip().lower()
        if not q:
            return self.help_text()
        if any(k in q for k in ["db", "database", "goodware", "44", "nặng"]):
            return self.explain_db()
        if any(k in q for k in ["rule", "yara", "score", "false positive", "fp"]):
            if rule_path and rule_path.exists():
                return self.explain_rule(rule_path)
            return "Bạn chưa chọn file YARA rule hợp lệ. Hãy chọn rule ở ô Rule file rồi bấm lại."
        if any(k in q for k in ["sample", "malware", "hash", "ioc", "folder"]):
            if sample_dir and sample_dir.exists():
                return self.analyze_samples(sample_dir)
            return "Bạn chưa chọn sample folder hợp lệ."
        if any(k in q for k in ["preset", "tham số", "generate", "chạy nhanh", "lag", "slow"]):
            return self.explain_presets_and_performance()
        if any(k in q for k in ["mitre", "attack", "hành vi", "behavior"]):
            if rule_path and rule_path.exists():
                return self.mitre_mapping_from_rule(rule_path)
            if sample_dir and sample_dir.exists():
                return self.mitre_mapping_from_samples(sample_dir)
            return "Cần chọn rule hoặc sample folder để gợi ý MITRE ATT&CK."
        return self.help_text()

    def help_text(self) -> str:
        return (
            "AI Assistant local có thể trả lời dựa trên dữ liệu trong app, không bịa nguồn ngoài.\n\n"
            "Bạn có thể hỏi:\n"
            "- DB của tôi có đủ không? Vì sao 44 DB chạy lâu?\n"
            "- Phân tích rule hiện tại có tốt không?\n"
            "- Rule nào dễ false positive?\n"
            "- Sample folder có những hash/IOC nào?\n"
            "- Nên dùng preset nào để demo nhanh?\n"
            "- Gợi ý MITRE từ rule/sample.\n\n"
            "Độ chính xác phụ thuộc vào file rule, sample folder và dbs/ local mà bạn chọn."
        )

    def explain_db(self) -> str:
        return (
            "PHÂN TÍCH GOODWARE DB LOCAL\n"
            "================================\n"
            f"{self.db.explain_db_coverage()}\n\n"
            "Khuyến nghị sử dụng:\n"
            "- Demo nhanh: dùng Fast no-opcodes DB hoặc chỉ strings/exports/imphashes.\n"
            "- Rule cuối: dùng Full quality DB để giảm false positive.\n"
            "- Không upload DB lên GitHub: thêm dbs/ và *.db vào .gitignore.\n"
            "- DB opcodes thường nặng nhất, chỉ bật --opcodes khi thật sự cần phân tích PE sâu."
        )

    def explain_presets_and_performance(self) -> str:
        return (
            "GỢI Ý PRESET VÀ HIỆU NĂNG\n"
            "==========================\n"
            "1. Demo nhanh trên lớp:\n"
            "   - DB Mode: Fast no-opcodes DB\n"
            "   - Không bật --opcodes\n"
            "   - Bật --score để có Rule Score Report\n\n"
            "2. Tạo rule chất lượng hơn:\n"
            "   - DB Mode: Full quality DB\n"
            "   - Bật --score, --strings\n"
            "   - Test lại goodware để kiểm false positive\n\n"
            "3. Khi yarGen sinh 0 rule:\n"
            "   - Dùng Loose Debug để kiểm tra\n"
            "   - Giảm -z hoặc -x\n"
            "   - Tăng -s nếu string dài\n"
            "   - Kiểm tra sample có bị pack/encrypt hoặc đang là archive chưa giải nén không\n\n"
            "Lưu ý: DB 44 file lớn không phải lỗi. Nó giúp yarGen lọc goodware tốt hơn nhưng làm thời gian load lâu."
        )

    def explain_rule(self, rule_path: Path) -> str:
        try:
            rows = parse_rule_score_report(rule_path)
            md = build_markdown(rows, rule_path)
        except Exception as exc:
            return f"Không phân tích được rule: {exc}"
        text = rule_path.read_text(encoding="utf-8", errors="replace")
        issues = self.rule_doctor(text)
        mitre = self.mitre_mapping_from_text(text)
        return (
            "PHÂN TÍCH YARA RULE LOCAL\n"
            "==========================\n"
            f"Nguồn: {rule_path}\n\n"
            f"{md}\n\n"
            "RULE DOCTOR\n"
            "-----------\n"
            + "\n".join(f"- {x}" for x in issues)
            + "\n\nMITRE/BEHAVIOR GỢI Ý\n--------------------\n"
            + ("\n".join(f"- {x}" for x in mitre) if mitre else "- Chưa thấy indicator hành vi rõ trong rule.")
        )

    def rule_doctor(self, yara_text: str) -> List[str]:
        issues: List[str] = []
        low = yara_text.lower()
        if "condition:" not in low:
            issues.append("Không thấy phần condition. Rule có thể chưa hoàn chỉnh.")
        if re.search(r"condition:\s*any\s+of\s+them", low):
            issues.append("Condition 'any of them' khá lỏng, dễ false positive. Nên cân nhắc '2 of them', '3 of them' hoặc nhóm $x.")
        if "score:" not in low:
            issues.append("Không thấy score. Hãy bật --score khi generate để đánh giá rule tốt hơn.")
        for s in GENERIC_STRINGS:
            if s in low:
                issues.append(f"Có string phổ biến '{s}', cần review vì dễ match goodware.")
        if "goodware string" in low:
            issues.append("Rule có comment Goodware String. Nên kiểm false positive trên goodware folder.")
        string_count = len(re.findall(r"(?m)^\s*\$[A-Za-z0-9_]+\s*=", yara_text))
        if string_count < 3:
            issues.append("Rule có ít hơn 3 strings, có thể quá yếu hoặc quá file-specific.")
        elif string_count > 80:
            issues.append("Rule có rất nhiều strings, nên xem lại để tránh rule khó bảo trì.")
        if not issues:
            issues.append("Chưa phát hiện vấn đề rõ ràng. Vẫn nên validate và test trên goodware.")
        return issues

    def mitre_mapping_from_text(self, text: str) -> List[str]:
        low = text.lower()
        hits = []
        for key, meaning in SUSPICIOUS_KEYWORDS.items():
            if key in low:
                hits.append(f"'{key}' → {meaning}")
        return hits[:30]

    def mitre_mapping_from_rule(self, rule_path: Path) -> str:
        try:
            text = rule_path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            return f"Không đọc được rule: {exc}"
        hits = self.mitre_mapping_from_text(text)
        if not hits:
            return "Chưa thấy indicator hành vi rõ trong rule. Hãy bật --strings hoặc kiểm tra strings_out."
        return "MITRE/BEHAVIOR GỢI Ý TỪ RULE\n============================\n" + "\n".join(f"- {x}" for x in hits)

    def extract_ascii_strings(self, path: Path, limit_bytes: int = 4 * 1024 * 1024) -> List[str]:
        try:
            data = path.read_bytes()[:limit_bytes]
        except Exception:
            return []
        out = []
        for m in ASCII_RE.finditer(data):
            s = m.group(0).decode("ascii", errors="ignore")
            if len(s) >= 5:
                out.append(s[:300])
            if len(out) >= 1000:
                break
        return out

    def analyze_samples(self, folder: Path) -> str:
        files = [p for p in folder.rglob("*") if p.is_file()]
        if not files:
            return f"Không có file trong sample folder: {folder}"
        lines = ["PHÂN TÍCH SAMPLE FOLDER", "=======================", f"Folder: {folder}", f"Tổng file: {len(files)}", ""]
        ioc_counts: Dict[str, set] = {k: set() for k in IOC_PATTERNS}
        suspicious_hits: Dict[str, int] = {}
        for p in files[:50]:
            try:
                data = p.read_bytes()
                md5 = hashlib.md5(data).hexdigest()
                sha256 = hashlib.sha256(data).hexdigest()
                head = data[:4]
                ftype = "PE/MZ" if head.startswith(b"MZ") else "ELF" if head.startswith(b"\x7fELF") else p.suffix.lower() or "unknown"
                lines.append(f"- {p.name}: type={ftype}, size={len(data)} bytes, md5={md5}, sha256={sha256}")
                strings = "\n".join(self.extract_ascii_strings(p))
                low = strings.lower()
                for k, pattern in IOC_PATTERNS.items():
                    for match in pattern.findall(strings):
                        ioc_counts[k].add(str(match)[:250])
                for key in SUSPICIOUS_KEYWORDS:
                    if key in low:
                        suspicious_hits[key] = suspicious_hits.get(key, 0) + 1
            except Exception as exc:
                lines.append(f"- {p.name}: lỗi đọc file: {exc}")
        lines.append("")
        lines.append("IOC rút trích:")
        for k, vals in ioc_counts.items():
            if vals:
                lines.append(f"- {k}: {len(vals)} giá trị")
                for v in sorted(vals)[:10]:
                    lines.append(f"  + {v}")
        if not any(ioc_counts.values()):
            lines.append("- Chưa phát hiện IOC rõ bằng regex cơ bản.")
        lines.append("")
        lines.append("Keyword hành vi đáng chú ý:")
        if suspicious_hits:
            for k, c in sorted(suspicious_hits.items(), key=lambda x: (-x[1], x[0])):
                lines.append(f"- {k}: xuất hiện trong {c} file → {SUSPICIOUS_KEYWORDS[k]}")
        else:
            lines.append("- Chưa thấy keyword hành vi rõ trong phần strings đọc được.")
        return "\n".join(lines)

    def mitre_mapping_from_samples(self, folder: Path) -> str:
        return self.analyze_samples(folder)

    def lookup_strings_report(self, values: Iterable[str], max_part: int | None = None, include_opcodes: bool = False, progress_callback=None) -> str:
        groups = ["strings", "exports", "imphashes"]
        if include_opcodes:
            groups.append("opcodes")
        hits = self.db.lookup_values(values, groups=groups, max_part=max_part, progress_callback=progress_callback)
        lines = ["TRA GOODWARE DB LOCAL", "====================", f"Groups: {', '.join(groups)}", f"Max part: {max_part or 'all'}", ""]
        for v, files in hits.items():
            lines.append(f"- {v}")
            lines.append(f"  Hits: {len(files)}")
            if files:
                lines.append(f"  DB files: {', '.join(files[:20])}")
            lines.append(f"  Đánh giá: {self.db.estimate_value_risk(v, files)}")
        return "\n".join(lines)
