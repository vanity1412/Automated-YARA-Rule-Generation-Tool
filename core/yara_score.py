# -*- coding: utf-8 -*-
import re
from pathlib import Path

def extract_rule_blocks(text: str):
    blocks = []
    current_name = None
    current_lines = []
    brace_depth = 0
    in_rule = False
    rule_re = re.compile(r"^\s*(?:global\s+)?(?:private\s+)?rule\s+([A-Za-z_][A-Za-z0-9_]*)\b")
    for line in text.splitlines():
        if not in_rule:
            m = rule_re.search(line)
            if m:
                in_rule = True
                current_name = m.group(1)
                current_lines = [line]
                brace_depth = line.count("{") - line.count("}")
            continue
        current_lines.append(line)
        brace_depth += line.count("{") - line.count("}")
        if brace_depth <= 0 and "}" in line:
            blocks.append((current_name or "unknown_rule", "\n".join(current_lines)))
            current_name = None
            current_lines = []
            in_rule = False
            brace_depth = 0
    return blocks

def short_rule_name(name: str, max_len: int = 46):
    return name if len(name) <= max_len else name[:max_len - 3] + "..."

def confidence_from_score(max_score):
    if max_score is None: return "Không đủ dữ liệu"
    if max_score > 35: return "Rất cao"
    if max_score > 25: return "Cao"
    if max_score > 10: return "Trung bình"
    return "Thấp"

def parse_rule_score_report(path: Path):
    data = path.read_text(encoding="utf-8", errors="replace")
    rows = []
    for idx, (name, block) in enumerate(extract_rule_blocks(data), start=1):
        string_lines = re.findall(r"(?m)^\s*\$[A-Za-z0-9_]+\s*=", block)
        scores = []
        for raw in re.findall(r"score:\s*'(-?\d+(?:\.\d+)?)'", block, flags=re.I):
            try: scores.append(float(raw))
            except ValueError: pass
        max_score = max(scores) if scores else None
        min_score = min(scores) if scores else None
        avg_score = sum(scores) / len(scores) if scores else None
        hash_count = len(re.findall(r'(?m)^\s*hash\d+\s*=', block))
        rows.append({
            "stt": idx, "name": name, "short_name": short_rule_name(name),
            "string_count": len(string_lines), "score_count": len(scores),
            "max_score": max_score, "avg_score": avg_score, "min_score": min_score,
            "confidence": confidence_from_score(max_score),
            "high_score_count": sum(1 for s in scores if s > 25),
            "negative_score_count": sum(1 for s in scores if s < 0),
            "goodware_count": len(re.findall(r"Goodware String", block, flags=re.I)),
            "is_super": hash_count > 1,
        })
    return rows

def build_markdown(rows, path: Path):
    def fmt(v):
        if v is None: return "-"
        if isinstance(v, float): return f"{v:.2f}"
        return str(v)
    lines = ["# Báo cáo đánh giá điểm YARA rule", "", f"File: `{path}`", ""]
    if not rows:
        return "\n".join(lines + ["Không tìm thấy rule nào trong file."])
    lines += [
        "## 1. Bảng tổng hợp", "",
        "| STT | Tên Rule | Số lượng chuỗi | Số chuỗi có score | Score cao nhất | Score trung bình | Score thấp nhất | Đánh giá độ tin cậy |",
        "|---:|---|---:|---:|---:|---:|---:|---|",
    ]
    for r in rows:
        lines.append(f"| {r['stt']} | `{r['short_name']}` | {r['string_count']} | {r['score_count']} | {fmt(r['max_score'])} | {fmt(r['avg_score'])} | {fmt(r['min_score'])} | {r['confidence']} |")
    scored = [r for r in rows if r.get("max_score") is not None]
    chart_max = max([float(r["max_score"]) for r in scored], default=1.0)
    lines += ["", "## 2. Biểu đồ thanh - Score cao nhất", "", "```text"]
    for r in sorted(rows, key=lambda x: float(x["max_score"]) if x.get("max_score") is not None else -999, reverse=True):
        if r.get("max_score") is None:
            lines.append(f"{str(r['short_name'])[:42]:42} | no score")
        else:
            val = float(r["max_score"])
            bar = "█" * max(1, int((val / chart_max) * 36))
            lines.append(f"{str(r['short_name'])[:42]:42} | {bar} {val:.2f}")
    lines.append("```")
    lines += ["", "## 3. Nhận xét", ""]
    if not scored:
        return "\n".join(lines + ["- Không có score. Hãy bật `--score` khi generate rule."])
    best = max(scored, key=lambda r: float(r["max_score"]))
    stable = max(scored, key=lambda r: float(r["avg_score"]) if r.get("avg_score") is not None else -999)
    lines.append(f"- Rule có khả năng phát hiện chính xác nhất theo Max Score là `{best['name']}` với **{float(best['max_score']):.2f}**.")
    lines.append(f"- Rule ổn định hơn theo Avg Score là `{stable['name']}` với **{float(stable['avg_score']):.2f}**.")
    super_rules = [r for r in rows if r.get("is_super")]
    if super_rules:
        lines.append(f"- Có {len(super_rules)} Super Rule, phù hợp mục tiêu tìm đặc trưng chung của family.")
    lines.append("- Khuyến nghị: giữ rule có Max/Avg Score cao, test lại trên goodware, chỉnh các string score thấp/âm.")
    return "\n".join(lines)
