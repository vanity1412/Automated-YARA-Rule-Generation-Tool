# -*- coding: utf-8 -*-
from pathlib import Path
from .analysis_common import parse_yara_summary, validate_yara_syntax, test_result_counts, write_csv, markdown_table

def _fmt(v):
    if v is None: return "not available"
    if isinstance(v, float): return f"{v:.2f}"
    return str(v)

def analyze_quality_gate(rule_path, test_results=None, score_rows=None):
    p=Path(rule_path)
    rows=[]; suggestions=[]; fail=0; warn=0
    syntax_ok, syntax_msg = validate_yara_syntax(p)
    summary = parse_yara_summary(p) if p.exists() else {"rule_count":0,"string_count":0,"score_count":0,"max_score":None,"avg_score":None,"min_score":None,"negative_score_count":0,"goodware_count":0,"super_rule_count":0,"loose_conditions":[],"rules":[]}
    tc=test_result_counts(test_results or [])
    def add(criteria, status, value, comment):
        nonlocal fail, warn
        rows.append({"criteria":criteria,"status":status,"value":_fmt(value),"comment":comment})
        if status == "FAIL": fail += 1
        elif status == "WARNING": warn += 1
    add("YARA syntax", "PASS" if syntax_ok else "FAIL", syntax_msg, "Full validation if yara-python/yarac is available.")
    add("At least 1 rule", "PASS" if summary["rule_count"] > 0 else "FAIL", summary["rule_count"], "Rule file must contain at least one YARA rule.")
    add("String count", "PASS" if summary["string_count"] >= 3 else "WARNING", summary["string_count"], "Prefer at least 3 meaningful strings.")
    add("Has score", "PASS" if summary["score_count"] else "WARNING", summary["score_count"], "Enable --score when generating rules." if not summary["score_count"] else "Score metadata found.")
    max_score=summary.get("max_score")
    if max_score is None: ms_status="WARNING"
    elif max_score > 25: ms_status="PASS"
    elif max_score > 10: ms_status="WARNING"
    else: ms_status="FAIL"
    add("Max Score", ms_status, max_score, "Max Score > 25 is preferred unless Super Rule is present.")
    add("Avg Score", "PASS" if (summary.get("avg_score") or 0) > 10 else "WARNING", summary.get("avg_score"), "Average score is an indicator, not a guarantee.")
    add("Min Score", "WARNING" if summary.get("min_score") is None or summary.get("min_score") < 0 else "PASS", summary.get("min_score"), "Negative scores can indicate goodware/generic strings.")
    add("Negative scores", "WARNING" if summary["negative_score_count"] else "PASS", summary["negative_score_count"], "Review negative-score strings." if summary["negative_score_count"] else "No negative score found.")
    add("Goodware String", "WARNING" if summary["goodware_count"] else "PASS", summary["goodware_count"], "Remove or tighten goodware strings." if summary["goodware_count"] else "No Goodware String marker found.")
    add("Super Rule", "PASS" if summary["super_rule_count"] else "WARNING", summary["super_rule_count"], "Super Rule is useful for family detection.")
    loose=len(summary["loose_conditions"])
    add("Loose condition", "FAIL" if loose and summary["string_count"] < 5 else "WARNING" if loose else "PASS", ", ".join(summary["loose_conditions"]) or "none", "Avoid 'any of them' / '1 of them' for final family rules.")
    if tc["has_test"]:
        add("Malware match rate", "PASS" if tc["malware_matches"] else "FAIL", tc["malware_matches"], "At least one malware match is expected after testing.")
        fp=tc["goodware_fp"]
        add("Goodware false positives", "FAIL" if fp > 3 else "WARNING" if fp > 0 else "PASS", fp, "Goodware FP should be zero for a demo-quality rule.")
    else:
        add("Malware match rate", "WARNING", "test data unavailable", "Run malware test for stronger confidence.")
        add("Goodware false positives", "WARNING", "test data unavailable", "Run goodware test to check false positives.")
    if not syntax_ok: suggestions.append("Fix YARA syntax before any quality decision.")
    if summary["rule_count"] == 0: suggestions.append("Generate or select a file with at least one YARA rule.")
    if not summary["score_count"]: suggestions.append("Regenerate with --score to get Max/Avg/Min Score.")
    if summary["negative_score_count"] or summary["goodware_count"]: suggestions.append("Review strings with negative score or Goodware String markers and remove generic strings.")
    if loose: suggestions.append("Tighten condition, for example '3 of them' or '2 of ($x*)'.")
    if not tc["has_test"]: suggestions.append("Run malware and goodware tests before final demo.")
    if fail: status="FAIL"
    elif warn: status="WARNING"
    else: status="PASS"
    if syntax_ok and summary["rule_count"] and tc.get("goodware_fp",0)==0 and ((max_score is not None and max_score > 25) or summary["super_rule_count"]) and not any(r["status"]=="FAIL" for r in rows):
        status = "PASS" if warn <= 2 else status
    return {"status":status,"criteria":rows,"suggestions":suggestions,"summary":summary}

def export_quality_gate(result, report_dir):
    report_dir=Path(report_dir); report_dir.mkdir(parents=True, exist_ok=True)
    csv_path=report_dir/"quality_gate_report.csv"; md_path=report_dir/"quality_gate_report.md"
    write_csv(csv_path, result["criteria"], ["criteria","status","value","comment"])
    lines=["# Quality Gate Report", "", f"Status: **{result['status']}**", "", markdown_table(["Criteria","Status","Value","Comment"], [[r['criteria'],r['status'],r['value'],r['comment']] for r in result['criteria']]), "", "## Suggestions"]
    lines += [f"- {s}" for s in (result.get("suggestions") or ["No critical suggestion."])]
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return md_path, csv_path
