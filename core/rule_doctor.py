# -*- coding: utf-8 -*-
import re
from pathlib import Path
from .analysis_common import parse_yara_summary, COMMON_GENERIC, write_csv, markdown_table

META_FIELDS = ["author", "description", "date", "reference", "family"]

def analyze_rule_doctor(rule_path):
    p=Path(rule_path); issues=[]
    if not p.exists():
        return [{"severity":"HIGH","rule":"-","issue":"Rule file not found","evidence":str(p),"suggestion":"Select an existing .yar/.yara file."}]
    summary=parse_yara_summary(p)
    if not summary["score_count"]:
        issues.append({"severity":"INFO","rule":"all","issue":"No score metadata","evidence":"No score: markers found","suggestion":"Regenerate with --score to support quality review."})
    if not summary["super_rule_count"]:
        issues.append({"severity":"INFO","rule":"all","issue":"No Super Rule","evidence":"No super/hash aggregation marker found","suggestion":"For family detection, prefer a Super Rule or a stricter multi-string condition."})
    for r in summary["rules"]:
        name=r["name"]; block=r["block"]; lower=block.lower()
        meta_block = re.search(r"meta\s*:(.*?)(?:strings\s*:|condition\s*:)", block, re.I|re.S)
        meta_text = meta_block.group(1).lower() if meta_block else ""
        missing=[m for m in META_FIELDS if not re.search(r"\b"+re.escape(m)+r"\s*=", meta_text)]
        if missing:
            issues.append({"severity":"WARNING","rule":name,"issue":"Missing meta fields","evidence":", ".join(missing),"suggestion":"Add author, description, date, reference and family metadata when available."})
        if r["string_count"] < 3:
            issues.append({"severity":"HIGH","rule":name,"issue":"Too few strings","evidence":str(r["string_count"]),"suggestion":"Use at least 3 meaningful family strings or tighten the condition."})
        for g in COMMON_GENERIC:
            if g.lower() in lower:
                issues.append({"severity":"WARNING","rule":name,"issue":"Generic / FP-prone string","evidence":g,"suggestion":"Remove it or require it only with stronger family-specific strings."})
        if r["scores"] and any(s < 0 for s in r["scores"]):
            issues.append({"severity":"WARNING","rule":name,"issue":"Negative score string","evidence":str([s for s in r["scores"] if s < 0][:5]),"suggestion":"Review negative-score strings, often linked to goodware/generic features."})
        if r["goodware_count"]:
            issues.append({"severity":"WARNING","rule":name,"issue":"Goodware String marker","evidence":str(r["goodware_count"]),"suggestion":"Avoid Goodware String indicators in final malware family rule."})
        if r["loose"]:
            issues.append({"severity":"HIGH","rule":name,"issue":"Condition too loose","evidence":"condition uses any of them or 1 of them","suggestion":"Change to '3 of them' or '2 of ($x*)' depending on string groups."})
        path_hits=re.findall(r"[A-Z]:\\[^\"']+|/home/[^\"']+|/tmp/[^\"']+", block, re.I)
        demo_hits=re.findall(r"demo|test|sample", block, re.I)
        hash_hits=re.findall(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b", block)
        if path_hits or len(hash_hits) > 3 or demo_hits:
            issues.append({"severity":"WARNING","rule":name,"issue":"Rule may be file-specific","evidence":", ".join((path_hits+demo_hits+hash_hits)[:5]),"suggestion":"Prefer family-wide strings over local paths, sample labels or many fixed hashes."})
        if r["generic_count"] >= 4:
            issues.append({"severity":"WARNING","rule":name,"issue":"Too many generic strings","evidence":str(r["generic_count"]),"suggestion":"Keep only generic strings that are combined with stronger family-specific evidence."})
    return issues

def export_rule_doctor(issues, report_dir):
    report_dir=Path(report_dir); report_dir.mkdir(parents=True, exist_ok=True)
    csv_path=report_dir/"rule_doctor_report.csv"; md_path=report_dir/"rule_doctor_report.md"
    fields=["severity","rule","issue","evidence","suggestion"]
    write_csv(csv_path, issues, fields)
    lines=["# Rule Doctor Report", "", f"Total issues: {len(issues)}", "", markdown_table(["Severity","Rule","Issue","Evidence","Suggestion"], [[i.get('severity'),i.get('rule'),i.get('issue'),i.get('evidence'),i.get('suggestion')] for i in issues])]
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return md_path, csv_path
