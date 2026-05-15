# -*- coding: utf-8 -*-
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from .analysis_common import file_kind, hash_file, printable_strings, parse_yara_summary, markdown_table, simple_html, ARCHIVE_EXTS, SCRIPT_EXTS
from .ioc_extractor import extract_iocs
from .quality_gate import analyze_quality_gate

SUSPICIOUS_TOKENS = ["powershell","cmd.exe","wscript","cscript","schtasks","rundll32","regsvr32","VirtualAlloc","WriteProcessMemory","CreateRemoteThread","AppData","Temp","ProgramData","RunOnce","CurrentVersion\\Run"]

def sample_summary(folder):
    p=Path(folder); files=[x for x in p.rglob("*") if x.is_file()] if p.exists() else []
    pe=scripts=archives=total=0; rows=[]; strings=Counter(); susp=Counter()
    for f in files[:2000]:
        try: size=f.stat().st_size
        except Exception: size=0
        total += size; kind=file_kind(f)
        if kind == "PE": pe += 1
        if f.suffix.lower() in SCRIPT_EXTS: scripts += 1
        if f.suffix.lower() in ARCHIVE_EXTS or kind == "archive": archives += 1
        md5, sha256=hash_file(f)
        rows.append({"file":str(f),"size":size,"type":kind,"md5":md5,"sha256":sha256})
        for s in printable_strings(f)[:3000]:
            ss=s.strip()
            if 5 <= len(ss) <= 120:
                strings[ss] += 1
            if any(t.lower() in ss.lower() for t in SUSPICIOUS_TOKENS):
                susp[ss[:160]] += 1
    return {"total":len(files),"pe":pe,"scripts":scripts,"archives":archives,"total_size":total,"avg_size":(total/len(files) if files else 0),"files":rows,"top_strings":strings.most_common(20),"top_suspicious":susp.most_common(20)}

def suggest_preset(summary, iocs):
    if summary["scripts"] > summary["pe"]: return "Script Malware"
    if summary["archives"] and summary["total"] == summary["archives"]: return "Fast Scan after extracting archives"
    types={r.get("type") for r in iocs}
    if "URL" in types or "Domain" in types: return "PE Deep" if summary["pe"] else "Script Malware"
    if summary["pe"] >= 2: return "PE Deep"
    return "Fast Scan"

def build_family_passport(family_name, sample_folder, rule_path, test_results=None, report_dir="reports"):
    ss=sample_summary(sample_folder)
    rule=parse_yara_summary(rule_path) if rule_path and Path(rule_path).exists() else {"rules":[],"max_score":None,"avg_score":None,"goodware_count":0,"rule_count":0}
    iocs=extract_iocs(sample_folder, include_rules=False, include_samples=True, include_logs=False)[:200]
    qg=analyze_quality_gate(rule_path, test_results or []) if rule_path and Path(rule_path).exists() else {"status":"WARNING"}
    scored=[r for r in rule.get("rules",[]) if r.get("scores")]
    best=max(scored, key=lambda r:max(r["scores"]), default=None)
    fp=sum(1 for r in (test_results or []) if str(r.get("dataset","")).lower()=="goodware")
    common_by_type=defaultdict(list)
    for r in iocs:
        if len(common_by_type[r["type"]]) < 8: common_by_type[r["type"]].append(r["value"])
    preset=suggest_preset(ss, iocs)
    conclusion = "Rule is suitable for demo after analyst review." if qg.get("status")=="PASS" and fp==0 else "More validation/tuning is recommended before final use."
    result={"family_name":family_name or "not available","sample_folder":str(sample_folder),"sample_summary":ss,"rule_summary":rule,"iocs":iocs,"common_ioc":dict(common_by_type),"best_rule":best,"quality_status":qg.get("status"),"fp_count":fp,"suggested_preset":preset,"conclusion":conclusion,"created_at":datetime.now().isoformat(timespec="seconds")}
    export_family_passport(result, report_dir)
    return result

def export_family_passport(result, report_dir):
    report_dir=Path(report_dir); report_dir.mkdir(parents=True, exist_ok=True)
    md_path=report_dir/"family_passport.md"; html_path=report_dir/"family_passport.html"
    best=result.get("best_rule") or {}
    ss=result["sample_summary"]
    ioc_lines=[]
    for k, vals in result.get("common_ioc",{}).items():
        ioc_lines.append(f"- **{k}**: " + ", ".join(f"`{v}`" for v in vals[:8]))
    md=["# Family Passport", "", f"Created: {result['created_at']}", "", "## Summary", f"- Family name: **{result['family_name']}**", f"- Sample folder: `{result['sample_folder']}`", f"- Total samples: {ss['total']}", f"- PE / Script / Archive: {ss['pe']} / {ss['scripts']} / {ss['archives']}", f"- Average file size: {ss['avg_size']:.2f} bytes", f"- Best rule: {best.get('name','not available')}", f"- Max Score: {max(best.get('scores',[0])) if best.get('scores') else 'not available'}", f"- Avg Score: {result['rule_summary'].get('avg_score') if result['rule_summary'].get('avg_score') is not None else 'not available'}", f"- Quality Gate: **{result['quality_status']}**", f"- Goodware FP count: {result['fp_count']}", f"- Suggested preset: {result['suggested_preset']}", "", "## Top repeated strings", markdown_table(["String","Count"], result['sample_summary']['top_strings'][:15]), "", "## Top suspicious strings", markdown_table(["String","Count"], result['sample_summary']['top_suspicious'][:15]), "", "## Common IOC"] + (ioc_lines or ["not available"]) + ["", "## Analyst conclusion", result['conclusion']]
    md_path.write_text("\n".join(md), encoding="utf-8")
    body=f"<h1>Family Passport</h1><div class='card'><span class='badge {result['quality_status']}'>{result['quality_status']}</span><p><b>Family:</b> {result['family_name']}</p><p><b>Samples:</b> {ss['total']} | <b>Best rule:</b> {best.get('name','not available')} | <b>FP:</b> {result['fp_count']}</p><p><b>Suggested preset:</b> {result['suggested_preset']}</p><p>{result['conclusion']}</p></div><pre>{md_path.read_text(encoding='utf-8')}</pre>"
    html_path.write_text(simple_html("Family Passport", body), encoding="utf-8")
    return md_path, html_path
