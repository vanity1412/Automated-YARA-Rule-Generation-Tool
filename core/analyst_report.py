# -*- coding: utf-8 -*-
from collections import Counter
from datetime import datetime
from pathlib import Path
from .analysis_common import parse_yara_summary, validate_yara_syntax, markdown_table, simple_html, file_kind, hash_file, ARCHIVE_EXTS, SCRIPT_EXTS
from .quality_gate import analyze_quality_gate
from .rule_doctor import analyze_rule_doctor
from .ioc_extractor import extract_iocs
from .mitre_mapper import map_mitre
from .family_passport import sample_summary

def generate_analyst_report(state, root_dir, report_dir):
    report_dir=Path(report_dir); report_dir.mkdir(parents=True, exist_ok=True)
    sample_folder=Path(state.var_malware.get() or state.var_analyzer_dir.get())
    rule_path=Path(state.var_output.get() or state.var_rule_to_test.get())
    ss=sample_summary(sample_folder)
    rule=parse_yara_summary(rule_path) if rule_path.exists() else {"rule_count":0,"string_count":0,"max_score":None,"avg_score":None,"min_score":None,"negative_score_count":0,"goodware_count":0,"super_rule_count":0,"rules":[]}
    syntax_ok, syntax_msg=validate_yara_syntax(rule_path) if rule_path.exists() else (False, "rule file not found")
    tests=state.last_test_results or []
    malware_matches=sum(1 for r in tests if str(r.get("dataset","")).lower()=="malware")
    goodware_fp=sum(1 for r in tests if str(r.get("dataset","")).lower()=="goodware")
    qg=analyze_quality_gate(rule_path, tests) if rule_path.exists() else {"status":"WARNING","criteria":[],"suggestions":["Rule file not available."]}
    issues=analyze_rule_doctor(rule_path) if rule_path.exists() else []
    issue_counts=Counter(i.get("severity") for i in issues)
    iocs=extract_iocs(sample_folder, False, True, False)[:500]
    if rule_path.exists(): iocs += extract_iocs(rule_path, True, False, True)[:200]
    ioc_counts=Counter(r.get("type") for r in iocs)
    mitre=map_mitre(str(sample_folder), iocs)[:200]
    techniques=[]; seen=set()
    for m in mitre:
        key=m.get("technique_id")
        if key not in seen:
            seen.add(key); techniques.append(m)
    best=None
    for r in rule.get("rules",[]):
        if r.get("scores") and (best is None or max(r["scores"]) > max(best["scores"])): best=r
    def val(v):
        return "not available" if v is None else v
    lines=["# Final Malware Family Analyst Report", "", "## 1. General Information", f"- App name: yarGen GUI - Malware Family YARA Builder", f"- Created: {datetime.now().isoformat(timespec='seconds')}", f"- Working directory: `{root_dir}`", f"- Malware family name: {state.var_family_name.get() or 'not available'}", f"- Author: {state.var_author.get() or 'not available'}", "", "## 2. Input", f"- Sample folder: `{sample_folder}`", f"- Output YARA file: `{rule_path}`", f"- Goodware folder: `{state.var_goodware_dir.get() or state.var_test_goodware_dir.get() or 'not available'}`", f"- DB mode: {state.var_db_mode.get()}", f"- Preset: {state.var_current_preset.get()}", f"- Last yarGen command: `{' '.join(state.last_command) if state.last_command else state.var_command_preview.get() or 'not available'}`", "", "## 3. Sample Summary", f"- Total files: {ss['total']}", f"- PE / Script / Archive: {ss['pe']} / {ss['scripts']} / {ss['archives']}", f"- Total size: {ss['total_size']} bytes", markdown_table(["File","Size","Type","MD5","SHA256"], [[Path(r['file']).name,r['size'],r['type'],r['md5'],r['sha256']] for r in ss['files'][:50]]), "", "## 4. YARA Rule Summary", f"- Rule count: {rule['rule_count']}", f"- String count: {rule['string_count']}", f"- Super rule count: {rule.get('super_rule_count',0)}", f"- Max / Avg / Min Score: {val(rule.get('max_score'))} / {val(rule.get('avg_score'))} / {val(rule.get('min_score'))}", f"- Negative score count: {rule.get('negative_score_count',0)}", f"- Goodware String count: {rule.get('goodware_count',0)}", "", "## 5. Validate/Test Summary", f"- Syntax: {'OK' if syntax_ok else 'ERROR'} ({syntax_msg})", f"- Malware matches: {malware_matches if tests else 'test data unavailable'}", f"- Goodware false positives: {goodware_fp if tests else 'test data unavailable'}", "", "## 6. Quality Gate Summary", f"- Status: **{qg['status']}**", markdown_table(["Criteria","Status","Value","Comment"], [[r.get('criteria'),r.get('status'),r.get('value'),r.get('comment')] for r in qg.get('criteria',[])[:20]]), "", "## 7. Rule Doctor Summary", f"- Total issues: {len(issues)}", f"- HIGH/WARNING/INFO: {issue_counts.get('HIGH',0)} / {issue_counts.get('WARNING',0)} / {issue_counts.get('INFO',0)}", markdown_table(["Severity","Rule","Issue","Evidence","Suggestion"], [[i.get('severity'),i.get('rule'),i.get('issue'),i.get('evidence'),i.get('suggestion')] for i in issues[:20]]), "", "## 8. IOC Summary", f"- Total IOC: {len(iocs)}", markdown_table(["Type","Count"], [[k,v] for k,v in ioc_counts.most_common()]), "", "## 9. MITRE Mapping Summary", "MITRE mapping is heuristic and should be reviewed by analyst.", markdown_table(["Technique ID","Technique Name","Tactic","Evidence","Confidence"], [[m.get('technique_id'),m.get('technique_name'),m.get('tactic'),m.get('evidence'),m.get('confidence')] for m in techniques[:30]]), "", "## 10. Family Passport Summary", f"- Family profile: {state.var_family_name.get() or 'not available'}", f"- Best rule: {best.get('name') if best else 'not available'}", f"- FP status: {goodware_fp if tests else 'not available'}", f"- Quality status: {qg['status']}", "", "## 11. Analyst Conclusion", "Rule is demo-ready." if qg['status']=='PASS' else "Rule needs review/tuning before final use.", "", "## 12. Appendix", f"- Command yarGen: `{' '.join(state.last_command) if state.last_command else 'not available'}`", f"- Report folder: `{report_dir}`", "- Safety note: only static analysis is performed; malware samples are not executed."]
    md_path=report_dir/"final_malware_family_report.md"; html_path=report_dir/"final_malware_family_report.html"
    md_path.write_text("\n".join(lines), encoding="utf-8")
    badge=qg['status']
    html_body=f"<h1>Final Malware Family Analyst Report</h1><div class='card'><span class='badge {badge}'>{badge}</span><p>MITRE mapping is heuristic and should be reviewed by analyst.</p></div><pre>{md_path.read_text(encoding='utf-8')}</pre>"
    html_path.write_text(simple_html("Final Malware Family Analyst Report", html_body), encoding="utf-8")
    return md_path, html_path, "\n".join(lines)
