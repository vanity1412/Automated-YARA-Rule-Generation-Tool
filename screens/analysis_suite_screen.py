# -*- coding: utf-8 -*-
import threading
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
from core.utils import path_row, normalize_path, open_path
from core.quality_gate import analyze_quality_gate, export_quality_gate
from core.rule_doctor import analyze_rule_doctor, export_rule_doctor
from core.ioc_extractor import extract_iocs, export_ioc_reports
from core.mitre_mapper import map_mitre, export_mitre_reports
from core.analyst_report import generate_analyst_report
from core.family_passport import build_family_passport, export_family_passport

class AnalysisSuiteScreen(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, style="App.TFrame")
        self.app=app
        self.qg_result=None; self.rd_issues=[]; self.ioc_rows=[]; self.mitre_rows=[]; self.passport=None
        self.var_ioc_source=tk.StringVar(self, value=app.state.var_malware.get())
        self.var_mitre_source=tk.StringVar(self, value=app.state.var_output.get())
        self.var_passport_family=tk.StringVar(self, value=app.state.var_family_name.get())
        self.var_passport_samples=tk.StringVar(self, value=app.state.var_malware.get())
        self.var_passport_rule=tk.StringVar(self, value=app.state.var_output.get())
        self.var_include_rule=tk.BooleanVar(self, value=True)
        self.var_include_samples=tk.BooleanVar(self, value=True)
        self.var_include_logs=tk.BooleanVar(self, value=True)
        self.build()

    def refresh_text(self): pass
    def on_mode_changed(self): pass
    def on_show(self):
        # Pull current app paths when the suite is opened, without overwriting manual edits if user changed them.
        if not self.var_mitre_source.get(): self.var_mitre_source.set(self.app.state.var_output.get())
        if not self.var_ioc_source.get(): self.var_ioc_source.set(self.app.state.var_malware.get())

    def build(self):
        self.columnconfigure(0, weight=1); self.rowconfigure(1, weight=1)
        ttk.Label(self, text="Analysis Suite", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        self.nb=ttk.Notebook(self); self.nb.grid(row=1, column=0, sticky="nsew", pady=8)
        self._build_quality_gate(); self._build_rule_doctor(); self._build_ioc(); self._build_mitre(); self._build_analyst_report(); self._build_family_passport()

    def run_thread(self, label, func):
        def worker():
            try:
                self.log(f"[{label}] Running static analysis...\n")
                result=func()
                self.log(f"[{label}] Done.\n")
                return result
            except Exception as e:
                self.after(0, lambda: messagebox.showerror(label, str(e)))
                self.log(f"[{label} ERROR] {e}\n")
        threading.Thread(target=worker, daemon=True).start()

    def log(self, text):
        try:
            self.app.screens["monitor"].log(text)
        except Exception:
            pass

    def report_dir(self):
        return normalize_path(self.app.state.var_report_dir.get(), self.app.root_dir)

    def _tree_with_scroll(self, parent, columns, widths):
        frame=ttk.Frame(parent, style="Surface.TFrame"); frame.columnconfigure(0, weight=1); frame.rowconfigure(0, weight=1)
        tree=ttk.Treeview(frame, columns=columns, show="headings")
        for c,w in zip(columns,widths):
            tree.heading(c, text=c); tree.column(c, width=w, anchor="w")
        y=ttk.Scrollbar(frame, orient="vertical", command=tree.yview); x=ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        tree.grid(row=0,column=0,sticky="nsew"); y.grid(row=0,column=1,sticky="ns"); x.grid(row=1,column=0,sticky="ew")
        return frame, tree

    def _build_quality_gate(self):
        tab=ttk.Frame(self.nb, style="App.TFrame", padding=8); tab.columnconfigure(0, weight=1); tab.rowconfigure(2, weight=1); self.nb.add(tab, text="Quality Gate")
        box=ttk.Frame(tab, style="Card.TFrame", padding=10); box.grid(row=0,column=0,sticky="ew"); box.columnconfigure(1, weight=1)
        path_row(box,0,"YARA file", self.app.state.var_rule_to_test, self.app.root_dir, "file_open")
        path_row(box,1,"Report folder", self.app.state.var_report_dir, self.app.root_dir, "folder")
        actions=ttk.Frame(box, style="Surface.TFrame"); actions.grid(row=2,column=1,sticky="w",pady=6)
        ttk.Button(actions,text="Analyze Quality Gate",command=self.analyze_qg).pack(side="left",padx=3)
        ttk.Button(actions,text="Export Markdown",command=self.export_qg_md).pack(side="left",padx=3)
        ttk.Button(actions,text="Export CSV",command=self.export_qg_csv).pack(side="left",padx=3)
        ttk.Button(actions,text="Open Report Folder",command=lambda: open_path(self.report_dir())).pack(side="left",padx=3)
        self.qg_badge=ttk.Label(tab,text="Not analyzed",style="H1.TLabel"); self.qg_badge.grid(row=1,column=0,sticky="w",pady=8)
        frame,self.qg_tree=self._tree_with_scroll(tab,("criteria","status","value","comment"),(210,100,160,620)); frame.grid(row=2,column=0,sticky="nsew")
        self.qg_suggest=ScrolledText(tab,height=6,wrap="word"); self.qg_suggest.grid(row=3,column=0,sticky="ew",pady=6)

    def analyze_qg(self):
        def task():
            rule=normalize_path(self.app.state.var_rule_to_test.get() or self.app.state.var_output.get(), self.app.root_dir)
            res=analyze_quality_gate(rule, self.app.state.last_test_results, self.app.state.last_rule_score_rows)
            self.qg_result=res
            self.after(0, lambda: self._show_qg(res))
        self.run_thread("Quality Gate", task)

    def _show_qg(self,res):
        self.qg_badge.configure(text=f"QUALITY GATE: {res['status']}")
        for i in self.qg_tree.get_children(): self.qg_tree.delete(i)
        for r in res["criteria"]: self.qg_tree.insert("","end",values=(r["criteria"],r["status"],r["value"],r["comment"]))
        self.qg_suggest.delete("1.0","end"); self.qg_suggest.insert("end", "\n".join("- "+s for s in res.get("suggestions",[])) or "No suggestions.")

    def export_qg_md(self):
        if not self.qg_result: self.analyze_qg(); return
        export_quality_gate(self.qg_result, self.report_dir()); open_path(self.report_dir())
    def export_qg_csv(self): self.export_qg_md()

    def _build_rule_doctor(self):
        tab=ttk.Frame(self.nb, style="App.TFrame", padding=8); tab.columnconfigure(0, weight=1); tab.rowconfigure(1, weight=1); self.nb.add(tab, text="Rule Doctor")
        box=ttk.Frame(tab, style="Card.TFrame", padding=10); box.grid(row=0,column=0,sticky="ew"); box.columnconfigure(1, weight=1)
        path_row(box,0,"YARA file", self.app.state.var_rule_to_test, self.app.root_dir, "file_open")
        actions=ttk.Frame(box,style="Surface.TFrame"); actions.grid(row=1,column=1,sticky="w",pady=6)
        ttk.Button(actions,text="Analyze Rule Doctor",command=self.analyze_rd).pack(side="left",padx=3)
        ttk.Button(actions,text="Export Markdown",command=self.export_rd).pack(side="left",padx=3)
        ttk.Button(actions,text="Export CSV",command=self.export_rd).pack(side="left",padx=3)
        ttk.Button(actions,text="Open Report Folder",command=lambda: open_path(self.report_dir())).pack(side="left",padx=3)
        frame,self.rd_tree=self._tree_with_scroll(tab,("severity","rule","issue","evidence","suggestion"),(90,160,210,300,480)); frame.grid(row=1,column=0,sticky="nsew",pady=8)
        self.rd_detail=ScrolledText(tab,height=5,wrap="word"); self.rd_detail.grid(row=2,column=0,sticky="ew")
        self.rd_tree.bind("<<TreeviewSelect>>", self._rd_select)

    def analyze_rd(self):
        def task():
            rule=normalize_path(self.app.state.var_rule_to_test.get() or self.app.state.var_output.get(), self.app.root_dir)
            issues=analyze_rule_doctor(rule); self.rd_issues=issues
            self.after(0, lambda: self._show_rd(issues))
        self.run_thread("Rule Doctor", task)
    def _show_rd(self, issues):
        for i in self.rd_tree.get_children(): self.rd_tree.delete(i)
        for r in issues: self.rd_tree.insert("","end",values=(r["severity"],r["rule"],r["issue"],r["evidence"],r["suggestion"]))
        self.rd_detail.delete("1.0","end"); self.rd_detail.insert("end", f"Total issues: {len(issues)}")
    def _rd_select(self, _e=None):
        item=self.rd_tree.focus();
        if item:
            self.rd_detail.delete("1.0","end"); self.rd_detail.insert("end", "\n".join(str(x) for x in self.rd_tree.item(item,"values")))
    def export_rd(self):
        if not self.rd_issues: self.analyze_rd(); return
        export_rule_doctor(self.rd_issues, self.report_dir()); open_path(self.report_dir())

    def _build_ioc(self):
        tab=ttk.Frame(self.nb, style="App.TFrame", padding=8); tab.columnconfigure(0, weight=1); tab.rowconfigure(1, weight=1); self.nb.add(tab, text="IOC Extractor")
        box=ttk.Frame(tab, style="Card.TFrame", padding=10); box.grid(row=0,column=0,sticky="ew"); box.columnconfigure(1, weight=1)
        path_row(box,0,"File or folder", self.var_ioc_source, self.app.root_dir, "file_open")
        checks=ttk.Frame(box,style="Surface.TFrame"); checks.grid(row=1,column=1,sticky="w")
        ttk.Checkbutton(checks,text="Include YARA rule",variable=self.var_include_rule).pack(side="left",padx=3)
        ttk.Checkbutton(checks,text="Include sample folder",variable=self.var_include_samples).pack(side="left",padx=3)
        ttk.Checkbutton(checks,text="Include logs/reports",variable=self.var_include_logs).pack(side="left",padx=3)
        actions=ttk.Frame(box,style="Surface.TFrame"); actions.grid(row=2,column=1,sticky="w",pady=6)
        ttk.Button(actions,text="Extract IOC",command=self.extract_ioc).pack(side="left",padx=3)
        ttk.Button(actions,text="Export CSV",command=self.export_ioc).pack(side="left",padx=3)
        ttk.Button(actions,text="Export Markdown",command=self.export_ioc).pack(side="left",padx=3)
        ttk.Button(actions,text="Copy selected IOC",command=self.copy_ioc).pack(side="left",padx=3)
        frame,self.ioc_tree=self._tree_with_scroll(tab,("type","value","source_file","confidence","note"),(120,360,360,90,260)); frame.grid(row=1,column=0,sticky="nsew",pady=8)

    def extract_ioc(self):
        def task():
            src=normalize_path(self.var_ioc_source.get(), self.app.root_dir)
            rows=extract_iocs(src,self.var_include_rule.get(),self.var_include_samples.get(),self.var_include_logs.get())
            self.ioc_rows=rows; self.after(0, lambda: self._show_ioc(rows))
        self.run_thread("IOC Extractor", task)
    def _show_ioc(self, rows):
        for i in self.ioc_tree.get_children(): self.ioc_tree.delete(i)
        for r in rows[:5000]: self.ioc_tree.insert("","end",values=(r["type"],r["value"],r["source_file"],r["confidence"],r["note"]))
    def export_ioc(self):
        if not self.ioc_rows: self.extract_ioc(); return
        export_ioc_reports(self.ioc_rows, self.report_dir()); open_path(self.report_dir())
    def copy_ioc(self):
        vals=[]
        for item in self.ioc_tree.selection():
            row=self.ioc_tree.item(item,"values")
            if row: vals.append(row[1])
        self.clipboard_clear(); self.clipboard_append("\n".join(vals))

    def _build_mitre(self):
        tab=ttk.Frame(self.nb, style="App.TFrame", padding=8); tab.columnconfigure(0, weight=1); tab.rowconfigure(2, weight=1); self.nb.add(tab, text="MITRE Mapping")
        box=ttk.Frame(tab, style="Card.TFrame", padding=10); box.grid(row=0,column=0,sticky="ew"); box.columnconfigure(1, weight=1)
        path_row(box,0,"Source file/folder", self.var_mitre_source, self.app.root_dir, "file_open")
        actions=ttk.Frame(box,style="Surface.TFrame"); actions.grid(row=1,column=1,sticky="w",pady=6)
        ttk.Button(actions,text="Analyze MITRE Mapping",command=self.analyze_mitre).pack(side="left",padx=3)
        ttk.Button(actions,text="Export Markdown",command=self.export_mitre).pack(side="left",padx=3)
        ttk.Button(actions,text="Export CSV",command=self.export_mitre).pack(side="left",padx=3)
        self.mitre_summary=ttk.Label(tab,text="MITRE mapping is heuristic and should be reviewed by analyst.",style="Muted.TLabel"); self.mitre_summary.grid(row=1,column=0,sticky="w",pady=4)
        frame,self.mitre_tree=self._tree_with_scroll(tab,("indicator","technique_id","technique_name","tactic","evidence","confidence"),(200,110,240,160,340,90)); frame.grid(row=2,column=0,sticky="nsew")

    def analyze_mitre(self):
        def task():
            src=normalize_path(self.var_mitre_source.get(), self.app.root_dir)
            rows=map_mitre(src, self.ioc_rows); self.mitre_rows=rows
            self.after(0, lambda: self._show_mitre(rows))
        self.run_thread("MITRE Mapping", task)
    def _show_mitre(self, rows):
        for i in self.mitre_tree.get_children(): self.mitre_tree.delete(i)
        for r in rows: self.mitre_tree.insert("","end",values=(r["indicator"],r["technique_id"],r["technique_name"],r["tactic"],r["evidence"],r["confidence"]))
        self.mitre_summary.configure(text=f"MITRE mapping is heuristic and should be reviewed by analyst. Total: {len(rows)}")
    def export_mitre(self):
        if not self.mitre_rows: self.analyze_mitre(); return
        export_mitre_reports(self.mitre_rows, self.report_dir()); open_path(self.report_dir())

    def _build_analyst_report(self):
        tab=ttk.Frame(self.nb, style="App.TFrame", padding=8); tab.columnconfigure(0, weight=1); tab.rowconfigure(1, weight=1); self.nb.add(tab, text="Analyst Report")
        actions=ttk.Frame(tab, style="Card.TFrame", padding=10); actions.grid(row=0,column=0,sticky="ew")
        ttk.Button(actions,text="Generate Markdown Report",command=self.generate_report).pack(side="left",padx=3)
        ttk.Button(actions,text="Generate HTML Report",command=self.generate_report).pack(side="left",padx=3)
        ttk.Button(actions,text="Open Report Folder",command=lambda: open_path(self.report_dir())).pack(side="left",padx=3)
        self.report_preview=ScrolledText(tab,wrap="word"); self.report_preview.grid(row=1,column=0,sticky="nsew",pady=8)
        self.report_preview.insert("end","Click Generate Markdown Report / HTML Report to build final report.\n")
    def generate_report(self):
        def task():
            md, html, preview=generate_analyst_report(self.app.state, self.app.root_dir, self.report_dir())
            self.after(0, lambda: (self.report_preview.delete("1.0","end"), self.report_preview.insert("end", preview), open_path(self.report_dir())))
        self.run_thread("Analyst Report", task)

    def _build_family_passport(self):
        tab=ttk.Frame(self.nb, style="App.TFrame", padding=8); tab.columnconfigure(0, weight=1); tab.rowconfigure(2, weight=1); self.nb.add(tab, text="Family Passport")
        box=ttk.Frame(tab, style="Card.TFrame", padding=10); box.grid(row=0,column=0,sticky="ew"); box.columnconfigure(1, weight=1)
        path_row(box,0,"Family name", self.var_passport_family, self.app.root_dir)
        path_row(box,1,"Sample folder", self.var_passport_samples, self.app.root_dir, "folder")
        path_row(box,2,"YARA rule", self.var_passport_rule, self.app.root_dir, "file_open")
        actions=ttk.Frame(box,style="Surface.TFrame"); actions.grid(row=3,column=1,sticky="w",pady=6)
        ttk.Button(actions,text="Build Family Passport",command=self.build_passport).pack(side="left",padx=3)
        ttk.Button(actions,text="Export Markdown",command=self.export_passport).pack(side="left",padx=3)
        ttk.Button(actions,text="Export HTML",command=self.export_passport).pack(side="left",padx=3)
        self.passport_cards=ttk.Label(tab,text="No passport yet.",style="H1.TLabel"); self.passport_cards.grid(row=1,column=0,sticky="ew",pady=8)
        frame,self.passport_tree=self._tree_with_scroll(tab,("type","value","count"),(180,760,120)); frame.grid(row=2,column=0,sticky="nsew")
    def build_passport(self):
        def task():
            res=build_family_passport(self.var_passport_family.get(), normalize_path(self.var_passport_samples.get(), self.app.root_dir), normalize_path(self.var_passport_rule.get(), self.app.root_dir), self.app.state.last_test_results, self.report_dir())
            self.passport=res; self.after(0, lambda: self._show_passport(res))
        self.run_thread("Family Passport", task)
    def _show_passport(self,res):
        ss=res["sample_summary"]; best=res.get("best_rule") or {}
        max_score=max(best.get("scores",[0])) if best.get("scores") else "not available"
        self.passport_cards.configure(text=f"Family: {res['family_name']} | Samples: {ss['total']} | Best Rule: {best.get('name','not available')} | Max Score: {max_score} | FP: {res['fp_count']} | Status: {res['quality_status']}")
        for i in self.passport_tree.get_children(): self.passport_tree.delete(i)
        for s,c in ss.get("top_strings",[])[:20]: self.passport_tree.insert("","end",values=("Top string",s,c))
        for s,c in ss.get("top_suspicious",[])[:20]: self.passport_tree.insert("","end",values=("Suspicious string",s,c))
        for r in res.get("iocs",[])[:50]: self.passport_tree.insert("","end",values=(r.get("type"),r.get("value"),""))
    def export_passport(self):
        if not self.passport: self.build_passport(); return
        export_family_passport(self.passport, self.report_dir()); open_path(self.report_dir())
