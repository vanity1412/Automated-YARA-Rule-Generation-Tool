# -*- coding: utf-8 -*-
import csv
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
from core.utils import path_row, normalize_path, open_path
from core.yara_score import parse_rule_score_report, build_markdown

class ReportsScreen(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, style="App.TFrame")
        self.app = app
        self.build()

    def refresh_text(self): pass
    def on_mode_changed(self): pass
    def on_show(self): pass

    def build(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)
        ttk.Label(self, text=self.app.t("reports.title"), style="Title.TLabel").grid(row=0, column=0, sticky="w")
        box = ttk.Frame(self, style="Card.TFrame", padding=12)
        box.grid(row=1, column=0, sticky="ew", pady=8)
        box.columnconfigure(1, weight=1)
        path_row(box, 0, "YARA file", self.app.state.var_rule_score_file, self.app.root_dir, "file_open")
        actions = ttk.Frame(box)
        actions.grid(row=1, column=1, sticky="w", pady=6)
        ttk.Button(actions, text=self.app.t("reports.analyze_scores"), command=self.analyze_rule_scores).pack(side="left", padx=4)
        ttk.Button(actions, text=self.app.t("reports.export_md"), command=self.export_markdown).pack(side="left", padx=4)
        ttk.Button(actions, text=self.app.t("reports.export_csv"), command=self.export_csv).pack(side="left", padx=4)
        chart_box = ttk.LabelFrame(self, text="Max Score Chart", padding=8)
        chart_box.grid(row=2, column=0, sticky="ew")
        chart_box.columnconfigure(0, weight=1)
        self.canvas = tk.Canvas(chart_box, height=280, background="#ffffff", highlightthickness=1, highlightbackground="#cccccc")
        self.canvas.grid(row=0, column=0, sticky="ew")
        self.report = ScrolledText(self, wrap="word", font=("Consolas", 9))
        self.report.grid(row=3, column=0, sticky="nsew", pady=8)
        self.report.insert("end", "Generate with --score, then click Analyze Rule Scores.\n")

    def analyze_rule_scores(self):
        path = normalize_path(self.app.state.var_rule_score_file.get() or self.app.state.var_output.get(), self.app.root_dir)
        try:
            rows = parse_rule_score_report(path)
            markdown = build_markdown(rows, path)
            self.app.state.last_rule_score_rows = rows
            self.app.state.last_rule_score_markdown = markdown
            self.report.delete("1.0", "end"); self.report.insert("end", markdown)
            self.draw_chart(rows)
            self.app.screens["monitor"].log(f"[SCORE REPORT] Parsed {len(rows)} rules from {path}\n")
        except Exception as e:
            messagebox.showerror("Rule Score Report", str(e))

    def draw_chart(self, rows):
        c = self.canvas; c.delete("all")
        width = max(760, c.winfo_width() or 900)
        c.create_text(12, 12, anchor="nw", text="Max Score by YARA Rule", font=("Segoe UI", 12, "bold"))
        scored = [r for r in rows if r.get("max_score") is not None]
        if not scored:
            c.create_text(12, 50, anchor="nw", text="No score found. Enable --score when generating rules."); return
        top = sorted(scored, key=lambda r: float(r["max_score"]), reverse=True)[:10]
        max_score = max(float(r["max_score"]) for r in top) or 1.0
        left, top_y, bar_h, gap = 230, 48, 18, 8
        for i, r in enumerate(top):
            y = top_y + i * (bar_h + gap)
            val = float(r["max_score"]); conf = str(r["confidence"])
            color = "#22c55e" if conf == "Rất cao" else "#3b82f6" if conf == "Cao" else "#f59e0b" if conf == "Trung bình" else "#ef4444"
            c.create_text(12, y + bar_h/2, anchor="w", text=str(r["short_name"])[:30])
            bw = int((width - left - 80) * val / max_score)
            c.create_rectangle(left, y, left+bw, y+bar_h, fill=color, outline="")
            c.create_text(left+bw+8, y+bar_h/2, anchor="w", text=f"{val:.2f} ({conf})")

    def export_markdown(self):
        if not self.app.state.last_rule_score_markdown: self.analyze_rule_scores()
        out = normalize_path(self.app.state.var_report_dir.get(), self.app.root_dir)
        out.mkdir(parents=True, exist_ok=True)
        path = out / "yara_rule_score_report.md"
        path.write_text(self.app.state.last_rule_score_markdown, encoding="utf-8")
        open_path(path.parent)

    def export_csv(self):
        rows = self.app.state.last_rule_score_rows
        if not rows:
            self.analyze_rule_scores()
            rows = self.app.state.last_rule_score_rows
        if not rows: return
        out = normalize_path(self.app.state.var_report_dir.get(), self.app.root_dir)
        out.mkdir(parents=True, exist_ok=True)
        path = out / "yara_rule_score_report.csv"
        fields = ["stt","name","string_count","score_count","max_score","avg_score","min_score","confidence","high_score_count","negative_score_count","goodware_count","is_super"]
        with path.open("w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields); writer.writeheader()
            for r in rows: writer.writerow({k: r.get(k, "") for k in fields})
        open_path(path.parent)
