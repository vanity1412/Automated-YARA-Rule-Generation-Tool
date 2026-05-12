# -*- coding: utf-8 -*-
import re
from pathlib import Path
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from core.utils import open_path

class MonitorScreen(ttk.Frame):
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
        ttk.Label(self, text=self.app.t("monitor.title"), style="Title.TLabel").grid(row=0, column=0, sticky="w")
        dash = ttk.Frame(self, style="Card.TFrame", padding=12)
        dash.grid(row=1, column=0, sticky="ew", pady=8)
        dash.columnconfigure(1, weight=1)
        ttk.Label(dash, text="Stage:", style="Card.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(dash, textvariable=self.app.state.progress_stage, style="H2.TLabel").grid(row=0, column=1, sticky="w")
        ttk.Progressbar(dash, variable=self.app.state.progress_percent, maximum=100).grid(row=1, column=0, columnspan=2, sticky="ew", pady=6)
        ttk.Label(dash, textvariable=self.app.state.progress_detail, style="Muted.TLabel").grid(row=2, column=0, columnspan=2, sticky="w")
        self.stage_tree = ttk.Treeview(dash, columns=("stage","status","detail"), show="headings", height=6)
        for col, width in [("stage",260),("status",120),("detail",650)]:
            self.stage_tree.heading(col, text=col); self.stage_tree.column(col, width=width, anchor="w")
        self.stage_tree.grid(row=3, column=0, columnspan=2, sticky="ew", pady=8)

        actions = ttk.Frame(self, style="App.TFrame")
        actions.grid(row=2, column=0, sticky="ew")
        ttk.Button(actions, text=self.app.t("monitor.clear"), command=lambda: self.log_text.delete("1.0", "end")).pack(side="left", padx=4)
        ttk.Button(actions, text=self.app.t("monitor.open_rule"), command=lambda: open_path(Path(self.app.state.var_output.get()))).pack(side="left", padx=4)
        ttk.Button(actions, text=self.app.t("monitor.open_folder"), command=lambda: open_path(Path(self.app.state.var_output.get()).parent)).pack(side="left", padx=4)
        ttk.Button(actions, text="Validate output rule", command=lambda: self.app.screens["validate"].validate_rule_file(Path(self.app.state.var_output.get()), True)).pack(side="left", padx=4)
        ttk.Button(actions, text="Rule Score Report", command=self.open_rule_score_report).pack(side="left", padx=4)

        pane = ttk.Panedwindow(self, orient="horizontal")
        pane.grid(row=3, column=0, sticky="nsew", pady=8)
        left = ttk.Frame(pane); right = ttk.Frame(pane)
        left.columnconfigure(0, weight=1); left.rowconfigure(0, weight=1)
        right.columnconfigure(0, weight=1); right.rowconfigure(0, weight=1)
        pane.add(left, weight=3); pane.add(right, weight=2)
        self.log_text = ScrolledText(left, wrap="word", font=("Consolas", 9))
        self.log_text.grid(row=0, column=0, sticky="nsew")
        self.preview = ScrolledText(right, wrap="none", font=("Consolas", 9))
        self.preview.grid(row=0, column=0, sticky="nsew")
        self.summary = ttk.Label(self, text="YARA summary: no rule yet.", style="Muted.TLabel")
        self.summary.grid(row=4, column=0, sticky="w")
        self.reset_progress()

    def reset_progress(self):
        s = self.app.state
        s.progress_stage.set("Idle"); s.progress_percent.set(0); s.progress_detail.set("No process running.")
        s.progress_db_loaded = 0; s.progress_samples_done = 0; s.progress_simple_rules = 0; s.progress_super_rules = 0
        for item in self.stage_tree.get_children(): self.stage_tree.delete(item)
        for stage in [("1","Preflight","Waiting",""),("2","Load goodware DB","Waiting",""),("3","Extract strings/opcodes","Waiting",""),("4","Generate statistics","Waiting",""),("5","Generate simple/super rules","Waiting",""),("6","Validate/Test","Waiting","")]:
            self.stage_tree.insert("", "end", iid=stage[0], values=stage[1:])

    def set_stage(self, iid, status, detail=""):
        if self.stage_tree.exists(iid):
            vals = list(self.stage_tree.item(iid, "values"))
            self.stage_tree.item(iid, values=(vals[0], status, detail))

    def log(self, text):
        self.log_text.insert("end", text)
        try:
            lines = int(float(self.log_text.index("end-1c").split(".")[0]))
            limit = int(self.app.settings.get("log_retention_lines", 8000))
            if lines > limit:
                self.log_text.delete("1.0", "1200.0")
                self.log_text.insert("1.0", "[Log trimmed]\n")
        except Exception: pass
        self.log_text.see("end")

    def update_progress_from_log_line(self, line):
        s = self.app.state
        low = line.lower()
        if "reading goodware strings" in low:
            s.progress_stage.set("Load goodware DB"); s.progress_percent.set(max(s.progress_percent.get(), 5))
            self.set_stage("1", "Done", "Preflight OK"); self.set_stage("2", "Running", "Loading DB")
        if "[+] loading ./dbs/" in low or "[+] loading .\\dbs\\" in low:
            s.progress_db_loaded += 1
            s.progress_percent.set(max(s.progress_percent.get(), min(45, 8 + s.progress_db_loaded)))
            s.progress_detail.set(line.strip()); self.set_stage("2", "Running", f"{s.progress_db_loaded} DB files")
        if "[+] processing malware files" in low:
            s.progress_stage.set("Extract strings/opcodes"); s.progress_percent.set(max(s.progress_percent.get(), 50))
            self.set_stage("2", "Done", "DB loaded"); self.set_stage("3", "Running", "Processing samples")
        if "[+] processing " in low and "processing malware files" not in low and "pestudio" not in low:
            s.progress_samples_done += 1
            s.progress_percent.set(max(s.progress_percent.get(), min(70, 50 + s.progress_samples_done * 4)))
            s.progress_detail.set(f"Sample: {s.progress_samples_done}"); self.set_stage("3", "Running", f"{s.progress_samples_done} samples")
        if "generating statistical data" in low:
            s.progress_stage.set("Generate statistics"); s.progress_percent.set(max(s.progress_percent.get(), 74)); self.set_stage("4", "Running", "Calculating overlap/score")
        if "generating simple rules" in low or "generating super rules" in low:
            s.progress_stage.set("Generate rules"); s.progress_percent.set(max(s.progress_percent.get(), 86)); self.set_stage("5", "Running", "Creating rules")
        m = re.search(r"Generated\s+(\d+)\s+SIMPLE", line, re.I)
        if m: s.progress_simple_rules = int(m.group(1)); s.progress_percent.set(max(s.progress_percent.get(), 92))
        m = re.search(r"Generated\s+(\d+)\s+SUPER", line, re.I)
        if m:
            s.progress_super_rules = int(m.group(1)); s.progress_percent.set(max(s.progress_percent.get(), 96)); self.set_stage("5", "Done", f"{s.progress_simple_rules} simple, {s.progress_super_rules} super")
        if "[process exited]" in low:
            if "code=0" in low:
                s.progress_stage.set("Finished"); s.progress_percent.set(100); s.progress_detail.set(f"Done. Simple={s.progress_simple_rules}, Super={s.progress_super_rules}")
            else:
                s.progress_stage.set("Error"); s.progress_detail.set(line.strip())

    def preview_output_rule(self, silent=False):
        p = Path(self.app.state.var_output.get())
        self.preview.delete("1.0", "end")
        if p.exists(): self.preview.insert("end", p.read_text(encoding="utf-8", errors="replace")[:200000])
        elif not silent: self.log(f"[WARN] Rule file not found: {p}\n")

    def refresh_yara_summary(self):
        p = Path(self.app.state.var_output.get())
        if not p.exists(): return
        data = p.read_text(encoding="utf-8", errors="replace")
        rules = len(re.findall(r"(?m)^\s*(?:global\s+|private\s+)*rule\s+\w+", data))
        strings = len(re.findall(r"(?m)^\s*\$[A-Za-z0-9_]+\s*=", data))
        x_strings = len(re.findall(r"(?m)^\s*\$x\d+\s*=", data))
        s_strings = len(re.findall(r"(?m)^\s*\$s\d+\s*=", data))
        simple = rules; super_rules = 0
        if "/* Super Rules" in data:
            before, after = data.split("/* Super Rules", 1)
            simple = len(re.findall(r"(?m)^\s*(?:global\s+|private\s+)*rule\s+\w+", before))
            super_rules = len(re.findall(r"(?m)^\s*(?:global\s+|private\s+)*rule\s+\w+", after))
        self.summary.configure(text=f"YARA summary: rules={rules}, simple={simple}, super={super_rules}, strings={strings}, $x={x_strings}, $s={s_strings}")

    def open_rule_score_report(self):
        self.app.state.var_rule_score_file.set(self.app.state.var_output.get())
        self.app.show_screen("reports")
        self.app.screens["reports"].analyze_rule_scores()
