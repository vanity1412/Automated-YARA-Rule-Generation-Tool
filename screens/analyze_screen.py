# -*- coding: utf-8 -*-
from __future__ import annotations

from pathlib import Path
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText

from core.utils import path_row, normalize_path, open_path, browse
from core.yara_engine import YaraEngine
from core.sample_analyzer import (
    analyze_file,
    discover_rule_files,
    render_markdown_report,
    render_quick_rule,
)


class AnalyzeScreen(ttk.Frame):
    """Main workflow: upload one malware sample and automatically assess it.

    This screen is the user-facing triage flow.  Validate & Test remains a later
    workflow for checking the quality of a generated .yar rule against malware
    and cleanware sets.
    """

    def __init__(self, parent, app):
        super().__init__(parent, style="App.TFrame")
        self.app = app
        self.build()

    def refresh_text(self):
        pass

    def on_mode_changed(self):
        pass

    def on_show(self):
        self._write_intro_once()

    def build(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)
        ttk.Label(self, text=self.app.t("analyze.title"), style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            self,
            text="Upload 1 malware sample -> static analysis -> YARA scan -> risk assessment -> suggested rule/report. Static only, sample is not executed.",
            style="AppMuted.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(2, 8))

        box = ttk.Frame(self, style="Card.TFrame", padding=12)
        box.grid(row=2, column=0, sticky="ew", pady=6)
        box.columnconfigure(1, weight=1)
        path_row(box, 0, "Malware sample file", self.app.state.var_analyze_sample_file, self.app.root_dir, "file_open")
        path_row(box, 1, "YARA rules file/folder (optional)", self.app.state.var_analyze_rule_source, self.app.root_dir, "file_open")
        ttk.Button(box, text="Browse folder", command=lambda: browse(self.app.state.var_analyze_rule_source, "folder", self.app.root_dir)).grid(row=1, column=3, sticky="ew", pady=4, padx=(4,0))
        path_row(box, 2, "Quick rule output", self.app.state.var_analyze_rule_output, self.app.root_dir, "file_save_yar")
        path_row(box, 3, "Report folder", self.app.state.var_analyze_report_dir, self.app.root_dir, "folder")

        actions = ttk.Frame(box, style="Surface.TFrame")
        actions.grid(row=4, column=1, sticky="w", pady=(8, 0))
        ttk.Button(actions, text="1. Analyze uploaded malware", style="Primary.TButton", command=self.analyze).pack(side="left", padx=4)
        ttk.Button(actions, text="2. Save suggested YARA rule", command=self.save_rule).pack(side="left", padx=4)
        ttk.Button(actions, text="3. Export assessment report", command=self.export_report).pack(side="left", padx=4)
        ttk.Button(actions, text="Open report folder", command=self.open_report_folder).pack(side="left", padx=4)

        panes = ttk.Panedwindow(self, orient="horizontal")
        panes.grid(row=3, column=0, sticky="nsew", pady=(8, 0))

        left = ttk.Frame(panes, style="Card.TFrame", padding=10)
        left.columnconfigure(0, weight=1)
        left.rowconfigure(1, weight=1)
        ttk.Label(left, text="Assessment summary", style="H2.TLabel").grid(row=0, column=0, sticky="w")
        self.summary_tree = ttk.Treeview(left, columns=("key", "value"), show="headings", height=14)
        self.summary_tree.heading("key", text="Item")
        self.summary_tree.heading("value", text="Value")
        self.summary_tree.column("key", width=160, anchor="w")
        self.summary_tree.column("value", width=420, anchor="w")
        self.summary_tree.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        panes.add(left, weight=1)

        right = ttk.Frame(panes, style="Card.TFrame", padding=10)
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)
        ttk.Label(right, text="Detailed analysis log", style="H2.TLabel").grid(row=0, column=0, sticky="w")
        self.log = ScrolledText(right, height=22, wrap="word", font=("Consolas", 10), bg="#1e1e1e", fg="#ffffff")
        self.log.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        
        # Configure color tags for different types of information
        self.log.tag_configure("header", foreground="#00d4ff", font=("Consolas", 11, "bold"))
        self.log.tag_configure("success", foreground="#00ff88", font=("Consolas", 10, "bold"))
        self.log.tag_configure("warning", foreground="#ffaa00", font=("Consolas", 10, "bold"))
        self.log.tag_configure("error", foreground="#ff4444", font=("Consolas", 10, "bold"))
        self.log.tag_configure("info", foreground="#88ccff", font=("Consolas", 10))
        self.log.tag_configure("highlight", foreground="#ff88ff", font=("Consolas", 10, "bold"))
        self.log.tag_configure("match", foreground="#00ff00", font=("Consolas", 10, "bold"))
        self.log.tag_configure("suspicious", foreground="#ff6666", font=("Consolas", 10))
        self.log.tag_configure("hash", foreground="#cccccc", font=("Consolas", 9))
        self.log.tag_configure("score", foreground="#ffff00", font=("Consolas", 10, "bold"))
        
        panes.add(right, weight=2)

    def _write_intro_once(self):
        if getattr(self, "_intro_written", False):
            return
        self._intro_written = True
        self.clear_log()
        self.log_line("=== ANALYZE MALWARE SAMPLE ===")
        self.log_line("Purpose: upload one malware file and let the app assess it automatically.")
        self.log_line("YARA role: match the sample against existing .yar rules if you select a rule file/folder.")
        self.log_line("Note: Validate & Test is only for testing rule quality after a rule has been generated.")

    def clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def log_line(self, text=""):
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def set_summary(self, profile: dict):
        for item in self.summary_tree.get_children():
            self.summary_tree.delete(item)
        h = profile.get("hashes", {})
        a = profile.get("assessment", {})
        rows = [
            ("File", profile.get("name", "")),
            ("Type", profile.get("file_type", "")),
            ("Size", f"{profile.get('size', 0)} bytes"),
            ("Entropy", str(profile.get("entropy", ""))),
            ("MD5", h.get("md5", "")),
            ("SHA1", h.get("sha1", "")),
            ("SHA256", h.get("sha256", "")),
            ("YARA matches", str(len(profile.get("yara_matches", [])))),
            ("Suspicious strings", str(len(profile.get("suspicious_strings", [])))),
            ("Suspicious imports", str(len(profile.get("suspicious_imports", [])))),
            ("Risk score", f"{a.get('score', 0)}/100"),
            ("Assessment", a.get("label", "")),
        ]
        for k, v in rows:
            self.summary_tree.insert("", "end", values=(k, v))

    def _selected_rule_files(self):
        source = normalize_path(self.app.state.var_analyze_rule_source.get(), self.app.root_dir)
        return discover_rule_files(source)

    def analyze(self):
        sample = normalize_path(self.app.state.var_analyze_sample_file.get(), self.app.root_dir)
        if not sample.exists() or not sample.is_file():
            messagebox.showerror("Missing sample", "Please choose one malware sample file first.")
            return

        self.clear_log()
        self.log_line("=== 1) UPLOADED MALWARE SAMPLE ===")
        self.log_line(f"Sample: {sample}")
        self.log_line("Mode: static analysis only. The sample is NOT executed.")

        engine = YaraEngine(self.app.root_dir, prefer_yara_x=False, prefer_cli=True)
        rule_files = self._selected_rule_files()
        if rule_files:
            self.log_line("\n=== 2) YARA ENGINE / RULE SCAN ===")
            self.log_line(f"Rules discovered: {len(rule_files)}")
            self.log_line(f"Engine: {engine.backend} - {engine.detail}")
            if engine.is_official_yara_cli:
                self.log_line("[OFFICIAL CLI] Directly using VirusTotal/YARA executable.")
            elif not engine.available():
                self.log_line("[WARNING] No YARA engine available. Static analysis continues without rule matching.")
        else:
            self.log_line("\n=== 2) YARA ENGINE / RULE SCAN ===")
            self.log_line("No .yar/.yara rule file selected. App will perform static assessment only.")

        try:
            profile = analyze_file(sample, rule_files=rule_files, engine=engine)
        except Exception as exc:
            messagebox.showerror("Analyze failed", str(exc))
            self.log_line(f"[ERROR] {exc}")
            return

        self.app.state.last_sample_analysis = profile
        self.set_summary(profile)
        self._render_profile_log(profile)
        self.app.state.var_analyze_rule_output.set(str(Path(self.app.state.var_analyze_rule_output.get() or self.app.root_dir / 'rules' / 'sample_auto_triage.yar')))
        messagebox.showinfo("Analysis completed", f"Assessment: {profile.get('assessment',{}).get('label')}\nScore: {profile.get('assessment',{}).get('score')}/100")

    def _render_profile_log(self, profile: dict):
        h = profile.get("hashes", {})
        a = profile.get("assessment", {})
        self.log_line("\n=== 3) FILE FINGERPRINT ===")
        self.log_line(f"Name   : {profile.get('name')}")
        self.log_line(f"Type   : {profile.get('file_type')}")
        self.log_line(f"Size   : {profile.get('size')} bytes")
        self.log_line(f"Entropy: {profile.get('entropy')}")
        self.log_line(f"MD5    : {h.get('md5')}")
        self.log_line(f"SHA1   : {h.get('sha1')}")
        self.log_line(f"SHA256 : {h.get('sha256')}")

        self.log_line("\n=== 4) YARA MATCH RESULT ===")
        matches = profile.get("yara_matches", [])
        if matches:
            for m in matches:
                self.log_line(f"[MATCH] {m.get('rule')}  <-  {m.get('rule_file')}")
        else:
            self.log_line("[NO MATCH] No selected YARA rule matched this sample.")
        for e in profile.get("yara_errors", [])[:10]:
            self.log_line(f"[YARA ERROR] {e.get('rule_file')}: {e.get('error')}")

        self.log_line("\n=== 5) STATIC INDICATORS ===")
        self.log_line(f"Printable strings extracted: {profile.get('strings_count')}")
        susp = profile.get("suspicious_strings", [])
        if susp:
            self.log_line("Suspicious strings:")
            for row in susp[:20]:
                val = str(row.get("value", ""))[:180]
                self.log_line(f"  - score={row.get('score'):>3} reason={row.get('reason')}: {val}")
        else:
            self.log_line("No strong suspicious string indicators found.")

        imports = profile.get("suspicious_imports", [])
        if imports:
            self.log_line("Suspicious PE imports/APIs:")
            for imp in imports[:30]:
                self.log_line(f"  - {imp}")
        else:
            self.log_line("No suspicious PE imports found or file is not a PE.")

        sections = profile.get("pe", {}).get("sections", [])
        if sections:
            self.log_line("PE sections:")
            for sec in sections[:20]:
                marker = " HIGH" if sec.get("entropy", 0) >= 7.2 else ""
                self.log_line(f"  - {sec.get('name')}: raw={sec.get('raw_size')} virtual={sec.get('virtual_size')} entropy={sec.get('entropy')}{marker}")

        self.log_line("\n=== 6) AUTOMATIC ASSESSMENT ===")
        self.log_line(f"Score: {a.get('score', 0)}/100")
        self.log_line(f"Label: {a.get('label', '')}")
        reasons = a.get("reasons", [])
        if reasons:
            self.log_line("Reasons:")
            for r in reasons:
                self.log_line(f"  - {r}")
        else:
            self.log_line("No strong static reason found. Review manually if the file is known malware.")

        self.log_line("\n=== 7) NEXT STEP ===")
        self.log_line("Click 'Save suggested YARA rule' to create a quick .yar rule from this sample.")
        self.log_line("For your thesis topic, use Generate Family Rule with multiple same-family samples to build a stronger family signature.")
        self.log_line("Then use Validate & Test Rule to check malware detection and goodware false positives.")

    def _profile_or_warn(self):
        profile = getattr(self.app.state, "last_sample_analysis", None)
        if not profile:
            messagebox.showwarning("No analysis", "Run Analyze uploaded malware first.")
            return None
        return profile

    def save_rule(self):
        profile = self._profile_or_warn()
        if not profile:
            return
        out = normalize_path(self.app.state.var_analyze_rule_output.get(), self.app.root_dir)
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(render_quick_rule(profile), encoding="utf-8")
            self.app.state.var_rule_to_test.set(str(out))
            self.log_line(f"\n[SAVED] Suggested quick YARA rule: {out}")
            self.log_line("[INFO] Rule path copied to Validate & Test screen.")
            messagebox.showinfo("Rule saved", f"Saved suggested rule:\n{out}\n\nOpen Validate & Test to test it against malware/goodware folders.")
        except Exception as exc:
            messagebox.showerror("Save failed", str(exc))

    def export_report(self):
        profile = self._profile_or_warn()
        if not profile:
            return
        report_dir = normalize_path(self.app.state.var_analyze_report_dir.get(), self.app.root_dir)
        try:
            report_dir.mkdir(parents=True, exist_ok=True)
            stem = Path(profile.get("path", "sample")).stem
            md = report_dir / f"{stem}_assessment.md"
            md.write_text(render_markdown_report(profile), encoding="utf-8")
            self.log_line(f"\n[REPORT] Markdown report saved: {md}")
            messagebox.showinfo("Report exported", str(md))
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))

    def open_report_folder(self):
        path = normalize_path(self.app.state.var_analyze_report_dir.get(), self.app.root_dir)
        open_path(path)
