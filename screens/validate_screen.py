# -*- coding: utf-8 -*-
import shutil, subprocess
from pathlib import Path
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
from core.utils import path_row, normalize_path, open_path
from core.report_builder import export_test_csv, export_test_html

class ValidateScreen(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, style="App.TFrame")
        self.app = app
        self.build()

    def refresh_text(self): pass
    def on_mode_changed(self): pass
    def on_show(self): pass

    def build(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)
        ttk.Label(self, text=self.app.t("validate.title"), style="Title.TLabel").grid(row=0, column=0, sticky="w")
        box = ttk.Frame(self, style="Card.TFrame", padding=12)
        box.grid(row=1, column=0, sticky="ew", pady=8)
        box.columnconfigure(1, weight=1)
        s = self.app.state
        path_row(box, 0, "Rule file (.yar)", s.var_rule_to_test, self.app.root_dir, "file_open")
        path_row(box, 1, "Malware folder", s.var_test_malware_dir, self.app.root_dir, "folder")
        path_row(box, 2, "Goodware folder", s.var_test_goodware_dir, self.app.root_dir, "folder")
        path_row(box, 3, "Report folder", s.var_report_dir, self.app.root_dir, "folder")
        actions = ttk.Frame(box, style="Surface.TFrame")
        actions.grid(row=4, column=1, sticky="w", pady=8)
        ttk.Button(actions, text=self.app.t("validate.syntax"), command=lambda: self.validate_rule_file(Path(s.var_rule_to_test.get()), True)).pack(side="left", padx=4)
        ttk.Button(actions, text=self.app.t("validate.test_malware"), command=lambda: self.test_rule(False)).pack(side="left", padx=4)
        ttk.Button(actions, text=self.app.t("validate.test_goodware"), command=lambda: self.test_rule(True)).pack(side="left", padx=4)
        ttk.Button(actions, text=self.app.t("validate.export_csv"), command=self.export_csv).pack(side="left", padx=4)
        ttk.Button(actions, text=self.app.t("validate.export_html"), command=self.export_html).pack(side="left", padx=4)
        self.output = ScrolledText(self, wrap="word")
        self.output.grid(row=2, column=0, sticky="nsew")

    def log(self, txt):
        self.output.insert("end", txt)
        self.output.see("end")
        self.app.screens["monitor"].log(txt)

    def validate_rule_file(self, rule_path: Path, show_popup=True):
        rule_path = normalize_path(str(rule_path), self.app.root_dir)
        if not rule_path.exists():
            if show_popup: messagebox.showerror("Validate", f"Rule file not found: {rule_path}")
            return False
        try:
            import yara
            yara.compile(filepath=str(rule_path))
            self.log(f"[VALIDATE OK] {rule_path}\n")
            if show_popup: messagebox.showinfo("Validate", "Rule is valid.")
            return True
        except ImportError:
            yarac = shutil.which("yarac")
            if not yarac:
                if show_popup: messagebox.showwarning("Validate", "Install yara-python or yarac.")
                return False
            proc = subprocess.run([yarac, str(rule_path), str(rule_path) + ".compiled.tmp"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            ok = proc.returncode == 0
            if show_popup: messagebox.showinfo("Validate", "OK" if ok else proc.stdout)
            return ok
        except Exception as e:
            self.log(f"[VALIDATE ERROR] {e}\n")
            if show_popup: messagebox.showerror("Validate", str(e))
            return False

    def test_rule(self, scan_goodware=False):
        s = self.app.state
        self.output.delete("1.0", "end")
        try:
            import yara
            rule_path = normalize_path(s.var_rule_to_test.get(), self.app.root_dir)
            if not self.validate_rule_file(rule_path, show_popup=False):
                self.log("[STOP] Invalid YARA rule.\n"); return
            rules = yara.compile(filepath=str(rule_path))
            rows = []
            targets = [("malware", normalize_path(s.var_test_malware_dir.get(), self.app.root_dir))]
            if scan_goodware:
                targets.append(("goodware", normalize_path(s.var_test_goodware_dir.get(), self.app.root_dir)))
            for dataset, folder in targets:
                if not folder.exists(): continue
                for p in folder.rglob("*"):
                    if not p.is_file(): continue
                    try:
                        matches = rules.match(str(p), timeout=60)
                        for m in matches:
                            rows.append({"dataset": dataset, "file": str(p), "rule": getattr(m, "rule", str(m)), "is_false_positive": "yes" if dataset == "goodware" else "no", "notes": ""})
                    except Exception as e:
                        rows.append({"dataset": dataset, "file": str(p), "rule": "<scan_error>", "is_false_positive": "", "notes": str(e)})
            s.last_test_results = rows
            mal = sum(1 for r in rows if r["dataset"] == "malware" and r["rule"] != "<scan_error>")
            fp = sum(1 for r in rows if r["dataset"] == "goodware" and r["rule"] != "<scan_error>")
            self.log(f"Malware matches: {mal}\nGoodware false positives: {fp}\n\n")
            for r in rows[:1000]:
                self.log(f"[{r['dataset']}] {r['rule']} -> {r['file']} FP={r['is_false_positive']}\n")
            if fp:
                self.log("\n[WARNING] Potential false positive detected. Try increasing -z/-x or removing common strings.\n")
        except Exception as e:
            messagebox.showerror("Test", str(e))

    def export_csv(self):
        rows = self.app.state.last_test_results
        if not rows:
            messagebox.showwarning("No results", "No test results yet."); return
        path = normalize_path(self.app.state.var_report_dir.get(), self.app.root_dir) / "yara_test_report.csv"
        export_test_csv(rows, path); open_path(path.parent)

    def export_html(self):
        rows = self.app.state.last_test_results
        if not rows:
            messagebox.showwarning("No results", "No test results yet."); return
        path = normalize_path(self.app.state.var_report_dir.get(), self.app.root_dir) / "yara_test_report.html"
        export_test_html(rows, path); open_path(path)
