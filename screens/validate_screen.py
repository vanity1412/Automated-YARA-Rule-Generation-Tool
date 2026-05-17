# -*- coding: utf-8 -*-
from __future__ import annotations

from pathlib import Path
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText

from core.utils import path_row, normalize_path, open_path
from core.report_builder import export_test_csv, export_test_html
from core.yara_engine import YaraEngine


class ValidateScreen(ttk.Frame):
    """Validate and test YARA rules with clear, human-readable scan output."""

    def __init__(self, parent, app):
        super().__init__(parent, style="App.TFrame")
        self.app = app
        self.build()

    def refresh_text(self):
        pass

    def on_mode_changed(self):
        pass

    def on_show(self):
        pass

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------
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
        path_row(box, 2, "Goodware folder (clean files only)", s.var_test_goodware_dir, self.app.root_dir, "folder")
        path_row(box, 3, "Report folder", s.var_report_dir, self.app.root_dir, "folder")

        actions = ttk.Frame(box, style="Surface.TFrame")
        actions.grid(row=4, column=1, sticky="w", pady=8)
        ttk.Button(actions, text="1. Check YARA CLI", command=self.detect_engine).pack(side="left", padx=4)
        ttk.Button(actions, text="2. Validate rule", command=lambda: self.validate_rule_file(Path(s.var_rule_to_test.get()), True)).pack(side="left", padx=4)
        ttk.Button(actions, text="3. Scan malware", command=lambda: self.test_rule(False)).pack(side="left", padx=4)
        ttk.Button(actions, text="4. Scan malware + goodware", command=lambda: self.test_rule(True)).pack(side="left", padx=4)
        ttk.Button(actions, text=self.app.t("validate.export_csv"), command=self.export_csv).pack(side="left", padx=4)
        ttk.Button(actions, text=self.app.t("validate.export_html"), command=self.export_html).pack(side="left", padx=4)

        help_text = (
            "Flow: Check YARA CLI -> Validate rule -> Scan malware. "
            "Goodware folder phai la thu muc file sach rieng, KHONG chon thu muc goc co chua malware."
        )
        ttk.Label(box, text=help_text, style="Muted.TLabel", wraplength=980).grid(row=5, column=1, sticky="w", pady=(2, 0))

        self.output = ScrolledText(self, wrap="word", font=("Consolas", 10))
        self.output.grid(row=2, column=0, sticky="nsew")
        self._configure_output_tags()

    def _configure_output_tags(self):
        try:
            self.output.tag_configure("heading", font=("Consolas", 11, "bold"))
            self.output.tag_configure("ok", foreground="#0a7a2f")
            self.output.tag_configure("warn", foreground="#a36b00")
            self.output.tag_configure("error", foreground="#b00020")
            self.output.tag_configure("match", foreground="#0057b8")
            self.output.tag_configure("muted", foreground="#666666")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Logging helpers
    # ------------------------------------------------------------------
    def clear_output(self):
        self.output.delete("1.0", "end")

    def log(self, txt, tag=None):
        try:
            if tag:
                self.output.insert("end", txt, tag)
            else:
                self.output.insert("end", txt)
            self.output.see("end")
        except Exception:
            pass
        try:
            self.app.screens["monitor"].log(txt)
        except Exception:
            pass
        try:
            self.app.update_idletasks()
        except Exception:
            pass

    def section(self, title):
        self.log("\n" + "=" * 78 + "\n", "muted")
        self.log(f"{title}\n", "heading")
        self.log("=" * 78 + "\n", "muted")

    def kv(self, key, value, tag=None):
        self.log(f"{key:<24}: ")
        self.log(f"{value}\n", tag)

    # ------------------------------------------------------------------
    # Path and safety helpers
    # ------------------------------------------------------------------
    def _paths(self):
        s = self.app.state
        return {
            "rule": normalize_path(s.var_rule_to_test.get(), self.app.root_dir),
            "malware": normalize_path(s.var_test_malware_dir.get(), self.app.root_dir),
            "goodware": normalize_path(s.var_test_goodware_dir.get(), self.app.root_dir),
            "report": normalize_path(s.var_report_dir.get(), self.app.root_dir),
        }

    def _safe_resolve(self, path: Path) -> Path:
        try:
            return path.resolve()
        except Exception:
            return path.absolute()

    def _same_or_inside(self, child: Path, parent: Path) -> bool:
        child_r = self._safe_resolve(child)
        parent_r = self._safe_resolve(parent)
        try:
            return child_r == parent_r or child_r.is_relative_to(parent_r)
        except AttributeError:
            child_s = str(child_r).lower()
            parent_s = str(parent_r).lower().rstrip("\\/")
            return child_s == parent_s or child_s.startswith(parent_s + "\\") or child_s.startswith(parent_s + "/")

    def _count_files(self, folder: Path) -> int:
        if not folder.exists() or not folder.is_dir():
            return 0
        return sum(1 for p in folder.rglob("*") if p.is_file())

    def _validate_goodware_safety(self, malware_dir: Path, goodware_dir: Path) -> bool:
        """Prevent the common mistake: using project root as goodware folder."""
        if not goodware_dir or not goodware_dir.exists():
            return True
        root_dir = self._safe_resolve(Path(self.app.root_dir))
        goodware_r = self._safe_resolve(goodware_dir)
        malware_r = self._safe_resolve(malware_dir)

        problems = []
        if goodware_r == root_dir:
            problems.append("Goodware folder dang la thu muc goc cua project/app.")
        if goodware_r == malware_r:
            problems.append("Goodware folder trung voi Malware folder.")
        elif self._same_or_inside(malware_r, goodware_r):
            problems.append("Goodware folder dang CHUA Malware folder ben trong.")

        if not problems:
            return True

        self.section("GOODWARE FOLDER SAFETY CHECK")
        for problem in problems:
            self.log(f"[BLOCKED] {problem}\n", "error")
        self.log(
            "\nHay tao/chon mot thu muc file sach rieng, vi du: C:/DACK_GOODWARE.\n"
            "Khong chon C:/DACK_MALWARE neu trong do co samples malware, rules, reports, yara64.exe.\n",
            "warn",
        )
        messagebox.showerror(
            "Goodware folder khong hop le",
            "Goodware folder phai la thu muc file sach rieng.\n\n"
            "Khong chon thu muc goc project/app, khong chon thu muc co chua Malware folder.\n"
            "Vi du nen dung: C:/DACK_GOODWARE",
        )
        return False

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def detect_engine(self):
        """Only checks which YARA backend is available; it does not scan files."""
        self.clear_output()
        engine = YaraEngine(self.app.root_dir, prefer_yara_x=False, prefer_cli=True)
        paths = self._paths()

        self.section("1) YARA ENGINE CHECK")
        if engine.available():
            self.kv("Status", "OK", "ok")
        else:
            self.kv("Status", "MISSING", "error")
        self.kv("Backend", engine.backend)
        self.kv("Detail", engine.detail)
        if engine.backend == "yara-cli":
            self.log("[OFFICIAL CLI] App dang goi truc tiep yara64.exe/yara.exe cua VirusTotal/YARA.\n", "ok")
        elif engine.available():
            self.log("[INFO] Backend hien tai la Python binding/fallback, khong phai official CLI executable.\n", "warn")

        self.section("2) PATH CHECK")
        self.kv("Rule file", f"{'OK' if paths['rule'].is_file() else 'NOT FOUND'} - {paths['rule']}", "ok" if paths["rule"].is_file() else "error")
        self.kv("Malware folder", f"{'OK' if paths['malware'].is_dir() else 'NOT FOUND'} - {paths['malware']}", "ok" if paths["malware"].is_dir() else "error")
        goodware_ok = paths["goodware"].is_dir()
        self.kv("Goodware folder", f"{'OK' if goodware_ok else 'optional / not set'} - {paths['goodware']}", "ok" if goodware_ok else "warn")
        self.kv("Report folder", f"{'OK' if paths['report'].exists() else 'will be created when exporting'} - {paths['report']}", "ok" if paths["report"].exists() else "warn")

        self.section("3) WHAT TO DO NEXT")
        self.log("Detect/Check chi kiem tra engine va duong dan. No CHUA scan malware.\n")
        self.log("De nhan dien malware: bam 'Validate rule' -> 'Scan malware'.\n")
        self.log("De kiem false positive: chon Goodware folder file sach rieng -> 'Scan malware + goodware'.\n")

        if engine.available():
            messagebox.showinfo(
                "YARA engine detected",
                f"Backend: {engine.backend}\n{engine.detail}\n\n"
                "Neu Backend = yara-cli thi app dang dung truc tiep VirusTotal/YARA executable.\n"
                "Bam Validate rule / Scan malware de chay nhan dien.",
            )
        else:
            messagebox.showerror(
                "YARA engine missing",
                "Chua tim thay YARA engine chay duoc.\n\n"
                "Hay dat yara64.exe/yara.exe va yarac64.exe/yarac.exe vao thu muc app, hoac cai:\n"
                "pip install yara-python\n\nSau do mo lai app.",
            )
        return engine

    def validate_rule_file(self, rule_path: Path, show_popup=True):
        rule_path = normalize_path(str(rule_path), self.app.root_dir)
        if show_popup:
            self.clear_output()
        self.section("RULE VALIDATION")

        if not rule_path.exists():
            msg = f"Rule file not found: {rule_path}"
            self.log(f"[VALIDATE ERROR] {msg}\n", "error")
            if show_popup:
                messagebox.showerror("Validate", msg)
            return False

        engine = YaraEngine(self.app.root_dir, prefer_yara_x=False, prefer_cli=True)
        self.kv("Backend", engine.backend)
        self.kv("Detail", engine.detail)

        if engine.backend == "yara-cli":
            self.log("[OFFICIAL CLI] Validate bang yarac64.exe/yarac.exe neu co.\n", "ok")
        if not engine.available():
            self.log(f"[VALIDATE ERROR] {engine.detail}\n", "error")
            if show_popup:
                messagebox.showerror("Validate", engine.detail)
            return False

        try:
            engine.compile_rule(rule_path)
            self.kv("Rule", str(rule_path))
            self.log("[VALIDATE OK] Rule dung cu phap YARA.\n", "ok")
            if engine.last_command:
                self.kv("Command", " ".join(f'"{x}"' if " " in str(x) else str(x) for x in engine.last_command))
            if show_popup:
                messagebox.showinfo("Validate", f"Rule is valid.\nBackend: {engine.detail}")
            return True
        except Exception as e:
            self.log(f"[VALIDATE ERROR] {e}\n", "error")
            if show_popup:
                messagebox.showerror("Validate", str(e))
            return False

    def test_rule(self, scan_goodware=False):
        s = self.app.state
        self.clear_output()
        try:
            paths = self._paths()
            rule_path = paths["rule"]
            malware_dir = paths["malware"]
            goodware_dir = paths["goodware"]
            engine = YaraEngine(self.app.root_dir, prefer_yara_x=False, prefer_cli=True)

            self.section("SCAN SETUP")
            self.kv("Backend", engine.backend)
            self.kv("Detail", engine.detail)
            if engine.backend == "yara-cli":
                self.log("[OFFICIAL CLI] App dang goi truc tiep VirusTotal/YARA executable.\n", "ok")
            else:
                self.log("[INFO] Backend khong phai official CLI executable. Kiem tra lai yara64.exe neu can.\n", "warn")

            if not engine.available():
                self.log("[STOP] No YARA backend found.\n", "error")
                messagebox.showerror("YARA engine missing", "Dat yara64.exe/yara.exe vao thu muc app, hoac install: pip install yara-python")
                return

            if not malware_dir.exists() or not malware_dir.is_dir():
                self.log(f"[STOP] Malware folder not found: {malware_dir}\n", "error")
                messagebox.showerror("Missing malware folder", str(malware_dir))
                return

            if scan_goodware:
                if not goodware_dir.exists() or not goodware_dir.is_dir():
                    self.log(f"[STOP] Goodware folder not found: {goodware_dir}\n", "error")
                    messagebox.showerror("Missing goodware folder", "Hay chon Goodware folder file sach rieng.")
                    return
                if not self._validate_goodware_safety(malware_dir, goodware_dir):
                    return

            if not self.validate_rule_file(rule_path, show_popup=False):
                self.log("[STOP] Invalid YARA rule. Khong the scan.\n", "error")
                return

            targets = [("malware", malware_dir)]
            if scan_goodware:
                targets.append(("goodware", goodware_dir))

            rows = []
            stats = {
                "malware": {"files": 0, "matched_files": 0, "matches": 0, "errors": 0},
                "goodware": {"files": 0, "matched_files": 0, "matches": 0, "errors": 0},
            }

            for dataset, folder in targets:
                self._scan_dataset(dataset, folder, rule_path, engine, rows, stats[dataset])

            s.last_test_results = rows
            self._print_final_summary(stats, scan_goodware)

            mal_files = stats["malware"]["matched_files"]
            mal_matches = stats["malware"]["matches"]
            fp_files = stats["goodware"]["matched_files"]
            errors = stats["malware"]["errors"] + stats["goodware"]["errors"]
            messagebox.showinfo(
                "Scan finished",
                f"Malware matched files: {mal_files}\n"
                f"Malware rule matches: {mal_matches}\n"
                f"Goodware false-positive files: {fp_files}\n"
                f"Errors: {errors}",
            )
        except Exception as e:
            self.log(f"[TEST ERROR] {e}\n", "error")
            messagebox.showerror("Test", str(e))

    def _scan_dataset(self, dataset, folder, rule_path, engine, rows, stat):
        files = [p for p in folder.rglob("*") if p.is_file()]
        stat["files"] = len(files)

        title = "MALWARE DETECTION SCAN" if dataset == "malware" else "GOODWARE FALSE-POSITIVE SCAN"
        self.section(title)
        self.kv("Folder", str(folder))
        self.kv("Files", len(files))
        if engine.backend == "yara-cli":
            self.kv("Command model", engine.cli_command_preview(rule_path, "<each-file>"))
            self.log("[INFO] App scan tung file de dem chinh xac matched files / false positives.\n", "muted")

        if not files:
            self.log("[WARNING] Khong co file nao trong folder nay.\n", "warn")
            return

        for idx, p in enumerate(files, 1):
            try:
                matches = engine.scan_file(rule_path, p, timeout=60)
                if matches:
                    stat["matched_files"] += 1
                    stat["matches"] += len(matches)
                    label = "FALSE POSITIVE" if dataset == "goodware" else "MATCH"
                    tag = "error" if dataset == "goodware" else "match"
                    self.log(f"[{label}] {p.name}\n", tag)
                    self.log(f"          path : {p}\n")
                    self.log(f"          rules: {', '.join(matches)}\n", tag)
                    for rule_name in matches:
                        rows.append({
                            "dataset": dataset,
                            "file": str(p),
                            "rule": rule_name,
                            "is_false_positive": "yes" if dataset == "goodware" else "no",
                            "notes": "",
                        })
                elif idx <= 5:
                    # Keep logs readable: show only first few clean/no-match files.
                    self.log(f"[NO MATCH] {p.name}\n", "muted")
            except Exception as e:
                stat["errors"] += 1
                self.log(f"[SCAN ERROR] {p}: {e}\n", "error")
                rows.append({
                    "dataset": dataset,
                    "file": str(p),
                    "rule": "<scan_error>",
                    "is_false_positive": "",
                    "notes": str(e),
                })

    def _print_final_summary(self, stats, scanned_goodware):
        self.section("FINAL SUMMARY")
        total_files = stats["malware"]["files"] + stats["goodware"]["files"]
        total_errors = stats["malware"]["errors"] + stats["goodware"]["errors"]

        self.kv("Total scanned files", total_files)
        self.kv("Malware files scanned", stats["malware"]["files"])
        self.kv("Malware matched files", stats["malware"]["matched_files"], "ok" if stats["malware"]["matched_files"] else "warn")
        self.kv("Malware rule matches", stats["malware"]["matches"])

        if stats["malware"]["files"]:
            rate = stats["malware"]["matched_files"] / stats["malware"]["files"] * 100
            self.kv("Detection rate", f"{rate:.2f}%")

        if scanned_goodware:
            self.kv("Goodware files scanned", stats["goodware"]["files"])
            self.kv("False-positive files", stats["goodware"]["matched_files"], "error" if stats["goodware"]["matched_files"] else "ok")
            self.kv("False-positive rule matches", stats["goodware"]["matches"])
            if stats["goodware"]["files"]:
                fp_rate = stats["goodware"]["matched_files"] / stats["goodware"]["files"] * 100
                self.kv("False-positive rate", f"{fp_rate:.2f}%")

        self.kv("Scan errors", total_errors, "error" if total_errors else "ok")

        self.log("\nINTERPRETATION\n", "heading")
        if stats["malware"]["matched_files"] > 0:
            self.log("[OK] Rule da nhan dien duoc malware trong folder mau.\n", "ok")
        else:
            self.log("[CHECK] Rule hop le nhung chua match malware nao. Kiem tra lai rule/features/sample.\n", "warn")

        if scanned_goodware:
            if stats["goodware"]["matched_files"] == 0:
                self.log("[OK] Chua thay false positive tren goodware folder da chon.\n", "ok")
            else:
                self.log(
                    "[WARNING] Co false positive tren goodware. Neu folder nay co chua malware thi hay chon lai folder file sach rieng.\n"
                    "Neu dung la file sach that, can tang coverage/min-score hoac bo string qua chung.\n",
                    "warn",
                )

    def export_csv(self):
        rows = self.app.state.last_test_results
        if not rows:
            messagebox.showwarning("No results", "No test results yet.")
            return
        path = normalize_path(self.app.state.var_report_dir.get(), self.app.root_dir) / "yara_test_report.csv"
        export_test_csv(rows, path)
        open_path(path.parent)

    def export_html(self):
        rows = self.app.state.last_test_results
        if not rows:
            messagebox.showwarning("No results", "No test results yet.")
            return
        path = normalize_path(self.app.state.var_report_dir.get(), self.app.root_dir) / "yara_test_report.html"
        export_test_html(rows, path)
        open_path(path)
