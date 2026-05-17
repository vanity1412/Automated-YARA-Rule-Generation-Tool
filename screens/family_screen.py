# -*- coding: utf-8 -*-
from pathlib import Path
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText

from core.utils import path_row, safe_identifier, normalize_path, open_path
from core.config import RELEVANT_EXTENSIONS
from core.family_signature import build_common_profile, write_profile_reports, append_rule_file
from core.yara_engine import YaraEngine


class FamilyScreen(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, style="App.TFrame")
        self.app = app
        self.last_profile = None
        self.build()

    def refresh_text(self): pass
    def on_mode_changed(self): pass
    def on_show(self): pass

    def build(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)
        ttk.Label(self, text=self.app.t("family.title"), style="Title.TLabel").grid(row=0, column=0, sticky="w")
        box = ttk.Frame(self, style="Card.TFrame", padding=12)
        box.grid(row=1, column=0, sticky="ew", pady=8)
        box.columnconfigure(1, weight=1)
        s = self.app.state
        path_row(box, 0, "Malware family name", s.var_family_name, self.app.root_dir)
        path_row(box, 1, "Goal / description", s.var_family_goal, self.app.root_dir)
        path_row(box, 2, "Minimum sample count", s.var_min_family_samples, self.app.root_dir)
        path_row(box, 3, "Author", s.var_author, self.app.root_dir)
        path_row(box, 4, "Reference", s.var_reference, self.app.root_dir)
        path_row(box, 5, "License", s.var_license, self.app.root_dir)
        path_row(box, 6, "Identifier file", s.var_identifier_file, self.app.root_dir, "file_open")
        path_row(box, 7, "Common-feature rule output", s.var_common_rule_output, self.app.root_dir, "file_save_yar")
        path_row(box, 8, "Coverage ratio 0.1-1.0", s.var_common_coverage, self.app.root_dir)
        path_row(box, 9, "Min string length", s.var_common_min_len, self.app.root_dir)
        path_row(box, 10, "Max common features", s.var_common_max_features, self.app.root_dir)
        path_row(box, 11, "Merged yarGen + common rule", s.var_merged_rule_output, self.app.root_dir, "file_save_yar")
        actions = ttk.Frame(box, style="Surface.TFrame")
        actions.grid(row=12, column=1, sticky="w", pady=8)
        ttk.Button(actions, text=self.app.t("family.apply"), command=self.apply_preset).pack(side="left", padx=4)
        ttk.Button(actions, text=self.app.t("family.analyze"), command=self.analyze_folder).pack(side="left", padx=4)
        ttk.Button(actions, text="Generate common rule", command=self.generate_common_rule).pack(side="left", padx=4)
        ttk.Button(actions, text="Merge with yarGen rule", command=self.merge_with_yargen_rule).pack(side="left", padx=4)
        ttk.Button(actions, text="Validate common rule", command=self.validate_common_rule).pack(side="left", padx=4)
        ttk.Button(actions, text=self.app.t("family.identifier"), command=self.create_identifier).pack(side="left", padx=4)
        self.report = ScrolledText(self, wrap="word")
        self.report.grid(row=2, column=0, sticky="nsew")
        self.report.insert("end", "Family rule = rule built from common features across multiple malware samples.\n")
        self.report.insert("end", "Recommended workflow: Analyze folder -> Generate common rule -> run yarGen -> Merge -> Validate/Test with YARA engine.\n")

    def _log(self, text):
        self.report.insert("end", text)
        self.report.see("end")
        try:
            self.app.screens["monitor"].log(text)
        except Exception:
            pass

    def apply_preset(self):
        s = self.app.state
        family = safe_identifier(s.var_family_name.get())
        s.var_malware.set(str(Path(s.var_workdir.get()) / "samples" / family))
        s.var_output.set(str(Path(s.var_workdir.get()) / "rules" / f"{family}_yargen.yar"))
        s.var_common_rule_output.set(str(Path(s.var_workdir.get()) / "rules" / f"{family}_common.yar"))
        s.var_merged_rule_output.set(str(Path(s.var_workdir.get()) / "rules" / f"{family}_combined.yar"))
        s.var_string_export_dir.set(str(Path(s.var_workdir.get()) / "strings_out" / family))
        s.var_prefix.set(f"Malware family {family}")
        s.var_score.set(True); s.var_strings.set(True)
        s.var_nosuper.set(False); s.var_nosimple.set(False)
        s.var_min_score.set("0"); s.var_high_score.set("10"); s.var_super_min.set("2")
        self.app.screens["generate"].update_command_preview()
        self._log(f"[FAMILY] Applied preset for {family}. Sample folder: {s.var_malware.get()}\n")
        self.app.show_screen("generate")

    def create_identifier(self):
        family = safe_identifier(self.app.state.var_family_name.get())
        out = Path(self.app.state.var_workdir.get()) / "identifier.txt"
        out.write_text(family + "\n", encoding="utf-8")
        self.app.state.var_identifier_file.set(str(out))
        messagebox.showinfo("Identifier created", str(out))

    def analyze_folder(self):
        folder = normalize_path(self.app.state.var_malware.get(), self.app.root_dir)
        self.report.delete("1.0", "end")
        self._log(f"Folder: {folder}\n")
        if not folder.exists():
            self._log("[MISSING] Folder not found. Use Apply preset or choose a valid malware family folder.\n")
            return
        files = [p for p in folder.rglob("*") if p.is_file()]
        relevant = [p for p in files if p.suffix.lower() in RELEVANT_EXTENSIONS]
        self._log(f"Total files: {len(files)}\nRelevant malware extensions: {len(relevant)}\n")
        ext_count = {}
        for p in files:
            ext_count[p.suffix.lower() or "<no_ext>"] = ext_count.get(p.suffix.lower() or "<no_ext>", 0) + 1
        for ext, count in sorted(ext_count.items(), key=lambda kv: (-kv[1], kv[0])):
            self._log(f"- {ext}: {count}\n")
        try:
            min_samples = int(self.app.state.var_min_family_samples.get() or "2")
        except Exception:
            min_samples = 2
        if len(files) < min_samples:
            self._log(f"[WARNING] Need at least {min_samples} samples to claim a family-common signature.\n")
        else:
            self._log("[OK] Sample count is enough for family-common extraction.\n")

    def _profile_options(self):
        s = self.app.state
        try:
            cov = max(0.1, min(1.0, float(s.var_common_coverage.get() or "0.60")))
        except Exception:
            cov = 0.60
        try:
            min_len = max(3, int(s.var_common_min_len.get() or "6"))
        except Exception:
            min_len = 6
        try:
            max_features = max(1, int(s.var_common_max_features.get() or "40"))
        except Exception:
            max_features = 40
        return cov, min_len, max_features

    def generate_common_rule(self):
        s = self.app.state
        folder = normalize_path(s.var_malware.get(), self.app.root_dir)
        goodware = normalize_path(s.var_test_goodware_dir.get(), self.app.root_dir) if s.var_test_goodware_dir.get() else None
        output = normalize_path(s.var_common_rule_output.get(), self.app.root_dir)
        cov, min_len, max_features = self._profile_options()
        self.report.delete("1.0", "end")
        self._log("[COMMON] Extracting features shared by the malware family...\n")
        profile = build_common_profile(
            folder,
            family_name=safe_identifier(s.var_family_name.get()),
            goodware_dir=goodware if goodware and goodware.exists() else None,
            min_coverage_ratio=cov,
            min_len=min_len,
            max_features=max_features,
        )
        self.last_profile = profile
        rule, csv_path, md_path = write_profile_reports(
            profile,
            output,
            report_dir=normalize_path(s.var_report_dir.get(), self.app.root_dir),
            author=s.var_author.get(),
            reference=s.var_reference.get(),
            license_text=s.var_license.get(),
        )
        s.var_common_rule_output.set(str(rule))
        s.var_rule_to_test.set(str(rule))
        s.var_rule_score_file.set(str(rule))
        self._log(f"[COMMON] Files analyzed: {profile['analyzed_count']} / {profile['sample_count']}\n")
        self._log(f"[COMMON] Features selected: {len(profile['features'])}\n")
        for row in profile["features"][:30]:
            self._log(f"  coverage={row['coverage']:.2f} score={row['score']:>3} value={row['value']}\n")
        self._log(f"[WRITE] Rule: {rule}\n[WRITE] CSV: {csv_path}\n[WRITE] Markdown: {md_path}\n")
        open_path(rule.parent)

    def merge_with_yargen_rule(self):
        s = self.app.state
        base = normalize_path(s.var_output.get(), self.app.root_dir)
        common = normalize_path(s.var_common_rule_output.get(), self.app.root_dir)
        merged = normalize_path(s.var_merged_rule_output.get(), self.app.root_dir)
        if not base.exists():
            messagebox.showwarning("Missing yarGen rule", f"Run Generate first or select an existing yarGen rule:\n{base}")
            return
        if not common.exists():
            messagebox.showwarning("Missing common rule", f"Generate common-feature rule first:\n{common}")
            return
        out = append_rule_file(base, common, merged)
        s.var_rule_to_test.set(str(out))
        s.var_rule_score_file.set(str(out))
        self._log(f"[MERGE] Combined rule written: {out}\n")
        open_path(out.parent)

    def validate_common_rule(self):
        rule = normalize_path(self.app.state.var_common_rule_output.get(), self.app.root_dir)
        engine = YaraEngine(self.app.root_dir)
        self._log(f"[YARA] Backend: {engine.backend} - {engine.detail}\n")
        try:
            engine.compile_rule(rule)
            self._log(f"[YARA OK] Rule is valid: {rule}\n")
            messagebox.showinfo("YARA validate", "Common-feature rule is valid.")
        except Exception as exc:
            self._log(f"[YARA ERROR] {exc}\n")
            messagebox.showerror("YARA validate", str(exc))
