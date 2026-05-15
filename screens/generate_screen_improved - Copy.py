# -*- coding: utf-8 -*-
import gzip, json, shutil
from pathlib import Path
from tkinter import ttk, messagebox
from core.utils import path_row, quoted_command, normalize_path
from core.config import EXPECTED_DB_PREFIXES, ARCHIVE_EXTENSIONS, PRESET_DESCRIPTIONS
from core.yargen_command import build_generate_command
from core.scrollable_screen import ScrollableScreen

class GenerateScreenImproved(ScrollableScreen):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.advanced_widgets = []
        self.build()

    def refresh_text(self): 
        pass
        
    def on_show(self):
        self.update_command_preview()
        self.on_mode_changed()
        
    def on_mode_changed(self):
        advanced = self.app.settings.get("mode", "basic") == "advanced"
        for w in self.advanced_widgets:
            if advanced: 
                w.grid()
            else: 
                w.grid_remove()
        
        # Force layout update after showing/hiding widgets
        self.update_idletasks()
        if hasattr(self, 'canvas'):
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        
        # Also update the parent frame to recalculate layout
        if hasattr(self, 'scrollable_frame'):
            self.scrollable_frame.update_idletasks()

    def build(self):
        # Create scrollable content with title
        content_frame = self.create_scrollable_content(self.app.t("generate.title"))
        content_frame.columnconfigure(0, weight=1)
        
        # Build the actual content
        self.build_content(content_frame)
        
        # Add trace listeners for command preview updates
        self.setup_trace_listeners()
        
        # Apply default preset
        self.apply_preset("Beginner")

    def build_content(self, parent):
        # Top controls
        top = ttk.Frame(parent, style="Card.TFrame", padding=12)
        top.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        top.columnconfigure(5, weight=1)
        
        ttk.Label(top, text="Preset", style="Card.TLabel").grid(row=0, column=0, padx=4)
        presets = ["Beginner", "PE Deep", "Script Malware", "Webshell", "Fast Scan", "TrickBot Demo", "Loose Debug"]
        self.preset_combo = ttk.Combobox(top, values=presets, state="readonly", 
                                       textvariable=self.app.state.var_current_preset, width=18)
        self.preset_combo.grid(row=0, column=1, padx=4)
        self.preset_combo.bind("<<ComboboxSelected>>", lambda _e: self.apply_selected_preset())
        
        ttk.Label(top, text="DB Mode", style="Card.TLabel").grid(row=0, column=2, padx=4)
        ttk.Combobox(top, values=["Full quality DB", "Fast strings DB", "Fast no-opcodes DB"], 
                    state="readonly", textvariable=self.app.state.var_db_mode, width=20).grid(row=0, column=3, padx=4)
        
        ttk.Button(top, text=self.app.t("generate.preview"), 
                  command=self.update_command_preview).grid(row=0, column=4, padx=4)
        ttk.Button(top, text=self.app.t("generate.generate"), command=self.run_generate, 
                  style="Primary.TButton").grid(row=0, column=5, padx=4, sticky="e")
        ttk.Button(top, text=self.app.t("generate.stop"), command=self.app.runner.stop, 
                  style="Danger.TButton").grid(row=0, column=6, padx=4)
        
        self.preset_desc = ttk.Label(top, text="", style="Muted.TLabel", wraplength=900)
        self.preset_desc.grid(row=1, column=0, columnspan=7, sticky="w", pady=(8, 0))

        # Body with Basic and Advanced options
        body = ttk.Frame(parent, style="App.TFrame")
        body.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)

        # Basic options
        basic = ttk.LabelFrame(body, text=self.app.t("generate.basic"), padding=12)
        basic.grid(row=0, column=0, sticky="new", padx=(0, 6))
        basic.columnconfigure(1, weight=1)
        s = self.app.state
        path_row(basic, 0, "Malware/sample folder (-m)", s.var_malware, self.app.root_dir, "folder")
        path_row(basic, 1, "Output YARA file (-o)", s.var_output, self.app.root_dir, "file_save_yar")
        path_row(basic, 2, "String export folder (-e)", s.var_string_export_dir, self.app.root_dir, "folder")
        path_row(basic, 3, "Author (-a)", s.var_author, self.app.root_dir)
        path_row(basic, 4, "Reference (-r)", s.var_reference, self.app.root_dir)

        # Advanced options
        adv = ttk.LabelFrame(body, text=self.app.t("generate.advanced"), padding=12)
        adv.grid(row=0, column=1, sticky="new", padx=(6, 0))
        adv.columnconfigure(1, weight=1)
        for row, (label, var) in enumerate([
            ("License (-l)", s.var_license),
            ("Prefix/description (-p)", s.var_prefix),
            ("Identifier file (-b)", s.var_identifier_file),
            ("Min string length (-y)", s.var_min_len),
            ("Min score (-z)", s.var_min_score),
            ("High specific score (-x)", s.var_high_score),
            ("Super rule min overlap (-w)", s.var_super_min),
            ("Max string length (-s)", s.var_max_len),
            ("Max strings per rule (-rc)", s.var_rule_count),
            ("Max file size MB (-fs)", s.var_file_size),
            ("Filesize multiplier (-fm)", s.var_filesize_multiplier),
            ("Opcode number (-n)", s.var_opcode_num),
        ]):
            path_row(adv, row, label, var, self.app.root_dir, "file_open" if "Identifier" in label else None)
        self.advanced_widgets.append(adv)

        # Options checkboxes - Improved layout
        flags = ttk.LabelFrame(parent, text="Options", padding=12)
        flags.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        
        # Create a frame for better organization
        flags_inner = ttk.Frame(flags, style="Surface.TFrame")
        flags_inner.pack(fill="both", expand=True)
        
        # Configure columns for even distribution
        for i in range(4):
            flags_inner.columnconfigure(i, weight=1, uniform="col")
        
        options = [
            ("--score", s.var_score), ("--strings", s.var_strings), ("--opcodes", s.var_opcodes), ("--oe", s.var_oe),
            ("--excludegood", s.var_excludegood), ("--nosuper", s.var_nosuper), ("--nosimple", s.var_nosimple),
            ("--nomagic", s.var_nomagic), ("--nofilesize", s.var_nofilesize), ("--noextras", s.var_noextras),
            ("--debug", s.var_debug), ("--trace", s.var_trace), ("--noscorefilter", s.var_noscorefilter),
        ]
        
        # Arrange checkboxes in a proper grid with adequate spacing
        for idx, (txt, var) in enumerate(options):
            row = idx // 4
            col = idx % 4
            cb = ttk.Checkbutton(flags_inner, text=txt, variable=var, command=self.update_command_preview)
            cb.grid(row=row, column=col, sticky="w", padx=20, pady=10, ipadx=5)
            if txt in {"--debug", "--trace", "--noscorefilter"}:
                self.advanced_widgets.append(cb)

        # Command Preview
        cmd_box = ttk.LabelFrame(parent, text="Command Preview", padding=8)
        cmd_box.grid(row=3, column=0, sticky="ew", pady=(0, 8))
        cmd_box.columnconfigure(0, weight=1)
        
        cmd_entry = ttk.Entry(cmd_box, textvariable=s.var_command_preview, font=("Consolas", 9))
        cmd_entry.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        
        button_frame = ttk.Frame(cmd_box, style="Surface.TFrame")
        button_frame.grid(row=0, column=1)
        ttk.Button(button_frame, text="Save .bat", command=self.save_bat).pack(side="left", padx=2)
        ttk.Button(button_frame, text="Save .sh", command=self.save_sh).pack(side="left", padx=2)

    def setup_trace_listeners(self):
        """Setup trace listeners for automatic command preview updates"""
        s = self.app.state
        for var in [
            s.var_python, s.var_yargen, s.var_malware, s.var_output, s.var_string_export_dir,
            s.var_author, s.var_reference, s.var_license, s.var_prefix, s.var_identifier_file,
            s.var_min_len, s.var_min_score, s.var_high_score, s.var_super_min, s.var_max_len,
            s.var_rule_count, s.var_file_size, s.var_filesize_multiplier, s.var_opcode_num,
            s.var_db_mode, s.var_fast_max_part
        ]:
            var.trace_add("write", lambda *_: self.update_command_preview())

    def update_command_preview(self):
        cmd = build_generate_command(self.app.state)
        self.app.state.last_command = cmd
        self.app.state.var_command_preview.set(quoted_command(cmd))
        self.app.refresh_status()

    def apply_selected_preset(self):
        self.apply_preset(self.app.state.var_current_preset.get())

    def apply_preset(self, name):
        s = self.app.state
        s.var_current_preset.set(name)
        for v in [s.var_strings, s.var_opcodes, s.var_oe, s.var_noextras, s.var_nofilesize, s.var_nomagic, s.var_debug, s.var_trace, s.var_noscorefilter, s.var_nosuper, s.var_nosimple]:
            v.set(False)
        s.var_score.set(True)
        s.var_min_len.set("8"); s.var_min_score.set("0"); s.var_high_score.set("30"); s.var_super_min.set("5")
        s.var_max_len.set("128"); s.var_rule_count.set("20"); s.var_file_size.set("10"); s.var_filesize_multiplier.set("3"); s.var_opcode_num.set("3")
        s.var_db_mode.set("Full quality DB")
        if name == "PE Deep":
            s.var_strings.set(True); s.var_opcodes.set(True); s.var_oe.set(True); s.var_debug.set(True)
        elif name == "Script Malware":
            s.var_strings.set(True); s.var_oe.set(True); s.var_noextras.set(True); s.var_nofilesize.set(True); s.var_min_len.set("6"); s.var_max_len.set("256"); s.var_rule_count.set("25")
        elif name == "Webshell":
            s.var_strings.set(True); s.var_oe.set(True); s.var_noextras.set(True); s.var_nofilesize.set(True); s.var_nomagic.set(True); s.var_min_len.set("5"); s.var_max_len.set("300"); s.var_rule_count.set("30")
        elif name == "Fast Scan":
            s.var_oe.set(True); s.var_file_size.set("5"); s.var_rule_count.set("15"); s.var_db_mode.set("Fast no-opcodes DB")
        elif name == "TrickBot Demo":
            s.var_strings.set(True); s.var_min_len.set("6"); s.var_min_score.set("0"); s.var_high_score.set("10"); s.var_super_min.set("2"); s.var_max_len.set("512"); s.var_rule_count.set("30"); s.var_file_size.set("100"); s.var_filesize_multiplier.set("5"); s.var_prefix.set("TrickBot family rule")
        elif name == "Loose Debug":
            s.var_strings.set(True); s.var_debug.set(True); s.var_noscorefilter.set(True); s.var_min_len.set("4"); s.var_min_score.set("-20"); s.var_high_score.set("1"); s.var_super_min.set("1"); s.var_max_len.set("2048"); s.var_rule_count.set("100"); s.var_file_size.set("100"); s.var_filesize_multiplier.set("5")
        lang = self.app.i18n.language
        self.preset_desc.configure(text=PRESET_DESCRIPTIONS.get(name, {}).get(lang, ""))
        self.update_command_preview()

    def preflight(self):
        s = self.app.state
        yargen = normalize_path(s.var_yargen.get(), self.app.root_dir)
        sample = normalize_path(s.var_malware.get(), self.app.root_dir)
        output = normalize_path(s.var_output.get(), self.app.root_dir)
        if not yargen.is_file():
            return False, f"yarGen.py not found: {yargen}"
        if not sample.is_dir():
            return False, f"Sample folder not found: {sample}"
        files = [p for p in sample.rglob("*") if p.is_file()]
        if not files:
            return False, f"Sample folder is empty: {sample}"
        archives = [p for p in files if p.suffix.lower() in ARCHIVE_EXTENSIONS]
        if archives:
            self.app.screens["monitor"].log(f"[WARN] Archive files detected ({len(archives)}). Extract before final generation.\n")
        output.parent.mkdir(parents=True, exist_ok=True)
        if s.var_strings.get():
            normalize_path(s.var_string_export_dir.get(), self.app.root_dir).mkdir(parents=True, exist_ok=True)
        s.var_yargen.set(str(yargen)); s.var_malware.set(str(sample)); s.var_output.set(str(output))
        s.var_rule_to_test.set(str(output)); s.var_rule_score_file.set(str(output)); s.var_test_malware_dir.set(str(sample))
        return True, "OK"

    def fast_db_runtime_dir(self):
        s = self.app.state
        mode = s.var_db_mode.get()
        if mode == "Full quality DB": return None
        workdir = normalize_path(s.var_workdir.get(), self.app.root_dir)
        source_dbs = workdir / "dbs"
        max_part = max(1, int(s.var_fast_max_part.get() or "2"))
        prefixes = ["good-strings-part"] if mode == "Fast strings DB" else ["good-strings-part", "good-exports-part", "good-imphashes-part"]
        runtime = workdir / "_gui_runtime" / (mode.lower().replace(" ", "_") + f"_p{max_part}")
        runtime_dbs = runtime / "dbs"
        if runtime_dbs.exists(): shutil.rmtree(runtime_dbs)
        runtime_dbs.mkdir(parents=True, exist_ok=True)
        if (workdir / "3rdparty").exists():
            dst = runtime / "3rdparty"
            if dst.exists(): shutil.rmtree(dst)
            shutil.copytree(workdir / "3rdparty", dst)
        empty = gzip.compress(json.dumps({}).encode("utf-8"))
        for prefix in EXPECTED_DB_PREFIXES:
            for part in range(1, max_part + 1):
                dst = runtime_dbs / f"{prefix}{part}.db"
                src = source_dbs / dst.name
                if prefix in prefixes and src.exists(): shutil.copy2(src, dst)
                else: dst.write_bytes(empty)
        self.app.screens["monitor"].log(f"[PERF] Runtime DB mode={mode}, cwd={runtime}\n")
        return runtime

    def run_generate(self):
        ok, msg = self.preflight()
        if not ok:
            messagebox.showerror("Cannot generate", msg); return
        runtime = self.fast_db_runtime_dir()
        self.app.runner.run_command(build_generate_command(self.app.state), "Generate YARA rules", cwd=runtime, task="generate")

    def after_generate_success(self):
        self.app.screens["monitor"].log("\n[POST] Generate completed.\n")
        if self.app.state.var_auto_validate.get():
            self.app.screens["validate"].validate_rule_file(Path(self.app.state.var_output.get()), show_popup=False)

    def save_bat(self):
        out = Path(self.app.state.var_workdir.get()) / "run_yargen_command.bat"
        out.write_text(quoted_command(self.app.state.last_command) + "\n", encoding="utf-8")
        messagebox.showinfo("Saved", str(out))

    def save_sh(self):
        out = Path(self.app.state.var_workdir.get()) / "run_yargen_command.sh"
        out.write_text("#!/usr/bin/env bash\n" + quoted_command(self.app.state.last_command) + "\n", encoding="utf-8")
        messagebox.showinfo("Saved", str(out))