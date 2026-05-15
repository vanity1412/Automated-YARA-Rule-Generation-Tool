# -*- coding: utf-8 -*-
import gzip
import json
import shutil
from pathlib import Path
from tkinter import ttk, messagebox

from core.scrollable_screen import ScrollableScreen
from core.utils import path_row, quoted_command, normalize_path, ToolTip
from core.config import EXPECTED_DB_PREFIXES, ARCHIVE_EXTENSIONS, PRESET_DESCRIPTIONS
from core.yargen_command import build_generate_command


OPTION_TOOLTIPS = {
    "--score": "Bật tính điểm cho từng string trong rule. Nên bật để rule có thông tin review/chấm điểm.",
    "--strings": "Xuất strings ra thư mục -e. Hữu ích để review nhưng có thể tạo thêm nhiều file output.",
    "--opcodes": "Phân tích opcode PE. Có thể tăng chất lượng với PE nhưng chậm và tốn RAM.",
    "--oe": "Chỉ scan extension liên quan. Giúp gọn hơn với folder lẫn nhiều file phụ.",
    "--excludegood": "Loại trừ string có trong goodware DB. Giảm false positive nhưng có thể sinh ít rule hơn.",
    "--nosuper": "Không sinh Super Rule.",
    "--nosimple": "Bỏ Simple Rule cho file đã nằm trong Super Rule.",
    "--nomagic": "Không dùng magic header/file type trong condition.",
    "--nofilesize": "Không thêm điều kiện filesize vào rule.",
    "--globalrule": "Tạo global rule để tăng tốc scan, cần review kỹ trước khi dùng production.",
    "--dropzone": "Dropzone mode của yarGen. Không khuyến nghị trong GUI vì có thể xoá file đã xử lý.",
    "--nr": "Không scan đệ quy thư mục con.",
    "--noextras": "Bỏ bớt imphash/export/PE extras để chạy gọn hơn.",
    "--debug": "Log debug chi tiết để tìm nguyên nhân lỗi hoặc 0 rule.",
    "--trace": "Trace rất dài, chỉ dùng khi debug sâu.",
    "--inverse": "Inverse mode ẩn/unstable của yarGen.",
    "--nodirname": "Dùng với inverse mode; không thêm dirname vào condition.",
    "--noscorefilter": "Bỏ lọc theo score. Dễ sinh rule hơn nhưng rule có thể yếu hơn.",
}

PARAM_TOOLTIPS = {
    "License (-l)": "Metadata license cho rule set. Có thể bỏ trống.",
    "Prefix/description (-p)": "Mô tả/prefix đưa vào meta description trong rule.",
    "Identifier file (-b)": "File identifier tùy chọn để đặt tên rule/family ổn định hơn.",
    "Min string length (-y)": "Độ dài string tối thiểu. Giảm nếu yarGen sinh 0 rule; tăng để lọc string ngắn.",
    "Min score (-z)": "Điểm tối thiểu. Tăng để giảm false positive; giảm khi cần sinh rule dễ hơn.",
    "High specific score (-x)": "Ngưỡng string rất đặc trưng, thường dùng cho $x strings.",
    "Super rule min overlap (-w)": "Số string overlap tối thiểu để tạo Super Rule.",
    "Max string length (-s)": "Độ dài string tối đa. Tăng nếu sample có URL/path/config dài.",
    "Max strings per rule (-rc)": "Giới hạn số string trong mỗi rule để dễ review.",
    "Max file size MB (-fs)": "Bỏ qua file vượt kích thước này để tránh chạy lâu.",
    "Filesize multiplier (-fm)": "Nhân kích thước sample khi tạo condition filesize.",
    "Opcode number (-n)": "Số opcode thêm vào rule khi bật --opcodes.",
}


class GenerateScreen(ScrollableScreen):
    """Scrollable generation screen.

    The old fixed grid clipped Advanced options on smaller screens.  This version
    keeps the same yarGen logic but puts the full form in a scrollable canvas and
    groups dangerous/rare flags so every option remains reachable.
    """

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.advanced_widgets = []
        self.realtime_log = None
        self.auto_scroll_var = None
        self.build()

    def refresh_text(self):
        pass

    def on_show(self):
        self.update_command_preview()
        self.on_mode_changed()
        # Hook vào runner để nhận realtime output
        if hasattr(self.app, 'runner') and hasattr(self.app.runner, 'add_output_callback'):
            self.app.runner.add_output_callback(self.on_runner_output)

    def on_runner_output(self, line):
        """Callback nhận output từ runner"""
        if line.strip():  # Chỉ log những dòng không rỗng
            # Lọc và format output
            if "yarGen" in line or "Processing" in line or "Rule" in line or "String" in line:
                self.log_realtime(f"📋 {line.strip()}")
            elif "ERROR" in line.upper() or "FAIL" in line.upper():
                self.log_realtime(f"❌ {line.strip()}")
            elif "WARNING" in line.upper() or "WARN" in line.upper():
                self.log_realtime(f"⚠️  {line.strip()}")
            elif "SUCCESS" in line.upper() or "COMPLETE" in line.upper():
                self.log_realtime(f"✅ {line.strip()}")
            else:
                self.log_realtime(f"ℹ️  {line.strip()}")

    def on_mode_changed(self):
        advanced = self.app.settings.get("mode", "basic") == "advanced"
        for w in self.advanced_widgets:
            if advanced:
                w.grid()
            else:
                w.grid_remove()
        self._refresh_scrollregion()

    def _refresh_scrollregion(self):
        try:
            self.update_idletasks()
            if self.canvas is not None:
                self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        except Exception:
            pass

    def build(self):
        parent = self.create_scrollable_content(self.app.t("generate.title"))
        parent.columnconfigure(0, weight=1)
        self.build_top(parent, 0)
        self.build_paths_and_params(parent, 1)
        self.build_flags(parent, 2)
        self.build_command_box(parent, 3)
        self.build_realtime_log(parent, 4)  # Thêm realtime log
        self.setup_trace_listeners()
        self.apply_preset("Beginner")

    def build_top(self, parent, row):
        top = ttk.Frame(parent, style="Card.TFrame", padding=12)
        top.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        for c in range(7):
            top.columnconfigure(c, weight=1 if c == 5 else 0)
        ttk.Label(top, text="Preset", style="Card.TLabel").grid(row=0, column=0, padx=4, sticky="w")
        presets = ["Beginner", "PE Deep", "Script Malware", "Webshell", "Fast Scan", "TrickBot Demo", "Loose Debug"]
        self.preset_combo = ttk.Combobox(top, values=presets, state="readonly", textvariable=self.app.state.var_current_preset, width=18)
        self.preset_combo.grid(row=0, column=1, padx=4, sticky="ew")
        self.preset_combo.bind("<<ComboboxSelected>>", lambda _e: self.apply_selected_preset())
        ttk.Label(top, text="DB Mode", style="Card.TLabel").grid(row=0, column=2, padx=4, sticky="w")
        ttk.Combobox(top, values=["Full quality DB", "Fast strings DB", "Fast no-opcodes DB"], state="readonly", textvariable=self.app.state.var_db_mode, width=20).grid(row=0, column=3, padx=4, sticky="ew")
        ttk.Button(top, text=self.app.t("generate.preview"), command=self.update_command_preview).grid(row=0, column=4, padx=4)
        ttk.Button(top, text=self.app.t("generate.generate"), command=self.run_generate, style="Primary.TButton").grid(row=0, column=5, padx=4, sticky="e")
        ttk.Button(top, text=self.app.t("generate.stop"), command=self.app.runner.stop, style="Danger.TButton").grid(row=0, column=6, padx=4)
        self.preset_desc = ttk.Label(top, text="", style="Muted.TLabel", wraplength=980)
        self.preset_desc.grid(row=1, column=0, columnspan=7, sticky="w", pady=(8, 0))

    def build_paths_and_params(self, parent, row):
        body = ttk.Frame(parent, style="App.TFrame")
        body.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)
        s = self.app.state

        basic = ttk.LabelFrame(body, text=self.app.t("generate.basic"), padding=12)
        basic.grid(row=0, column=0, sticky="new", padx=(0, 6))
        basic.columnconfigure(1, weight=1)
        path_row(basic, 0, "Malware/sample folder (-m)", s.var_malware, self.app.root_dir, "folder")
        path_row(basic, 1, "Output YARA file (-o)", s.var_output, self.app.root_dir, "file_save_yar")
        path_row(basic, 2, "String export folder (-e)", s.var_string_export_dir, self.app.root_dir, "folder")
        path_row(basic, 3, "Author (-a)", s.var_author, self.app.root_dir)
        path_row(basic, 4, "Reference (-r)", s.var_reference, self.app.root_dir)

        adv = ttk.LabelFrame(body, text=self.app.t("generate.advanced"), padding=12)
        adv.grid(row=0, column=1, sticky="new", padx=(6, 0))
        adv.columnconfigure(1, weight=1)
        for r, (label, var) in enumerate([
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
            path_row(adv, r, label, var, self.app.root_dir, "file_open" if "Identifier" in label else None, tooltip=PARAM_TOOLTIPS.get(label, ""))
        self.advanced_widgets.append(adv)

    def _flag(self, parent, row, col, text, var, advanced=False):
        cb = ttk.Checkbutton(parent, text=text, variable=var, command=self.update_command_preview)
        cb.grid(row=row, column=col, sticky="w", padx=14, pady=8, ipadx=4)
        ToolTip(cb, OPTION_TOOLTIPS.get(text, ""))
        if advanced:
            self.advanced_widgets.append(cb)
        return cb

    def build_flags(self, parent, row):
        s = self.app.state
        flags = ttk.LabelFrame(parent, text="Options", padding=12)
        flags.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        flags.columnconfigure(0, weight=1)

        common = ttk.LabelFrame(flags, text="Common", padding=8)
        common.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        for c in range(4):
            common.columnconfigure(c, weight=1, uniform="flag")
        common_flags = [
            ("--score", s.var_score),
            ("--strings", s.var_strings),
            ("--oe", s.var_oe),
            ("--opcodes", s.var_opcodes),
            ("--excludegood", s.var_excludegood),
            ("--nosuper", s.var_nosuper),
            ("--nosimple", s.var_nosimple),
            ("--noextras", s.var_noextras),
        ]
        for i, (txt, var) in enumerate(common_flags):
            self._flag(common, i // 4, i % 4, txt, var)

        advanced_box = ttk.LabelFrame(flags, text="Advanced / risky flags", padding=8)
        advanced_box.grid(row=1, column=0, sticky="ew")
        for c in range(4):
            advanced_box.columnconfigure(c, weight=1, uniform="flag2")
        adv_flags = [
            ("--nomagic", s.var_nomagic),
            ("--nofilesize", s.var_nofilesize),
            ("--globalrule", s.var_globalrule),
            ("--dropzone", s.var_dropzone),
            ("--nr", s.var_nr),
            ("--debug", s.var_debug),
            ("--trace", s.var_trace),
            ("--inverse", s.var_inverse),
            ("--nodirname", s.var_nodirname),
            ("--noscorefilter", s.var_noscorefilter),
        ]
        for i, (txt, var) in enumerate(adv_flags):
            self._flag(advanced_box, i // 4, i % 4, txt, var)
        self.advanced_widgets.append(advanced_box)

        note = ttk.Label(flags, text="Basic mode ẩn Advanced/risky flags để tránh vô tình tạo command chậm hoặc rule yếu. Bật Advanced trên topbar để xem toàn bộ.", style="Muted.TLabel", wraplength=980)
        note.grid(row=2, column=0, sticky="w", pady=(8, 0))

    def build_command_box(self, parent, row):
        s = self.app.state
        cmd_box = ttk.LabelFrame(parent, text="Command Preview", padding=8)
        cmd_box.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        cmd_box.columnconfigure(0, weight=1)
        ttk.Entry(cmd_box, textvariable=s.var_command_preview, font=("Consolas", 9)).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ttk.Button(cmd_box, text="Save .bat", command=self.save_bat).grid(row=0, column=1, padx=3)
        ttk.Button(cmd_box, text="Save .sh", command=self.save_sh).grid(row=0, column=2, padx=3)

    def build_realtime_log(self, parent, row):
        """Thêm vùng hiển thị log realtime"""
        from tkinter.scrolledtext import ScrolledText
        import tkinter as tk
        
        log_frame = ttk.LabelFrame(parent, text="Tiến trình thực thi (Realtime Log)", padding=8)
        log_frame.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        # Tạo ScrolledText để hiển thị log
        self.realtime_log = ScrolledText(
            log_frame, 
            wrap="word", 
            font=("Consolas", 9), 
            height=15,
            background="#1e1e1e",  # Dark background
            foreground="#ffffff",  # White text
            insertbackground="#ffffff"  # White cursor
        )
        self.realtime_log.grid(row=0, column=0, sticky="nsew", pady=(0, 8))
        
        # Buttons để control log
        button_frame = ttk.Frame(log_frame)
        button_frame.grid(row=1, column=0, sticky="ew")
        
        ttk.Button(button_frame, text="Xóa log", command=self.clear_realtime_log).pack(side="left", padx=(0, 8))
        ttk.Button(button_frame, text="Lưu log", command=self.save_realtime_log).pack(side="left", padx=(0, 8))
        
        # Checkbox để auto-scroll
        self.auto_scroll_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(button_frame, text="Auto scroll", variable=self.auto_scroll_var).pack(side="left")
        
        # Khởi tạo log với thông báo
        self.realtime_log.insert("end", "=== YarGen GUI - Realtime Log ===\n")
        self.realtime_log.insert("end", "Sẵn sàng tạo YARA rules. Bấm 'Generate' để bắt đầu.\n\n")
        self.realtime_log.see("end")

    def setup_trace_listeners(self):
        s = self.app.state
        variables = [
            s.var_python, s.var_yargen, s.var_malware, s.var_output, s.var_string_export_dir,
            s.var_author, s.var_reference, s.var_license, s.var_prefix, s.var_identifier_file,
            s.var_min_len, s.var_min_score, s.var_high_score, s.var_super_min, s.var_max_len,
            s.var_rule_count, s.var_file_size, s.var_filesize_multiplier, s.var_opcode_num,
            s.var_db_mode, s.var_fast_max_part,
            s.var_score, s.var_strings, s.var_excludegood, s.var_nosimple, s.var_nomagic,
            s.var_nofilesize, s.var_globalrule, s.var_nosuper, s.var_dropzone, s.var_nr,
            s.var_oe, s.var_noextras, s.var_debug, s.var_trace, s.var_opcodes, s.var_inverse,
            s.var_nodirname, s.var_noscorefilter,
        ]
        for var in variables:
            var.trace_add("write", lambda *_: self.update_command_preview())

    def update_command_preview(self):
        cmd = build_generate_command(self.app.state)
        self.app.state.last_command = cmd
        command_str = quoted_command(cmd)
        self.app.state.var_command_preview.set(command_str)
        
        # Log command changes nếu có sự thay đổi đáng kể
        if hasattr(self, 'last_logged_command') and self.last_logged_command != command_str:
            if hasattr(self, 'realtime_log') and self.realtime_log:
                self.log_realtime("🔧 Command đã được cập nhật")
        self.last_logged_command = command_str
        
        self.app.refresh_status()

    def apply_selected_preset(self):
        self.apply_preset(self.app.state.var_current_preset.get())

    def apply_preset(self, name):
        s = self.app.state
        s.var_current_preset.set(name)
        
        # Log preset change
        if hasattr(self, 'realtime_log') and self.realtime_log:
            self.log_realtime(f"🎛️  Áp dụng preset: {name}")
        
        for v in [
            s.var_strings, s.var_opcodes, s.var_oe, s.var_noextras, s.var_nofilesize,
            s.var_nomagic, s.var_debug, s.var_trace, s.var_noscorefilter, s.var_nosuper,
            s.var_nosimple, s.var_excludegood, s.var_globalrule, s.var_dropzone, s.var_nr,
            s.var_inverse, s.var_nodirname,
        ]:
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
        self._refresh_scrollregion()

    def preflight(self):
        s = self.app.state
        yargen = normalize_path(s.var_yargen.get(), self.app.root_dir)
        sample = normalize_path(s.var_malware.get(), self.app.root_dir)
        output = normalize_path(s.var_output.get(), self.app.root_dir)
        
        self.log_realtime("🔍 Kiểm tra điều kiện trước khi chạy...")
        
        if not yargen.is_file():
            self.log_realtime(f"❌ Không tìm thấy yarGen.py: {yargen}")
            return False, f"yarGen.py not found: {yargen}"
        self.log_realtime(f"✅ yarGen.py: {yargen}")
        
        if not sample.is_dir():
            self.log_realtime(f"❌ Không tìm thấy thư mục sample: {sample}")
            return False, f"Sample folder not found: {sample}"
        
        files = [p for p in sample.rglob("*") if p.is_file()]
        if not files:
            self.log_realtime(f"❌ Thư mục sample rỗng: {sample}")
            return False, f"Sample folder is empty: {sample}"
        
        self.log_realtime(f"✅ Tìm thấy {len(files)} file trong thư mục sample")
        
        archives = [p for p in files if p.suffix.lower() in ARCHIVE_EXTENSIONS]
        if archives:
            self.log_realtime(f"⚠️  Phát hiện {len(archives)} file nén. Nên giải nén trước khi tạo rule cuối cùng.")
            self.app.screens["monitor"].log(f"[WARN] Archive files detected ({len(archives)}). Extract before final generation.\n")
        
        output.parent.mkdir(parents=True, exist_ok=True)
        self.log_realtime(f"✅ Output sẽ lưu tại: {output}")
        
        if s.var_strings.get():
            export_dir = normalize_path(s.var_string_export_dir.get(), self.app.root_dir)
            export_dir.mkdir(parents=True, exist_ok=True)
            self.log_realtime(f"✅ String export folder: {export_dir}")
        
        s.var_yargen.set(str(yargen)); s.var_malware.set(str(sample)); s.var_output.set(str(output))
        s.var_rule_to_test.set(str(output)); s.var_rule_score_file.set(str(output)); s.var_test_malware_dir.set(str(sample))
        
        self.log_realtime("✅ Tất cả điều kiện đã sẵn sàng!")
        return True, "OK"

    def fast_db_runtime_dir(self):
        s = self.app.state
        mode = s.var_db_mode.get()
        if mode == "Full quality DB":
            self.log_realtime("🗄️  Sử dụng Full quality DB - không cần tạo runtime DB")
            return None
            
        self.log_realtime(f"⚡ Chuẩn bị {mode} để tăng tốc...")
        workdir = normalize_path(s.var_workdir.get(), self.app.root_dir)
        
        try:
            max_part = max(1, int(s.var_fast_max_part.get() or "2"))
        except Exception:
            self.log_realtime("❌ Lỗi: Max DB part phải là số nguyên dương")
            messagebox.showerror("Invalid DB part", "Max DB part must be a positive integer, e.g. 1, 2, 3, 11.")
            return None
            
        source_dbs = workdir / "dbs"
        if not source_dbs.exists():
            self.log_realtime(f"❌ Không tìm thấy thư mục dbs: {source_dbs}")
            messagebox.showerror("Missing DB folder", f"Cannot find dbs folder: {source_dbs}")
            return None
            
        self.log_realtime(f"📦 Tạo runtime DB với {max_part} parts...")
        prefixes = ["good-strings-part"] if mode == "Fast strings DB" else ["good-strings-part", "good-exports-part", "good-imphashes-part"]
        runtime = workdir / "_gui_runtime" / (mode.lower().replace(" ", "_") + f"_p{max_part}")
        runtime_dbs = runtime / "dbs"
        
        if runtime_dbs.exists():
            self.log_realtime("🧹 Xóa runtime DB cũ...")
            shutil.rmtree(runtime_dbs)
        runtime_dbs.mkdir(parents=True, exist_ok=True)
        
        if (workdir / "3rdparty").exists():
            self.log_realtime("📋 Copy 3rdparty files...")
            dst = runtime / "3rdparty"
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(workdir / "3rdparty", dst)
            
        self.log_realtime("🔄 Tạo DB files...")
        empty = gzip.compress(json.dumps({}).encode("utf-8"))
        copied_count = 0
        for prefix in EXPECTED_DB_PREFIXES:
            for part in range(1, max_part + 1):
                dst = runtime_dbs / f"{prefix}{part}.db"
                src = source_dbs / dst.name
                if prefix in prefixes and src.exists():
                    shutil.copy2(src, dst)
                    copied_count += 1
                else:
                    dst.write_bytes(empty)
                    
        self.log_realtime(f"✅ Runtime DB sẵn sàng: {copied_count} DB files được copy")
        self.log_realtime(f"📂 Runtime directory: {runtime}")
        self.app.screens["monitor"].log(f"[PERF] Runtime DB mode={mode}, cwd={runtime}\n")
        return runtime


    def _start_waiting_video_on_monitor(self):
        """Switch to monitor screen and start the waiting video panel."""
        try:
            monitor = self.app.screens.get("monitor") if hasattr(self.app, "screens") else None
            if monitor and hasattr(monitor, "start_generate_waiting_media"):
                # Show the monitor so the user can see log + progress + video immediately.
                try:
                    self.app.show_screen("monitor")
                except Exception:
                    pass
                monitor.start_generate_waiting_media()
        except Exception:
            # Video is a UX helper, never block rule generation because of it.
            pass


    def run_generate(self):
        ok, msg = self.preflight()
        if not ok:
            messagebox.showerror("Cannot generate", msg)
            return
        runtime = self.fast_db_runtime_dir()
        if self.app.state.var_db_mode.get() != "Full quality DB" and runtime is None:
            return
        
        # Log bắt đầu quá trình
        self.log_realtime("🚀 Bắt đầu tạo YARA rules...")
        self.log_realtime(f"📁 Sample folder: {self.app.state.var_malware.get()}")
        self.log_realtime(f"📄 Output file: {self.app.state.var_output.get()}")
        self.log_realtime(f"⚙️  Command: {quoted_command(build_generate_command(self.app.state))}")
        self.log_realtime("=" * 60)
        
        self._start_waiting_video_on_monitor()
        self.app.runner.run_command(build_generate_command(self.app.state), "Generate YARA rules", cwd=runtime, task="generate")

    def log_realtime(self, message):
        """Thêm message vào realtime log với timestamp"""
        import datetime
        if hasattr(self, 'realtime_log'):
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            formatted_message = f"[{timestamp}] {message}\n"
            
            self.realtime_log.insert("end", formatted_message)
            
            # Auto scroll nếu được bật
            if self.auto_scroll_var.get():
                self.realtime_log.see("end")
            
            # Update UI
            self.realtime_log.update_idletasks()

    def clear_realtime_log(self):
        """Xóa nội dung realtime log"""
        if hasattr(self, 'realtime_log'):
            self.realtime_log.delete("1.0", "end")
            self.log_realtime("Log đã được xóa.")

    def save_realtime_log(self):
        """Lưu realtime log ra file"""
        if hasattr(self, 'realtime_log'):
            import datetime
            from pathlib import Path
            
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file = Path(self.app.state.var_workdir.get()) / f"yargen_log_{timestamp}.txt"
            
            content = self.realtime_log.get("1.0", "end-1c")
            log_file.write_text(content, encoding="utf-8")
            
            self.log_realtime(f"💾 Log đã lưu: {log_file}")
            messagebox.showinfo("Đã lưu", f"Log đã được lưu vào:\n{log_file}")

    def on_generate_start(self):
        """Callback khi bắt đầu generate"""
        self.log_realtime("🚀 Quá trình tạo YARA rules đã bắt đầu...")
        self.log_realtime("⏳ Đang xử lý, vui lòng đợi...")

    def on_generate_progress(self, progress_info):
        """Callback để hiển thị tiến trình"""
        if "Processing" in progress_info:
            self.log_realtime(f"🔄 {progress_info}")
        elif "Analyzing" in progress_info:
            self.log_realtime(f"🔍 {progress_info}")
        elif "Generated" in progress_info:
            self.log_realtime(f"📝 {progress_info}")


    def after_generate_success(self):
        """Called by core.runner after generate exits successfully.

        Keep this method because runner.py calls screens["generate"].after_generate_success.
        It also stops the waiting video on the Monitor screen and optionally runs validation.
        """
        try:
            monitor = self.app.screens.get("monitor") if hasattr(self.app, "screens") else None
            if monitor and hasattr(monitor, "stop_generate_waiting_media"):
                monitor.stop_generate_waiting_media()
            if monitor and hasattr(monitor, "log"):
                monitor.log("\n[POST] Generate completed.\n")
        except Exception:
            pass

        try:
            if self.app.state.var_auto_validate.get():
                self.app.screens["validate"].validate_rule_file(Path(self.app.state.var_output.get()), show_popup=False)
        except Exception:
            pass

    def save_bat(self):
        out = Path(self.app.state.var_workdir.get()) / "run_yargen_command.bat"
        out.write_text(quoted_command(self.app.state.last_command) + "\n", encoding="utf-8")
        self.log_realtime(f"💾 Đã lưu batch file: {out}")
        messagebox.showinfo("Saved", str(out))

    def save_sh(self):
        out = Path(self.app.state.var_workdir.get()) / "run_yargen_command.sh"
        out.write_text("#!/usr/bin/env bash\n" + quoted_command(self.app.state.last_command) + "\n", encoding="utf-8")
        self.log_realtime(f"💾 Đã lưu shell script: {out}")
        messagebox.showinfo("Saved", str(out))
