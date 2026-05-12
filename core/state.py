# -*- coding: utf-8 -*-
import sys
import tkinter as tk
from pathlib import Path

class AppState:
    def __init__(self, root: tk.Tk, root_dir: Path, settings):
        rd = root_dir
        self.var_mode = tk.StringVar(root, value=settings.get("mode", "basic"))
        self.var_current_preset = tk.StringVar(root, value="Beginner")
        self.var_run_status = tk.StringVar(root, value="Idle")
        self.var_env_status = tk.StringVar(root, value="Unknown")

        self.var_python = tk.StringVar(root, value=sys.executable)
        self.var_workdir = tk.StringVar(root, value=str(rd))
        self.var_yargen = tk.StringVar(root, value=str(rd / "yarGen.py"))

        self.var_malware = tk.StringVar(root, value=str(rd / "samples"))
        self.var_output = tk.StringVar(root, value=str(rd / "rules" / "yargen_rules.yar"))
        self.var_string_export_dir = tk.StringVar(root, value=str(rd / "strings_out"))
        self.var_author = tk.StringVar(root, value="yarGen GUI")
        self.var_reference = tk.StringVar(root, value="")
        self.var_license = tk.StringVar(root, value="")
        self.var_prefix = tk.StringVar(root, value="Malware family rule")
        self.var_identifier_file = tk.StringVar(root, value="")

        self.var_family_name = tk.StringVar(root, value="malware_family")
        self.var_family_goal = tk.StringVar(root, value="Tạo chữ ký YARA từ đặc trưng chung của một họ mã độc")
        self.var_min_family_samples = tk.StringVar(root, value="2")

        self.var_min_len = tk.StringVar(root, value="8")
        self.var_min_score = tk.StringVar(root, value="0")
        self.var_high_score = tk.StringVar(root, value="30")
        self.var_super_min = tk.StringVar(root, value="5")
        self.var_max_len = tk.StringVar(root, value="128")
        self.var_rule_count = tk.StringVar(root, value="20")
        self.var_file_size = tk.StringVar(root, value="10")
        self.var_filesize_multiplier = tk.StringVar(root, value="3")
        self.var_opcode_num = tk.StringVar(root, value="3")

        self.var_score = tk.BooleanVar(root, value=True)
        self.var_strings = tk.BooleanVar(root, value=False)
        self.var_excludegood = tk.BooleanVar(root, value=False)
        self.var_nosimple = tk.BooleanVar(root, value=False)
        self.var_nomagic = tk.BooleanVar(root, value=False)
        self.var_nofilesize = tk.BooleanVar(root, value=False)
        self.var_globalrule = tk.BooleanVar(root, value=False)
        self.var_nosuper = tk.BooleanVar(root, value=False)
        self.var_dropzone = tk.BooleanVar(root, value=False)
        self.var_nr = tk.BooleanVar(root, value=False)
        self.var_oe = tk.BooleanVar(root, value=False)
        self.var_noextras = tk.BooleanVar(root, value=False)
        self.var_ai = tk.BooleanVar(root, value=False)
        self.var_debug = tk.BooleanVar(root, value=False)
        self.var_trace = tk.BooleanVar(root, value=False)
        self.var_opcodes = tk.BooleanVar(root, value=False)
        self.var_inverse = tk.BooleanVar(root, value=False)
        self.var_nodirname = tk.BooleanVar(root, value=False)
        self.var_noscorefilter = tk.BooleanVar(root, value=False)

        self.var_db_mode = tk.StringVar(root, value=settings.get("default_db_mode", "Full quality DB"))
        self.var_fast_max_part = tk.StringVar(root, value="2")

        self.var_goodware_dir = tk.StringVar(root, value="")
        self.var_goodware_identifier = tk.StringVar(root, value="")
        self.var_rule_to_test = tk.StringVar(root, value=str(rd / "rules" / "yargen_rules.yar"))
        self.var_test_malware_dir = tk.StringVar(root, value=str(rd / "samples"))
        self.var_test_goodware_dir = tk.StringVar(root, value="")
        self.var_report_dir = tk.StringVar(root, value=str(rd / "reports"))
        self.var_auto_validate = tk.BooleanVar(root, value=True)

        self.var_analyzer_dir = tk.StringVar(root, value=str(rd / "samples"))
        self.var_cluster_threshold = tk.StringVar(root, value="0.35")
        self.var_cluster_output_dir = tk.StringVar(root, value=str(rd / "clusters"))

        self.var_db_eval_selected = tk.StringVar(root, value="")
        self.var_command_preview = tk.StringVar(root, value="")

        self.progress_stage = tk.StringVar(root, value="Idle")
        self.progress_percent = tk.DoubleVar(root, value=0.0)
        self.progress_detail = tk.StringVar(root, value="No process running.")
        self.progress_db_loaded = 0
        self.progress_samples_done = 0
        self.progress_simple_rules = 0
        self.progress_super_rules = 0

        self.var_rule_score_file = tk.StringVar(root, value=str(rd / "rules" / "yargen_rules.yar"))

        self.last_command = []
        self.last_test_results = []
        self.last_rule_score_rows = []
        self.last_rule_score_markdown = ""
        self.sample_features = []
        self.clusters = []
        self.last_exit_code = None
        self.current_task = ""
