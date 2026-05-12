# -*- coding: utf-8 -*-
from pathlib import Path
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
from core.utils import path_row, safe_identifier
from core.config import RELEVANT_EXTENSIONS

class FamilyScreen(ttk.Frame):
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
        actions = ttk.Frame(box, style="Surface.TFrame")
        actions.grid(row=7, column=1, sticky="w", pady=8)
        ttk.Button(actions, text=self.app.t("family.apply"), command=self.apply_preset).pack(side="left", padx=4)
        ttk.Button(actions, text=self.app.t("family.analyze"), command=self.analyze_folder).pack(side="left", padx=4)
        ttk.Button(actions, text=self.app.t("family.identifier"), command=self.create_identifier).pack(side="left", padx=4)
        self.report = ScrolledText(self, wrap="word")
        self.report.grid(row=2, column=0, sticky="nsew")
        self.report.insert("end", "Family rule = rule built from common features across multiple malware samples.\n")

    def apply_preset(self):
        s = self.app.state
        family = safe_identifier(s.var_family_name.get())
        s.var_malware.set(str(Path(s.var_workdir.get()) / "samples" / family))
        s.var_output.set(str(Path(s.var_workdir.get()) / "rules" / f"{family}.yar"))
        s.var_string_export_dir.set(str(Path(s.var_workdir.get()) / "strings_out" / family))
        s.var_prefix.set(f"Malware family {family}")
        s.var_score.set(True); s.var_strings.set(True)
        s.var_nosuper.set(False); s.var_nosimple.set(False)
        s.var_min_score.set("0"); s.var_high_score.set("10"); s.var_super_min.set("2")
        self.app.screens["generate"].update_command_preview()
        self.app.show_screen("generate")

    def create_identifier(self):
        family = safe_identifier(self.app.state.var_family_name.get())
        out = Path(self.app.state.var_workdir.get()) / "identifier.txt"
        out.write_text(family + "\n", encoding="utf-8")
        self.app.state.var_identifier_file.set(str(out))
        messagebox.showinfo("Identifier created", str(out))

    def analyze_folder(self):
        folder = Path(self.app.state.var_malware.get())
        self.report.delete("1.0", "end")
        self.report.insert("end", f"Folder: {folder}\n")
        if not folder.exists():
            self.report.insert("end", "[MISSING] Folder not found.\n")
            return
        files = [p for p in folder.rglob("*") if p.is_file()]
        relevant = [p for p in files if p.suffix.lower() in RELEVANT_EXTENSIONS]
        self.report.insert("end", f"Total files: {len(files)}\nRelevant malware extensions: {len(relevant)}\n")
        ext_count = {}
        for p in files:
            ext_count[p.suffix.lower() or "<no_ext>"] = ext_count.get(p.suffix.lower() or "<no_ext>", 0) + 1
        for ext, count in sorted(ext_count.items(), key=lambda kv: (-kv[1], kv[0])):
            self.report.insert("end", f"- {ext}: {count}\n")
