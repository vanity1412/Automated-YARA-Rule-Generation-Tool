# -*- coding: utf-8 -*-
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from pathlib import Path
from core.utils import path_row, open_path
from core.validators import validate_environment

class SetupScreen(ttk.Frame):
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
        ttk.Label(self, text=self.app.t("setup.title"), style="Title.TLabel").grid(row=0, column=0, sticky="w")
        box = ttk.Frame(self, style="Card.TFrame", padding=12)
        box.grid(row=1, column=0, sticky="ew", pady=10)
        box.columnconfigure(1, weight=1)
        s = self.app.state
        path_row(box, 0, "Python executable", s.var_python, self.app.root_dir, "file_open")
        path_row(box, 1, "Working directory", s.var_workdir, self.app.root_dir, "folder")
        path_row(box, 2, "yarGen.py", s.var_yargen, self.app.root_dir, "file_open")
        actions = ttk.Frame(box, style="Surface.TFrame")
        actions.grid(row=3, column=1, sticky="w", pady=8)
        ttk.Button(actions, text=self.app.t("setup.validate"), command=self.validate).pack(side="left", padx=4)
        ttk.Button(actions, text=self.app.t("setup.install"), command=self.install_requirements).pack(side="left", padx=4)
        ttk.Button(actions, text=self.app.t("setup.update_db"), command=self.update_dbs).pack(side="left", padx=4)
        ttk.Button(actions, text=self.app.t("setup.open"), command=lambda: open_path(Path(s.var_workdir.get()))).pack(side="left", padx=4)
        self.tree = ttk.Treeview(self, columns=("item", "status", "detail"), show="headings", height=12)
        for col, width in [("item", 260), ("status", 100), ("detail", 700)]:
            self.tree.heading(col, text=col); self.tree.column(col, width=width, anchor="w")
        self.tree.grid(row=2, column=0, sticky="nsew", pady=6)
        self.info = ScrolledText(self, height=5, wrap="word")
        self.info.grid(row=3, column=0, sticky="ew")
        self.info.insert("end", "If dependency is missing, use Install requirements or run pip manually.\n")

    def validate(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        ok, rows = validate_environment(self.app.state)
        for row in rows:
            self.tree.insert("", "end", values=row)
        self.app.state.var_env_status.set("OK" if ok else "Warning")
        self.app.refresh_status()

    def install_requirements(self):
        s = self.app.state
        self.app.runner.run_command([s.var_python.get(), "-m", "pip", "install", "-r", str(Path(s.var_workdir.get()) / "requirements.txt")], "Install requirements", cwd=Path(s.var_workdir.get()), task="install")

    def update_dbs(self):
        s = self.app.state
        self.app.runner.run_command([s.var_python.get(), "-W", "ignore", s.var_yargen.get(), "--update"], "Download / update DBs", cwd=Path(s.var_workdir.get()), task="update_dbs")
