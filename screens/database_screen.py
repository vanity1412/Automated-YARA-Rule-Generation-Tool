# -*- coding: utf-8 -*-
"""Database screen.

Important design decision:
- Do NOT load all 44 DB files during Refresh.
- Some DB files are hundreds of MB; json.loads on all of them will freeze Tkinter.
- Refresh only shows existence/size/status.
- Evaluate selected DB only previews small/medium files; huge DBs are skipped safely.
"""
import gzip
import json
from pathlib import Path
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
from core.config import EXPECTED_DB_PREFIXES, MIN_DB_PARTS
from core.utils import path_row, open_path

MAX_PREVIEW_DB_SIZE_MB = 50

class DatabaseScreen(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, style="App.TFrame")
        self.app = app
        self.build()

    def refresh_text(self): pass
    def on_mode_changed(self): pass
    def on_show(self): self.refresh_db_status()

    def build(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)
        ttk.Label(self, text=self.app.t("database.title"), style="Title.TLabel").grid(row=0, column=0, sticky="w")
        gw = ttk.LabelFrame(self, text="Goodware DB operations", padding=12)
        gw.grid(row=1, column=0, sticky="ew", pady=8)
        gw.columnconfigure(1, weight=1)
        path_row(gw, 0, "Goodware folder (-g)", self.app.state.var_goodware_dir, self.app.root_dir, "folder")
        path_row(gw, 1, "Identifier (-i)", self.app.state.var_goodware_identifier, self.app.root_dir)
        actions = ttk.Frame(gw)
        actions.grid(row=2, column=1, sticky="w", pady=6)
        ttk.Button(actions, text="Create new DB", command=lambda: self.run_goodware_db("create")).pack(side="left", padx=4)
        ttk.Button(actions, text="Update DB", command=lambda: self.run_goodware_db("update")).pack(side="left", padx=4)
        ttk.Button(actions, text="Create with opcodes", command=lambda: self.run_goodware_db("create_opcodes")).pack(side="left", padx=4)

        top = ttk.Frame(self, style="App.TFrame")
        top.grid(row=2, column=0, sticky="ew", pady=6)
        ttk.Button(top, text=self.app.t("database.refresh"), command=self.refresh_db_status).pack(side="left", padx=4)
        ttk.Button(top, text=self.app.t("database.open"), command=lambda: open_path(Path(self.app.state.var_workdir.get()) / "dbs")).pack(side="left", padx=4)
        ttk.Button(top, text=self.app.t("database.evaluate"), command=self.evaluate_selected_db).pack(side="left", padx=4)

        self.tree = ttk.Treeview(self, columns=("file", "group", "size_mb", "entries", "status"), show="headings")
        for col, width in [("file",300), ("group",120), ("size_mb",100), ("entries",120), ("status",180)]:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor="w")
        self.tree.grid(row=3, column=0, sticky="nsew")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        self.detail = ScrolledText(self, height=9, wrap="word")
        self.detail.grid(row=4, column=0, sticky="ew", pady=6)

    def db_names(self):
        dbdir = Path(self.app.state.var_workdir.get()) / "dbs"
        names = set()
        for prefix in EXPECTED_DB_PREFIXES:
            for i in range(1, MIN_DB_PARTS + 1):
                names.add(f"{prefix}{i}.db")
            if dbdir.exists():
                for p in dbdir.glob(f"{prefix}*.db"):
                    names.add(p.name)
        return sorted(names)

    def group_from_name(self, name):
        for group in ["strings", "opcodes", "exports", "imphashes"]:
            if f"good-{group}-part" in name:
                return group
        return "custom"

    def refresh_db_status(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        dbdir = Path(self.app.state.var_workdir.get()) / "dbs"
        total_size = 0
        existing = 0
        for name in self.db_names():
            path = dbdir / name
            if not path.exists():
                self.tree.insert("", "end", values=(name, self.group_from_name(name), "", "", "missing"))
                continue
            existing += 1
            size_mb = path.stat().st_size / (1024 * 1024)
            total_size += path.stat().st_size
            status = "ok"
            if size_mb >= MAX_PREVIEW_DB_SIZE_MB:
                status = "large - preview skipped"
            self.tree.insert("", "end", values=(name, self.group_from_name(name), f"{size_mb:.2f}", "click Evaluate", status))
        self.detail.delete("1.0", "end")
        self.detail.insert("end", f"DB folder: {dbdir}\n")
        self.detail.insert("end", f"Existing DB files: {existing}\n")
        self.detail.insert("end", f"Total DB size: {total_size / (1024 * 1024):.2f} MB\n\n")
        self.detail.insert("end", "Refresh is intentionally lightweight: it does not load huge DB JSON into RAM.\n")
        self.detail.insert("end", f"Evaluate selected DB previews files smaller than {MAX_PREVIEW_DB_SIZE_MB} MB.\n")

    def on_select(self, _e=None):
        sel = self.tree.selection()
        if sel:
            self.app.state.var_db_eval_selected.set(self.tree.item(sel[0], "values")[0])

    def evaluate_selected_db(self):
        name = self.app.state.var_db_eval_selected.get()
        path = Path(self.app.state.var_workdir.get()) / "dbs" / name
        self.detail.delete("1.0", "end")
        self.detail.insert("end", f"File: {path}\n")
        if not path.exists():
            self.detail.insert("end", "Status: missing\n")
            return
        size_mb = path.stat().st_size / (1024 * 1024)
        self.detail.insert("end", f"Size: {size_mb:.2f} MB\n")
        if size_mb >= MAX_PREVIEW_DB_SIZE_MB:
            self.detail.insert("end", "\nThis DB is large, so preview is skipped to avoid freezing the GUI.\n")
            self.detail.insert("end", "Use it normally during yarGen generation, or reduce DB mode for fast demo.\n")
            return
        try:
            with gzip.GzipFile(path, "rb") as fh:
                data = json.loads(fh.read().decode("utf-8", errors="replace"))
            entries = len(data) if hasattr(data, "__len__") else "?"
            self.detail.insert("end", f"Entries: {entries}\nPreview:\n")
            items = list(data.items())[:25] if isinstance(data, dict) else data[:25]
            for i, item in enumerate(items, 1):
                self.detail.insert("end", f"{i}. {item!r}\n")
        except Exception as e:
            self.detail.insert("end", f"Error: {e}\n")

    def run_goodware_db(self, mode):
        s = self.app.state
        if not s.var_goodware_dir.get():
            messagebox.showwarning("Goodware DB", "Please select a goodware folder first.")
            return
        cmd = [s.var_python.get(), "-W", "ignore", s.var_yargen.get(), "-g", s.var_goodware_dir.get()]
        if mode == "create": cmd.append("-c")
        if mode == "update": cmd.append("-u")
        if s.var_goodware_identifier.get(): cmd += ["-i", s.var_goodware_identifier.get()]
        if mode == "create_opcodes": cmd.append("--opcodes")
        self.app.runner.run_command(cmd, f"Goodware DB operation: {mode}", cwd=Path(s.var_workdir.get()), task="goodware_db")
