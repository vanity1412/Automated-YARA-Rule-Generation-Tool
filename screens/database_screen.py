# -*- coding: utf-8 -*-
import gzip, json
from pathlib import Path
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from core.config import EXPECTED_DB_PREFIXES, MIN_DB_PARTS
from core.utils import path_row, open_path

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
        self.tree = ttk.Treeview(self, columns=("file","group","size","entries","status"), show="headings")
        for col, width in [("file",300),("group",120),("size",100),("entries",120),("status",120)]:
            self.tree.heading(col, text=col); self.tree.column(col, width=width, anchor="w")
        self.tree.grid(row=3, column=0, sticky="nsew")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.detail = ScrolledText(self, height=8, wrap="word")
        self.detail.grid(row=4, column=0, sticky="ew", pady=6)

    def db_names(self):
        dbdir = Path(self.app.state.var_workdir.get()) / "dbs"
        names = set()
        for prefix in EXPECTED_DB_PREFIXES:
            for i in range(1, MIN_DB_PARTS+1): names.add(f"{prefix}{i}.db")
            if dbdir.exists():
                for p in dbdir.glob(f"{prefix}*.db"): names.add(p.name)
        return sorted(names)

    def group_from_name(self, name):
        for group in ["strings","opcodes","exports","imphashes"]:
            if f"good-{group}-part" in name: return group
        return "custom"

    def refresh_db_status(self):
        for row in self.tree.get_children(): self.tree.delete(row)
        dbdir = Path(self.app.state.var_workdir.get()) / "dbs"
        for name in self.db_names():
            path = dbdir / name
            if not path.exists():
                self.tree.insert("", "end", values=(name, self.group_from_name(name), "", "", "missing"))
            else:
                entries = "?"
                status = "ok"
                try:
                    with gzip.GzipFile(path, "rb") as fh: data = json.loads(fh.read())
                    entries = len(data) if hasattr(data, "__len__") else "?"
                except Exception: status = "error"
                self.tree.insert("", "end", values=(name, self.group_from_name(name), path.stat().st_size, entries, status))
        self.detail.delete("1.0", "end"); self.detail.insert("end", f"DB folder: {dbdir}\n")

    def on_select(self, _e=None):
        sel = self.tree.selection()
        if sel: self.app.state.var_db_eval_selected.set(self.tree.item(sel[0], "values")[0])

    def evaluate_selected_db(self):
        name = self.app.state.var_db_eval_selected.get()
        path = Path(self.app.state.var_workdir.get()) / "dbs" / name
        self.detail.delete("1.0", "end"); self.detail.insert("end", f"File: {path}\n")
        if not path.exists(): return
        try:
            with gzip.GzipFile(path, "rb") as fh: data = json.loads(fh.read())
            self.detail.insert("end", f"Entries: {len(data)}\nPreview:\n")
            items = list(data.items())[:25] if isinstance(data, dict) else data[:25]
            for i, item in enumerate(items,1): self.detail.insert("end", f"{i}. {item!r}\n")
        except Exception as e:
            self.detail.insert("end", f"Error: {e}\n")

    def run_goodware_db(self, mode):
        s = self.app.state
        if not s.var_goodware_dir.get(): return
        cmd = [s.var_python.get(), "-W", "ignore", s.var_yargen.get(), "-g", s.var_goodware_dir.get()]
        if mode == "create": cmd.append("-c")
        if mode == "update": cmd.append("-u")
        if s.var_goodware_identifier.get(): cmd += ["-i", s.var_goodware_identifier.get()]
        if mode == "create_opcodes": cmd.append("--opcodes")
        self.app.runner.run_command(cmd, f"Goodware DB operation: {mode}", cwd=Path(s.var_workdir.get()), task="goodware_db")
