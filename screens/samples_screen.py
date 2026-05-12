# -*- coding: utf-8 -*-
import hashlib, mimetypes, re, shutil
from pathlib import Path
from tkinter import ttk, messagebox
from core.config import ARCHIVE_EXTENSIONS
from core.utils import path_row, normalize_path

class SamplesScreen(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, style="App.TFrame")
        self.app = app
        self.build()

    def refresh_text(self): pass
    def on_mode_changed(self): pass
    def on_show(self): pass

    def build(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)
        ttk.Label(self, text=self.app.t("samples.title"), style="Title.TLabel").grid(row=0, column=0, sticky="w")
        box = ttk.Frame(self, style="Card.TFrame", padding=12)
        box.grid(row=1, column=0, sticky="ew", pady=8)
        box.columnconfigure(1, weight=1)
        path_row(box, 0, "Malware sample folder", self.app.state.var_analyzer_dir, self.app.root_dir, "folder")
        path_row(box, 1, "Cluster threshold", self.app.state.var_cluster_threshold, self.app.root_dir)
        path_row(box, 2, "Cluster output folder", self.app.state.var_cluster_output_dir, self.app.root_dir, "folder")
        actions = ttk.Frame(box, style="Surface.TFrame")
        actions.grid(row=3, column=1, sticky="w", pady=8)
        ttk.Button(actions, text=self.app.t("samples.scan"), command=self.scan).pack(side="left", padx=4)
        ttk.Button(actions, text=self.app.t("samples.cluster"), command=self.cluster).pack(side="left", padx=4)
        ttk.Button(actions, text=self.app.t("samples.gen_cluster"), command=self.generate_rule_per_cluster).pack(side="left", padx=4)
        self.summary = ttk.Label(self, text="No scan yet.", style="Muted.TLabel")
        self.summary.grid(row=2, column=0, sticky="w", pady=4)
        self.tree = ttk.Treeview(self, columns=("file", "type", "size", "md5", "sha256", "status"), show="headings")
        for col, width in [("file",240),("type",90),("size",90),("md5",220),("sha256",360),("status",160)]:
            self.tree.heading(col, text=col); self.tree.column(col, width=width, anchor="w")
        self.tree.grid(row=3, column=0, sticky="nsew")

    def hash_file(self, path: Path):
        md5 = hashlib.md5(); sha256 = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                md5.update(chunk); sha256.update(chunk)
        return md5.hexdigest(), sha256.hexdigest()

    def file_type(self, path: Path):
        try: head = path.read_bytes()[:8]
        except Exception: head = b""
        if head.startswith(b"MZ"): return "PE"
        if head.startswith(b"\x7fELF"): return "ELF"
        if head.startswith(b"PK"): return "Archive/ZIP"
        return mimetypes.guess_type(str(path))[0] or path.suffix.lower() or "unknown"

    def strings_set(self, path: Path):
        try: data = path.read_bytes()[:5 * 1024 * 1024]
        except Exception: return set()
        strings = set()
        for m in re.finditer(rb"[\x20-\x7e]{5,}", data):
            raw = m.group(0).decode("ascii", errors="ignore").lower()
            strings.add(raw[:160])
            for token in re.split(r"[^a-z0-9_./:@$%+-]+", raw):
                if len(token) >= 5: strings.add(token[:120])
            if len(strings) > 4000: break
        return strings

    def scan(self):
        folder = normalize_path(self.app.state.var_analyzer_dir.get(), self.app.root_dir)
        for row in self.tree.get_children(): self.tree.delete(row)
        self.app.state.sample_features = []
        files = [p for p in folder.rglob("*") if p.is_file()] if folder.exists() else []
        archives = pe = scripts = total = 0
        for p in files:
            try:
                total += p.stat().st_size
                md5, sha256 = self.hash_file(p)
                ftype = self.file_type(p)
                if p.suffix.lower() in ARCHIVE_EXTENSIONS: archives += 1
                if ftype == "PE": pe += 1
                if p.suffix.lower() in {".ps1",".js",".vbs",".bat",".cmd",".php",".asp",".aspx",".jsp"}: scripts += 1
                status = "Archive - extract first" if p.suffix.lower() in ARCHIVE_EXTENSIONS else "OK"
                rec = {"path": p, "name": p.name, "size": p.stat().st_size, "type": ftype, "md5": md5, "sha256": sha256, "strings": self.strings_set(p)}
                self.app.state.sample_features.append(rec)
                self.tree.insert("", "end", values=(p.name, ftype, p.stat().st_size, md5, sha256, status))
            except Exception as e:
                self.tree.insert("", "end", values=(p.name, "error", "", "", "", str(e)))
        suggested = "Script Malware" if scripts > pe else "Beginner/PE Deep"
        self.summary.configure(text=f"Total={len(files)} | PE={pe} | Scripts={scripts} | Archives={archives} | Size={total/(1024*1024):.2f}MB | Suggested={suggested}")

    def sim(self, a, b):
        return len(a & b) / len(a | b) if a and b else 0.0

    def cluster(self):
        if not self.app.state.sample_features: self.scan()
        try: threshold = float(self.app.state.var_cluster_threshold.get())
        except Exception: threshold = 0.35
        used = set(); clusters = []; feats = self.app.state.sample_features
        for i, rec in enumerate(feats):
            if i in used: continue
            group = [i]; used.add(i)
            for j in range(i+1, len(feats)):
                if j in used: continue
                if self.sim(rec["strings"], feats[j]["strings"]) >= threshold:
                    group.append(j); used.add(j)
            if len(group) >= 2:
                clusters.append([feats[k]["path"] for k in group])
        self.app.state.clusters = clusters
        self.summary.configure(text=self.summary.cget("text") + f" | Clusters={len(clusters)}")

    def generate_rule_per_cluster(self):
        if not self.app.state.clusters: self.cluster()
        if not self.app.state.clusters:
            messagebox.showwarning("No clusters", "No cluster with at least 2 files.")
            return
        out_base = normalize_path(self.app.state.var_cluster_output_dir.get(), self.app.root_dir)
        out_base.mkdir(parents=True, exist_ok=True)
        for idx, group in enumerate(self.app.state.clusters, 1):
            cdir = out_base / f"cluster_{idx:02d}"
            cdir.mkdir(parents=True, exist_ok=True)
            for src in group:
                dst = cdir / src.name
                if not dst.exists(): shutil.copy2(src, dst)
        self.app.state.var_malware.set(str(out_base / "cluster_01"))
        self.app.state.var_output.set(str(Path(self.app.state.var_workdir.get()) / "rules" / "clusters" / "cluster_01.yar"))
        self.app.screens["generate"].update_command_preview()
        self.app.show_screen("generate")
