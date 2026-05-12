# -*- coding: utf-8 -*-
import os, re, shlex, subprocess, sys
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, ttk

def open_path(path: Path):
    try:
        path = Path(path)
        if path.suffix and not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        elif not path.suffix:
            path.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            os.startfile(str(path))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except Exception:
        pass

def browse(var: tk.StringVar, mode: str, root_dir: Path):
    current = var.get() or str(root_dir)
    if mode == "folder":
        value = filedialog.askdirectory(initialdir=current if Path(current).exists() else str(root_dir))
    elif mode == "file_open":
        value = filedialog.askopenfilename(initialdir=str(Path(current).parent if current else root_dir))
    elif mode == "file_save_yar":
        value = filedialog.asksaveasfilename(
            initialdir=str(Path(current).parent if current else root_dir),
            defaultextension=".yar",
            filetypes=[("YARA rules", "*.yar *.yara"), ("All files", "*.*")]
        )
    else:
        value = ""
    if value:
        var.set(value)

def path_row(parent: ttk.Frame, row: int, label: str, var: tk.StringVar, root_dir: Path, mode: str | None = None):
    ttk.Label(parent, text=label, style="Card.TLabel").grid(row=row, column=0, sticky="w", pady=4)
    entry = ttk.Entry(parent, textvariable=var)
    entry.grid(row=row, column=1, sticky="ew", padx=(8, 4), pady=4)
    if mode:
        ttk.Button(parent, text="Browse", command=lambda: browse(var, mode, root_dir)).grid(row=row, column=2, sticky="ew", pady=4)
    return entry

def normalize_path(value: str, base: Path) -> Path:
    raw = (value or "").strip().strip('"')
    if not raw:
        return base
    p = Path(raw).expanduser()
    if not p.is_absolute():
        p = base / p
    try:
        return p.resolve(strict=False)
    except Exception:
        return p.absolute()

def safe_identifier(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_]+", "_", value.strip())
    value = re.sub(r"_+", "_", value).strip("_")
    return value or "malware_family"

def quoted_command(cmd: list[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(cmd)
    return " ".join(shlex.quote(c) for c in cmd)
