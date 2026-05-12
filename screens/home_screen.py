# -*- coding: utf-8 -*-
from tkinter import ttk
from widgets.cards import card

class HomeScreen(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, style="App.TFrame")
        self.app = app
        self.build()

    def refresh_text(self): pass
    def on_mode_changed(self): pass
    def on_show(self): self.app.refresh_status()

    def build(self):
        self.columnconfigure(0, weight=1)
        ttk.Label(self, text=self.app.t("home.title"), style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(self, text=self.app.t("home.subtitle"), style="Muted.TLabel").grid(row=1, column=0, sticky="w", pady=(0, 12))
        grid = ttk.Frame(self, style="App.TFrame")
        grid.grid(row=2, column=0, sticky="ew")
        for i in range(3):
            grid.columnconfigure(i, weight=1)
        items = [
            ("1. Setup", "Validate Python, yarGen.py, DBs and dependencies.", "Check", lambda: self.app.show_screen("setup")),
            ("2. Samples", "Scan folder, hashes, file types and cluster samples.", "Analyze", lambda: self.app.show_screen("samples")),
            ("3. Generate", "Choose preset and build YARA rules with yarGen.py.", "Generate", lambda: self.app.show_screen("generate")),
            ("4. Monitor", "Watch DB loading, extraction and rule generation.", "Open", lambda: self.app.show_screen("monitor")),
            ("5. Validate/Test", "Compile rule, scan malware and goodware folders.", "Test", lambda: self.app.show_screen("validate")),
            ("6. Reports", "Score YARA rules and export Markdown/CSV/HTML.", "Report", lambda: self.app.show_screen("reports")),
        ]
        for idx, (title, sub, btn, cmd) in enumerate(items):
            c = card(grid, title, sub, btn, cmd)
            c.grid(row=idx // 3, column=idx % 3, sticky="nsew", padx=6, pady=6)
        quick = ttk.LabelFrame(self, text="Quick Start", padding=12)
        quick.grid(row=3, column=0, sticky="ew", pady=12)
        ttk.Label(quick, text="Setup → Samples → Generate → Monitor → Validate/Test → Reports").pack(anchor="w")
        ttk.Button(quick, text="Start with Setup", command=lambda: self.app.show_screen("setup")).pack(anchor="w", pady=8)
