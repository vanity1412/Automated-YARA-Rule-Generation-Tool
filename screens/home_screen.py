# -*- coding: utf-8 -*-
from tkinter import ttk
from widgets.cards import card
from widgets.wuxia_theme import WuxiaMiniMascot


class HomeScreen(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, style="App.TFrame")
        self.app = app
        self.build()

    def refresh_text(self):
        pass

    def on_mode_changed(self):
        pass

    def on_show(self):
        self.app.refresh_status()

    def build(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        self.hero = WuxiaMiniMascot(self, height=190)
        self.hero.grid(row=0, column=0, sticky="ew", pady=(0, 12))

        ttk.Label(self, text=self.app.t("home.title"), style="Title.TLabel").grid(row=1, column=0, sticky="w")
        ttk.Label(
            self,
            text="Workflow rèn chữ ký YARA từ sample family: setup → scan → generate → monitor → validate → analysis report.",
            style="AppMuted.TLabel",
        ).grid(row=1, column=0, sticky="e", pady=(4, 0))

        grid = ttk.Frame(self, style="App.TFrame")
        grid.grid(row=2, column=0, sticky="nsew", pady=(8, 0))
        for i in range(3):
            grid.columnconfigure(i, weight=1, uniform="home")
        for i in range(2):
            grid.rowconfigure(i, weight=1)
        items = [
            ("1. Setup", "Kiểm tra Python, yarGen.py, DB và dependencies trước khi luyện công.", "Check", lambda: self.app.show_screen("setup"), "🧭"),
            ("2. Samples", "Scan hash, file type, archive warning và gom cụm sample cùng family.", "Analyze", lambda: self.app.show_screen("samples"), "🧪"),
            ("3. Generate", "Chọn preset, build command và tạo YARA rule bằng engine gốc.", "Generate", lambda: self.app.show_screen("generate"), "⚔"),
            ("4. Monitor", "Theo dõi nội lực, stage, log và mascot trong lúc yarGen chạy lâu.", "Open", lambda: self.app.show_screen("monitor"), "☯"),
            ("5. Validate/Test", "Validate syntax, test malware/goodware và kiểm soát false positive.", "Test", lambda: self.app.show_screen("validate"), "🛡"),
            ("6. Analysis Suite", "Quality Gate, Rule Doctor, IOC, MITRE, Passport và report cuối.", "Open Suite", lambda: self.app.show_screen("analysis"), "🔮"),
        ]
        for idx, (title, sub, btn, cmd, icon) in enumerate(items):
            c = card(grid, title, sub, btn, cmd, icon=icon)
            c.grid(row=idx // 3, column=idx % 3, sticky="nsew", padx=6, pady=6)

        quick = ttk.LabelFrame(self, text="Quick cultivation flow", padding=12)
        quick.grid(row=3, column=0, sticky="ew", pady=12)
        quick.columnconfigure(0, weight=1)
        ttk.Label(
            quick,
            text="🏯 Setup  →  🧪 Samples  →  ⚔ Generate  →  ☯ Monitor  →  🛡 Validate/Test  →  🔮 Analysis Suite",
            style="Card.TLabel",
        ).grid(row=0, column=0, sticky="w")
        ttk.Button(quick, text="Start with Setup", command=lambda: self.app.show_screen("setup"), style="Primary.TButton").grid(row=0, column=1, sticky="e", padx=8)
