# -*- coding: utf-8 -*-
from tkinter import ttk

class Sidebar(ttk.Frame):
    def __init__(self, app, items):
        super().__init__(app, style="Sidebar.TFrame", padding=(8, 12))
        self.app = app
        self.items = items
        self.buttons = {}
        self.active_key = None
        self.build()

    def build(self):
        ttk.Label(self, text="YARA Builder", style="Sidebar.TButton").pack(fill="x", pady=(0, 8))
        for key, label_key in self.items:
            btn = ttk.Button(self, text=self.app.t(label_key), style="Sidebar.TButton", command=lambda k=key: self.app.show_screen(k))
            btn.pack(fill="x", pady=2)
            self.buttons[key] = (btn, label_key)

    def refresh_labels(self):
        for key, (btn, label_key) in self.buttons.items():
            prefix = "● " if key == self.active_key else "  "
            btn.configure(text=prefix + self.app.t(label_key))

    def set_active(self, key):
        self.active_key = key
        self.refresh_labels()
