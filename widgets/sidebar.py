# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import ttk
from widgets.wuxia_theme import NAV_ICONS


class Sidebar(ttk.Frame):
    """Left navigation redesigned as a small 'YARA Kiếm Các' pavilion."""

    def __init__(self, app, items):
        super().__init__(app, style="Sidebar.TFrame", padding=(8, 12))
        self.app = app
        self.items = items
        self.buttons = {}
        self.active_key = None
        self.banner = None
        self.build()

    def build(self):
        self.banner = tk.Canvas(self, width=205, height=92, highlightthickness=0, bg="#101B33")
        self.banner.pack(fill="x", pady=(0, 10))
        self._draw_banner()
        self.banner.bind("<Configure>", lambda _e: self._draw_banner())
        ttk.Label(self, text="YARA Kiếm Các", style="SidebarHeader.TLabel").pack(fill="x")
        ttk.Label(self, text="Rèn rule • soi IOC • xuất báo cáo", style="SidebarHint.TLabel").pack(fill="x", pady=(0, 8))
        for key, label_key in self.items:
            btn = ttk.Button(
                self,
                text=self._label_for(key, label_key, active=False),
                style="Sidebar.TButton",
                command=lambda k=key: self.app.show_screen(k),
            )
            btn.pack(fill="x", pady=2)
            self.buttons[key] = (btn, label_key)
        ttk.Label(self, text="☁ Static analysis only", style="SidebarHint.TLabel").pack(fill="x", side="bottom", pady=(12, 0))

    def _draw_banner(self):
        if not self.banner:
            return
        c = self.banner
        c.delete("all")
        w = max(c.winfo_width(), 205)
        h = max(c.winfo_height(), 92)
        c.create_rectangle(0, 0, w, h, fill="#101B33", outline="#20385A")
        for i in range(4):
            x = i * w / 3 - 45
            c.create_polygon(x, h - 6, x + 60, 32 + i * 4, x + 130, h - 6, fill="#172A45", outline="", smooth=True)
        c.create_text(18, 30, text="☯", anchor="w", fill="#7DD3FC", font=("Segoe UI", 24, "bold"))
        c.create_text(58, 30, text="YARA", anchor="w", fill="#F8FAFC", font=("Segoe UI", 20, "bold"))
        c.create_text(60, 58, text="Wuxia Forge", anchor="w", fill="#9CC9EF", font=("Segoe UI", 10, "bold italic"))
        c.create_line(16, 78, w - 18, 78, fill="#315273", width=2)
        c.create_line(18, 78, w * 0.62, 78, fill="#38BDF8", width=2)

    def _label_for(self, key, label_key, active=False):
        icon = NAV_ICONS.get(key, "•")
        marker = "▸" if active else " "
        return f"{marker} {icon}  {self.app.t(label_key)}"

    def refresh_labels(self):
        for key, (btn, label_key) in self.buttons.items():
            active = key == self.active_key
            btn.configure(text=self._label_for(key, label_key, active=active), style="SidebarActive.TButton" if active else "Sidebar.TButton")

    def set_active(self, key):
        self.active_key = key
        self.refresh_labels()
