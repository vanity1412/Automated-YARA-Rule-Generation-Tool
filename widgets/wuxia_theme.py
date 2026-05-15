# -*- coding: utf-8 -*-
"""Shared wuxia / kiếm hiệp visual helpers for the Tkinter GUI.

The helpers in this file are intentionally lightweight and pure Tkinter.  They
avoid external image files, internet access and additional dependencies, so the
student demo can run offline on Windows machines without packaging surprises.
"""
from __future__ import annotations

import math
import tkinter as tk
from tkinter import ttk


WUXIA = {
    "bg": "#F3F7FC",
    "surface": "#FFFFFF",
    "surface_2": "#F8FBFF",
    "line": "#D7E2F1",
    "line_dark": "#B8C7DC",
    "text": "#10213F",
    "muted": "#64748B",
    "accent": "#1D74F5",
    "accent_2": "#42C7FF",
    "accent_3": "#7C3AED",
    "jade": "#079669",
    "gold": "#B7791F",
    "danger": "#DC2626",
    "sidebar": "#101B33",
    "sidebar_2": "#152744",
}

DARK_WUXIA = {
    "bg": "#07111F",
    "surface": "#0F1D33",
    "surface_2": "#13243D",
    "line": "#24415F",
    "line_dark": "#315273",
    "text": "#F8FAFC",
    "muted": "#A9BAD0",
    "accent": "#7DD3FC",
    "accent_2": "#38BDF8",
    "accent_3": "#C4B5FD",
    "jade": "#34D399",
    "gold": "#FBBF24",
    "danger": "#FB7185",
    "sidebar": "#050B16",
    "sidebar_2": "#0B1628",
}

NAV_ICONS = {
    "home": "🏯",
    "setup": "🧭",
    "samples": "🧪",
    "family": "🐉",
    "generate": "⚔",
    "monitor": "☯",
    "validate": "🛡",
    "database": "📚",
    "reports": "📜",
    "analysis": "🔮",
    "settings": "⚙",
}


class WuxiaTitleBanner(tk.Canvas):
    """Reusable decorative title banner for content pages."""

    def __init__(self, parent, title: str, subtitle: str = "", height: int = 98, **kwargs):
        super().__init__(parent, height=height, highlightthickness=0, bg=WUXIA["bg"], **kwargs)
        self.title = title
        self.subtitle = subtitle
        self.bind("<Configure>", lambda _e: self.draw())

    def set_text(self, title: str, subtitle: str = ""):
        self.title = title
        self.subtitle = subtitle
        self.draw()

    def draw(self):
        self.delete("all")
        w = max(self.winfo_width(), 640)
        h = max(self.winfo_height(), 88)
        self.create_rectangle(0, 0, w, h, fill="#F8FBFF", outline="#D7E2F1")
        # misty mountains
        for i in range(5):
            x = i * w / 4 - 70
            y = 44 + (i % 2) * 12
            self.create_polygon(x, h - 8, x + 110, y, x + 240, h - 8, fill="#E5EFFA", outline="", smooth=True)
        for x in range(-30, int(w), 120):
            self.create_arc(x, 18, x + 120, 66, start=10, extent=150, outline="#D8E7F7", width=2)
        self.create_text(24, 30, text=self.title, anchor="w", fill="#0F254A", font=("Segoe UI", 20, "bold"))
        if self.subtitle:
            self.create_text(26, 62, text=self.subtitle, anchor="w", fill="#52647C", font=("Segoe UI", 10))
        self.create_text(w - 34, 32, text="☯", anchor="e", fill="#1D74F5", font=("Segoe UI", 30, "bold"))
        self.create_text(w - 78, 62, text="YARA Kiếm Khí", anchor="e", fill="#1D74F5", font=("Segoe UI", 11, "bold italic"))


class WuxiaMiniMascot(tk.Canvas):
    """Small no-asset chibi/martial mascot used on the home dashboard."""

    def __init__(self, parent, height: int = 180, **kwargs):
        super().__init__(parent, height=height, highlightthickness=0, bg="#FFFFFF", **kwargs)
        self.phase = 0.0
        self._job = None
        self.bind("<Configure>", lambda _e: self.draw())
        self._tick()

    def _tick(self):
        self.phase += 0.12
        self.draw()
        self._job = self.after(100, self._tick)

    def draw(self):
        self.delete("all")
        w = max(self.winfo_width(), 420)
        h = max(self.winfo_height(), 160)
        self.create_rectangle(0, 0, w, h, fill="#FFFFFF", outline="#D7E2F1")
        for i in range(4):
            x = i * w / 3 - 80
            self.create_polygon(x, h - 18, x + 110, 48 + i * 5, x + 220, h - 18, fill="#E9F3FD", outline="", smooth=True)
        cx = w * 0.78
        cy = h * 0.72
        r = 44 + math.sin(self.phase) * 3
        for i in range(3):
            self.create_arc(cx - r - i * 14, cy - r/2 - i * 6, cx + r + i * 14, cy + r/2 + i * 6,
                            start=20 + self.phase * 40 + i * 70, extent=125, outline="#4FC3FF", width=2)
        # mascot
        self.create_oval(cx - 48, cy - 10, cx + 48, cy + 26, fill="#D9E8F8", outline="#52647C")
        self.create_oval(cx - 25, cy - 70, cx + 25, cy - 20, fill="#F6D2B8", outline="#263A5A", width=2)
        self.create_arc(cx - 32, cy - 76, cx + 32, cy - 32, start=0, extent=180, fill="#17223A", outline="#17223A")
        self.create_oval(cx - 8, cy - 96, cx + 18, cy - 66, fill="#17223A", outline="#17223A")
        self.create_polygon(cx - 28, cy - 25, cx + 28, cy - 25, cx + 18, cy + 20, cx - 18, cy + 20,
                            fill="#EFF6FF", outline="#52647C")
        self.create_arc(cx - 15, cy - 50, cx - 4, cy - 42, start=180, extent=180, style="arc", outline="#10213F", width=2)
        self.create_arc(cx + 4, cy - 50, cx + 15, cy - 42, start=180, extent=180, style="arc", outline="#10213F", width=2)
        self.create_text(cx + 5, cy - 84, text="☯", fill="#7BE7FF", font=("Segoe UI", 11, "bold"))
        self.create_line(cx + 46, cy + 5, cx + 86, cy - 74, fill="#22314F", width=4)
        self.create_rectangle(cx - 132, cy - 18, cx - 62, cy + 24, fill="#22314F", outline="#0F172A", width=2)
        self.create_text(cx - 98, cy + 2, text="YARA", fill="#7BE7FF", font=("Segoe UI", 10, "bold"))
        # copy
        self.create_text(26, 42, text="Lò luyện YARA kiếm hiệp", anchor="w", fill="#0F254A", font=("Segoe UI", 18, "bold"))
        self.create_text(28, 74, text="Generate • Validate • IOC • MITRE • Report", anchor="w", fill="#52647C", font=("Segoe UI", 10))
        self.create_text(28, 112, text="⚔ Tạo rule như rèn kiếm  |  ☯ Theo dõi nội lực  |  📜 Xuất báo cáo đẹp", anchor="w", fill="#1D74F5", font=("Segoe UI", 10, "bold"))
