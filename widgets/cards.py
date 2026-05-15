# -*- coding: utf-8 -*-
from tkinter import ttk


def card(parent, title, subtitle="", button_text="", command=None, icon="☯"):
    """Reusable full-app card with wuxia polish but standard ttk stability."""
    f = ttk.Frame(parent, style="Card.TFrame", padding=14)
    head = ttk.Frame(f, style="Surface.TFrame")
    head.pack(fill="x")
    ttk.Label(head, text=icon, style="Accent.H2.TLabel").pack(side="left", padx=(0, 8))
    ttk.Label(head, text=title, style="H2.TLabel").pack(side="left", anchor="w")
    if subtitle:
        ttk.Label(f, text=subtitle, style="Muted.TLabel", wraplength=310, justify="left").pack(anchor="w", pady=(8, 10), fill="x")
    if button_text:
        ttk.Button(f, text=button_text, command=command, style="Wuxia.TButton").pack(anchor="w")
    return f
