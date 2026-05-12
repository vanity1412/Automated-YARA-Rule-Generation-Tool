# -*- coding: utf-8 -*-
from tkinter import ttk

def card(parent, title, subtitle="", button_text="", command=None):
    f = ttk.Frame(parent, style="Card.TFrame", padding=12)
    ttk.Label(f, text=title, style="H2.TLabel").pack(anchor="w")
    if subtitle:
        ttk.Label(f, text=subtitle, style="Muted.TLabel", wraplength=280).pack(anchor="w", pady=(4, 8))
    if button_text:
        ttk.Button(f, text=button_text, command=command).pack(anchor="w")
    return f
