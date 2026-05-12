# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import ttk

class WelcomeScreen(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("Welcome")
        self.geometry("460x320")
        self.resizable(False, False)
        self.var_lang = tk.StringVar(value=app.i18n.language)
        self.var_remember = tk.BooleanVar(value=True)
        self.build()

    def build(self):
        self.columnconfigure(0, weight=1)
        ttk.Label(self, text="yarGen GUI", font=("Segoe UI", 22, "bold")).grid(row=0, column=0, pady=(28, 4))
        ttk.Label(self, text="Malware Family YARA Builder").grid(row=1, column=0, pady=(0, 24))
        box = ttk.Frame(self, padding=12)
        box.grid(row=2, column=0)
        ttk.Label(box, text="Choose language / Chọn ngôn ngữ").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Radiobutton(box, text="Tiếng Việt", variable=self.var_lang, value="vi").grid(row=1, column=0, sticky="w")
        ttk.Radiobutton(box, text="English", variable=self.var_lang, value="en").grid(row=2, column=0, sticky="w")
        ttk.Checkbutton(box, text="Remember my choice", variable=self.var_remember).grid(row=3, column=0, sticky="w", pady=10)
        ttk.Button(self, text="Continue / Tiếp tục", command=self.continue_app).grid(row=3, column=0, pady=16)

    def continue_app(self):
        self.app.update_language(self.var_lang.get())
        self.app.settings.set("language_selected", bool(self.var_remember.get()))
        self.app.settings.save()
        self.destroy()
        self.app.show_screen("home")
