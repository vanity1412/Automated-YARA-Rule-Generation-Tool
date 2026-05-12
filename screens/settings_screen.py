# -*- coding: utf-8 -*-
from tkinter import ttk

class SettingsScreen(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, style="App.TFrame")
        self.app = app
        self.build()

    def refresh_text(self): pass
    def on_mode_changed(self): pass
    def on_show(self): pass

    def build(self):
        self.columnconfigure(0, weight=1)
        ttk.Label(self, text=self.app.t("settings.title"), style="Title.TLabel").grid(row=0, column=0, sticky="w")
        box = ttk.Frame(self, style="Card.TFrame", padding=12)
        box.grid(row=1, column=0, sticky="ew", pady=8)
        ttk.Label(box, text="Language", style="Card.TLabel").grid(row=0, column=0, sticky="w", pady=5)
        self.lang = ttk.Combobox(box, values=["vi", "en"], state="readonly", width=12)
        self.lang.set(self.app.i18n.language); self.lang.grid(row=0, column=1, sticky="w", padx=8)
        ttk.Label(box, text="Theme", style="Card.TLabel").grid(row=1, column=0, sticky="w", pady=5)
        self.theme = ttk.Combobox(box, values=["light", "dark"], state="readonly", width=12)
        self.theme.set(self.app.settings.get("theme", "light")); self.theme.grid(row=1, column=1, sticky="w", padx=8)
        ttk.Label(box, text="Mode", style="Card.TLabel").grid(row=2, column=0, sticky="w", pady=5)
        self.mode = ttk.Combobox(box, values=["basic", "advanced"], state="readonly", width=12)
        self.mode.set(self.app.settings.get("mode", "basic")); self.mode.grid(row=2, column=1, sticky="w", padx=8)
        ttk.Button(box, text=self.app.t("settings.save"), command=self.save).grid(row=3, column=1, sticky="w", pady=12)
        ttk.Button(box, text=self.app.t("settings.reset"), command=self.reset).grid(row=3, column=2, sticky="w", pady=12, padx=8)

    def save(self):
        self.app.settings.set("language", self.lang.get())
        self.app.settings.set("theme", self.theme.get())
        self.app.settings.set("mode", self.mode.get())
        self.app.settings.set("language_selected", True)
        self.app.settings.save()
        self.app.update_language(self.lang.get())
        self.app.apply_theme()
        self.app.state.var_mode.set(self.mode.get())
        self.app.update_topbar_text()

    def reset(self):
        self.app.settings.reset()
        self.lang.set(self.app.settings.get("language"))
        self.theme.set(self.app.settings.get("theme"))
        self.mode.set(self.app.settings.get("mode"))
        self.save()
