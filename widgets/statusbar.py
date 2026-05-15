# -*- coding: utf-8 -*-
from tkinter import ttk


class StatusBar(ttk.Frame):
    def __init__(self, app):
        super().__init__(app, style="Surface.TFrame", padding=(12, 6))
        self.app = app
        self.columnconfigure(0, weight=1)
        self.text = ttk.Label(self, text="", style="Status.TLabel")
        self.text.grid(row=0, column=0, sticky="w")
        self.safe = ttk.Label(self, text="🛡 Static only • No sample execution • Offline", style="Jade.TLabel")
        self.safe.grid(row=0, column=1, sticky="e")

    def refresh(self):
        s = self.app.state
        text = (
            f"☯ {self.app.t('status.env')}: {s.var_env_status.get()}   |   "
            f"🏯 {self.app.t('status.project')}: {s.var_workdir.get()}   |   "
            f"⚔ {self.app.t('status.preset')}: {s.var_current_preset.get()}   |   "
            f"📜 {self.app.t('status.output')}: {s.var_output.get()}   |   "
            f"⏳ {self.app.t('status.running')}: {s.var_run_status.get()}"
        )
        self.text.configure(text=text)
