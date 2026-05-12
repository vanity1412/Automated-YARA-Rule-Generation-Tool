#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import ttk
from pathlib import Path

from core.config import APP_TITLE, APP_VERSION, NAV_ITEMS
from core.state import AppState
from core.settings import SettingsManager
from core.i18n import I18n
from core.runner import ProcessRunner
from widgets.sidebar import Sidebar
from widgets.statusbar import StatusBar

from screens.welcome_screen import WelcomeScreen
from screens.home_screen import HomeScreen
from screens.setup_screen import SetupScreen
from screens.samples_screen import SamplesScreen
from screens.family_screen import FamilyScreen
from screens.generate_screen import GenerateScreen
from screens.monitor_screen import MonitorScreen
from screens.validate_screen import ValidateScreen
from screens.database_screen import DatabaseScreen
from screens.reports_screen import ReportsScreen
from screens.settings_screen import SettingsScreen

class YarGenApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.root_dir = Path(__file__).resolve().parent
        self.settings = SettingsManager(self.root_dir)
        self.i18n = I18n(self.settings.get("language", "vi"))
        self.state = AppState(self, self.root_dir, self.settings)
        self.runner = ProcessRunner(self)

        self.title(f"{APP_TITLE} v{APP_VERSION}")
        self.geometry("1366x820")
        self.minsize(1180, 720)

        self.screens = {}
        self._configure_style()
        self._build_layout()

        if not self.settings.get("language_selected", False):
            self.show_welcome()
        else:
            self.show_screen("home")
            self.refresh_status()

        self.after(100, self.runner.drain_output_queue)

    def _configure_style(self):
        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except Exception:
            pass
        self.apply_theme()

    def apply_theme(self):
        theme = self.settings.get("theme", "light")
        dark = theme == "dark"
        bg = "#0F172A" if dark else "#F5F7FA"
        surface = "#111827" if dark else "#FFFFFF"
        text = "#F8FAFC" if dark else "#111827"
        muted = "#94A3B8" if dark else "#6B7280"
        self.configure(bg=bg)
        self.style.configure(".", font=("Segoe UI", 10), background=bg, foreground=text)
        self.style.configure("App.TFrame", background=bg)
        self.style.configure("Surface.TFrame", background=surface)
        self.style.configure("Card.TFrame", background=surface, relief="solid", borderwidth=1)
        self.style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"), background=bg, foreground=text)
        self.style.configure("H1.TLabel", font=("Segoe UI", 15, "bold"), background=surface, foreground=text)
        self.style.configure("H2.TLabel", font=("Segoe UI", 12, "bold"), background=surface, foreground=text)
        self.style.configure("Muted.TLabel", background=surface, foreground=muted)
        self.style.configure("Card.TLabel", background=surface, foreground=text)
        self.style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"))
        self.style.configure("Danger.TButton", foreground="#DC2626")
        self.style.configure("Sidebar.TFrame", background="#111827")
        self.style.configure("Sidebar.TButton", background="#111827", foreground="#F8FAFC", anchor="w", padding=(12, 8))
        self.style.map("Sidebar.TButton", background=[("active", "#1F2937")], foreground=[("active", "#FFFFFF")])
        self.style.configure("Status.TLabel", background=surface, foreground=muted)
        self.style.configure("Treeview", rowheight=24)

    def _build_layout(self):
        self.columnconfigure(1, weight=1)
        self.rowconfigure(1, weight=1)

        self.topbar = ttk.Frame(self, style="App.TFrame", padding=(12, 8))
        self.topbar.grid(row=0, column=0, columnspan=2, sticky="ew")
        self.topbar.columnconfigure(1, weight=1)
        ttk.Label(self.topbar, text=APP_TITLE, style="Title.TLabel").grid(row=0, column=0, sticky="w")
        self.mode_button = ttk.Button(self.topbar, text="", command=self.toggle_mode)
        self.mode_button.grid(row=0, column=2, padx=4)
        self.lang_button = ttk.Button(self.topbar, text="", command=self.toggle_language)
        self.lang_button.grid(row=0, column=3, padx=4)
        self.theme_button = ttk.Button(self.topbar, text="", command=self.toggle_theme)
        self.theme_button.grid(row=0, column=4, padx=4)

        self.sidebar = Sidebar(self, NAV_ITEMS)
        self.sidebar.grid(row=1, column=0, sticky="nsw")

        self.content = ttk.Frame(self, style="App.TFrame", padding=(12, 10))
        self.content.grid(row=1, column=1, sticky="nsew")
        self.content.columnconfigure(0, weight=1)
        self.content.rowconfigure(0, weight=1)

        self.statusbar = StatusBar(self)
        self.statusbar.grid(row=2, column=0, columnspan=2, sticky="ew")

        self._build_screens()
        self.update_topbar_text()

    def _build_screens(self):
        screen_classes = {
            "home": HomeScreen, "setup": SetupScreen, "samples": SamplesScreen, "family": FamilyScreen,
            "generate": GenerateScreen, "monitor": MonitorScreen, "validate": ValidateScreen,
            "database": DatabaseScreen, "reports": ReportsScreen, "settings": SettingsScreen,
        }
        for key, cls in screen_classes.items():
            frame = cls(self.content, self)
            frame.grid(row=0, column=0, sticky="nsew")
            frame.grid_remove()
            self.screens[key] = frame

    def show_welcome(self):
        self.welcome = WelcomeScreen(self)
        self.welcome.grab_set()

    def show_screen(self, key):
        for frame in self.screens.values():
            frame.grid_remove()
        self.screens[key].grid()
        self.screens[key].on_show()
        self.sidebar.set_active(key)
        self.refresh_status()

    def t(self, key):
        return self.i18n.t(key)

    def update_language(self, lang):
        self.i18n.set_language(lang)
        self.settings.set("language", lang)
        self.settings.set("language_selected", True)
        self.settings.save()
        self.sidebar.refresh_labels()
        for screen in self.screens.values():
            screen.refresh_text()
        self.update_topbar_text()
        self.refresh_status()

    def toggle_language(self):
        self.update_language("en" if self.i18n.language == "vi" else "vi")

    def toggle_theme(self):
        current = self.settings.get("theme", "light")
        self.settings.set("theme", "dark" if current != "dark" else "light")
        self.settings.save()
        self.apply_theme()
        for screen in self.screens.values():
            screen.refresh_text()

    def toggle_mode(self):
        current = self.settings.get("mode", "basic")
        self.settings.set("mode", "advanced" if current == "basic" else "basic")
        self.settings.save()
        self.state.var_mode.set(self.settings.get("mode"))
        self.update_topbar_text()
        for screen in self.screens.values():
            screen.on_mode_changed()

    def update_topbar_text(self):
        mode = self.settings.get("mode", "basic")
        lang = self.i18n.language
        theme = self.settings.get("theme", "light")
        self.mode_button.configure(text=("Advanced Mode" if mode == "advanced" else "Basic Mode"))
        self.lang_button.configure(text=("English" if lang == "vi" else "Tiếng Việt"))
        self.theme_button.configure(text=("Dark" if theme != "dark" else "Light"))

    def refresh_status(self):
        self.statusbar.refresh()
