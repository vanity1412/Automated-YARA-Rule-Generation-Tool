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
from core.audio_manager import AudioManager
from widgets.sidebar import Sidebar
from widgets.statusbar import StatusBar
from widgets.wuxia_theme import WUXIA, DARK_WUXIA

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
from screens.analysis_suite_screen import AnalysisSuiteScreen
from screens.web_mode_screen import WebModeScreen

class YarGenApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.root_dir = Path(__file__).resolve().parent
        self.settings = SettingsManager(self.root_dir)
        self.i18n = I18n(self.settings.get("language", "vi"))
        self.state = AppState(self, self.root_dir, self.settings)
        self.runner = ProcessRunner(self)
        
        # Khởi tạo Audio Manager
        self.audio_manager = AudioManager(self.root_dir)

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
        
        # Bắt đầu phát nhạc nền nếu được bật trong settings
        if self.settings.get("background_music_enabled", True):
            self.after(500, self.audio_manager.play_background_music)
            
        # Đặt âm lượng từ settings
        volume = self.settings.get("music_volume", 30)
        self.audio_manager.set_volume(volume / 100.0)
        
        # Đăng ký sự kiện đóng ứng dụng để dọn dẹp audio
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def _configure_style(self):
        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except Exception:
            pass
        self.apply_theme()

    def apply_theme(self):
        """Apply the full-app wuxia visual system.

        The UI is still standard ttk/Tkinter for stability, but every common
        control now shares the same light martial-fantasy theme used by the
        Generation Monitor.  This keeps layout predictable and avoids fragile
        image dependencies.
        """
        theme = self.settings.get("theme", "light")
        dark = theme == "dark"
        palette = DARK_WUXIA if dark else WUXIA
        bg = palette["bg"]
        surface = palette["surface"]
        surface_2 = palette["surface_2"]
        text = palette["text"]
        muted = palette["muted"]
        accent = palette["accent"]
        line = palette["line"]
        self.configure(bg=bg)

        # Global defaults
        self.style.configure(".", font=("Segoe UI", 10), background=bg, foreground=text)
        self.style.configure("App.TFrame", background=bg)
        self.style.configure("Surface.TFrame", background=surface)
        self.style.configure("Soft.TFrame", background=surface_2)
        self.style.configure("Card.TFrame", background=surface, relief="solid", borderwidth=1)
        self.style.configure("Topbar.TFrame", background=surface, relief="solid", borderwidth=1)

        # Labels
        self.style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"), background=bg, foreground=text)
        self.style.configure("TopTitle.TLabel", font=("Segoe UI", 16, "bold"), background=surface, foreground=text)
        self.style.configure("TopSubtitle.TLabel", font=("Segoe UI", 9), background=surface, foreground=muted)
        self.style.configure("H1.TLabel", font=("Segoe UI", 15, "bold"), background=surface, foreground=text)
        self.style.configure("H2.TLabel", font=("Segoe UI", 12, "bold"), background=surface, foreground=text)
        self.style.configure("Muted.TLabel", background=surface, foreground=muted)
        self.style.configure("AppMuted.TLabel", background=bg, foreground=muted)
        self.style.configure("Card.TLabel", background=surface, foreground=text)
        self.style.configure("Accent.H2.TLabel", font=("Segoe UI", 12, "bold"), background=surface, foreground=accent)
        self.style.configure("Jade.TLabel", font=("Segoe UI", 10, "bold"), background=surface, foreground=palette["jade"])
        self.style.configure("Gold.TLabel", font=("Segoe UI", 10, "bold"), background=surface, foreground=palette["gold"])
        self.style.configure("Pill.TLabel", font=("Segoe UI", 9, "bold"), background="#EAF4FF" if not dark else "#123047", foreground="#1D4ED8" if not dark else "#BAE6FD", padding=(10, 4))
        self.style.configure("Footer.TLabel", background=surface, foreground=muted, padding=(8, 6))

        # Buttons: use padding and bold text; clam theme keeps them stable cross-platform.
        self.style.configure("TButton", font=("Segoe UI", 9), padding=(9, 5))
        self.style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"), padding=(12, 7))
        self.style.configure("Wuxia.TButton", font=("Segoe UI", 9, "bold"), padding=(10, 6))
        self.style.map("Wuxia.TButton", background=[("active", "#EAF4FF")], foreground=[("active", "#1D4ED8")])
        self.style.configure("Danger.TButton", foreground=palette["danger"])

        # Inputs / tables / notebooks
        self.style.configure("TEntry", fieldbackground=surface, foreground=text, bordercolor=line, lightcolor=line, darkcolor=line)
        self.style.configure("TCombobox", fieldbackground=surface, foreground=text, bordercolor=line)
        self.style.configure("TCheckbutton", background=surface, foreground=text)
        self.style.configure("TRadiobutton", background=surface, foreground=text)
        self.style.configure("TLabelframe", background=surface, bordercolor=line, relief="solid")
        self.style.configure("TLabelframe.Label", background=surface, foreground=accent, font=("Segoe UI", 10, "bold"))
        self.style.configure("TNotebook", background=bg, borderwidth=0)
        self.style.configure("TNotebook.Tab", padding=(14, 7), font=("Segoe UI", 9, "bold"), background=surface_2, foreground=muted)
        self.style.map("TNotebook.Tab", background=[("selected", surface)], foreground=[("selected", accent)])
        self.style.configure("Treeview", rowheight=28, background=surface, fieldbackground=surface, foreground=text, bordercolor=line)
        self.style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"), background="#EAF2FD" if not dark else "#172A45", foreground=text, relief="flat")
        self.style.map("Treeview", background=[("selected", "#DBEAFE" if not dark else "#1E3A5F")], foreground=[("selected", text)])

        # Sidebar and status
        self.style.configure("Sidebar.TFrame", background=palette["sidebar"], relief="flat")
        self.style.configure("SidebarHeader.TLabel", background=palette["sidebar"], foreground="#EAF6FF", font=("Segoe UI", 14, "bold"), padding=(10, 8))
        self.style.configure("SidebarHint.TLabel", background=palette["sidebar"], foreground="#9CC9EF", font=("Segoe UI", 8), padding=(10, 0))
        self.style.configure("Sidebar.TButton", background=palette["sidebar"], foreground="#F8FAFC", anchor="w", padding=(12, 9), font=("Segoe UI", 9, "bold"))
        self.style.configure("SidebarActive.TButton", background=palette["sidebar_2"], foreground="#7DD3FC", anchor="w", padding=(12, 9), font=("Segoe UI", 9, "bold"))
        self.style.map("Sidebar.TButton", background=[("active", palette["sidebar_2"])], foreground=[("active", "#FFFFFF")])
        self.style.map("SidebarActive.TButton", background=[("active", palette["sidebar_2"])], foreground=[("active", "#E0F2FE")])
        self.style.configure("Status.TLabel", background=surface, foreground=muted)

    def _build_layout(self):
        self.columnconfigure(1, weight=1)
        self.rowconfigure(1, weight=1)

        self.topbar = ttk.Frame(self, style="Topbar.TFrame", padding=(14, 9))
        self.topbar.grid(row=0, column=0, columnspan=2, sticky="ew")
        self.topbar.columnconfigure(1, weight=1)
        brand = ttk.Frame(self.topbar, style="Surface.TFrame")
        brand.grid(row=0, column=0, sticky="w")
        ttk.Label(brand, text="☯", style="Accent.H2.TLabel").grid(row=0, column=0, rowspan=2, sticky="w", padx=(0, 8))
        ttk.Label(brand, text=APP_TITLE, style="TopTitle.TLabel").grid(row=0, column=1, sticky="w")
        ttk.Label(brand, text="Kiếm hiệp malware-analysis workstation • static only • offline friendly", style="TopSubtitle.TLabel").grid(row=1, column=1, sticky="w")
        ttk.Label(self.topbar, text="⚔ YARA Kiếm Các", style="Pill.TLabel").grid(row=0, column=1, sticky="e", padx=8)
        
        # Nút điều khiển âm thanh
        self.music_button = ttk.Button(self.topbar, text="", command=self.toggle_background_music, style="Wuxia.TButton")
        self.music_button.grid(row=0, column=2, padx=4)
        
        self.mode_button = ttk.Button(self.topbar, text="", command=self.toggle_mode, style="Wuxia.TButton")
        self.mode_button.grid(row=0, column=3, padx=4)
        self.lang_button = ttk.Button(self.topbar, text="", command=self.toggle_language, style="Wuxia.TButton")
        self.lang_button.grid(row=0, column=4, padx=4)
        self.theme_button = ttk.Button(self.topbar, text="", command=self.toggle_theme, style="Wuxia.TButton")
        self.theme_button.grid(row=0, column=5, padx=4)

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
            "database": DatabaseScreen, "reports": ReportsScreen, "analysis": AnalysisSuiteScreen, "web": WebModeScreen, "settings": SettingsScreen,
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
        music_enabled = self.settings.get("background_music_enabled", True)
        
        self.music_button.configure(text=("🎵 Music ON" if music_enabled else "🔇 Music OFF"))
        self.mode_button.configure(text=("⚔ Advanced" if mode == "advanced" else "🧘 Basic"))
        self.lang_button.configure(text=("🌐 English" if lang == "vi" else "🌐 Tiếng Việt"))
        self.theme_button.configure(text=("🌙 Dark" if theme != "dark" else "☀ Light"))

    def refresh_status(self):
        self.statusbar.refresh()
    
    def on_closing(self):
        """Xử lý khi đóng ứng dụng"""
        # Dọn dẹp audio manager
        if hasattr(self, 'audio_manager'):
            self.audio_manager.cleanup()
        
        # Đóng ứng dụng
        self.destroy()
    
    def toggle_background_music(self):
        """Bật/tắt nhạc nền"""
        if hasattr(self, 'audio_manager'):
            current_state = self.settings.get("background_music_enabled", True)
            new_state = not current_state
            
            self.settings.set("background_music_enabled", new_state)
            self.settings.save()
            
            if new_state:
                self.audio_manager.play_background_music()
            else:
                self.audio_manager.stop_music()
    
    def set_music_volume(self, volume):
        """Đặt âm lượng nhạc (0-100)"""
        if hasattr(self, 'audio_manager'):
            volume_float = volume / 100.0
            self.audio_manager.set_volume(volume_float)
            self.settings.set("music_volume", volume)
            self.settings.save()
