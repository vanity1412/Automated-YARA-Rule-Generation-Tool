# -*- coding: utf-8 -*-
from tkinter import ttk
import tkinter as tk

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
        
        # General Settings
        box = ttk.Frame(self, style="Card.TFrame", padding=12)
        box.grid(row=1, column=0, sticky="ew", pady=8)
        box.columnconfigure(1, weight=1)
        
        ttk.Label(box, text="Language", style="Card.TLabel").grid(row=0, column=0, sticky="w", pady=5)
        self.lang = ttk.Combobox(box, values=["vi", "en"], state="readonly", width=12)
        self.lang.set(self.app.i18n.language)
        self.lang.grid(row=0, column=1, sticky="w", padx=8)
        
        ttk.Label(box, text="Theme", style="Card.TLabel").grid(row=1, column=0, sticky="w", pady=5)
        self.theme = ttk.Combobox(box, values=["light", "dark"], state="readonly", width=12)
        self.theme.set(self.app.settings.get("theme", "light"))
        self.theme.grid(row=1, column=1, sticky="w", padx=8)
        
        ttk.Label(box, text="Mode", style="Card.TLabel").grid(row=2, column=0, sticky="w", pady=5)
        self.mode = ttk.Combobox(box, values=["basic", "advanced"], state="readonly", width=12)
        self.mode.set(self.app.settings.get("mode", "basic"))
        self.mode.grid(row=2, column=1, sticky="w", padx=8)
        
        # Audio Settings
        audio_box = ttk.LabelFrame(self, text="🎵 Audio Settings", style="TLabelframe", padding=12)
        audio_box.grid(row=2, column=0, sticky="ew", pady=8)
        audio_box.columnconfigure(1, weight=1)
        
        # Background Music Toggle
        ttk.Label(audio_box, text="Background Music", style="Card.TLabel").grid(row=0, column=0, sticky="w", pady=5)
        self.music_enabled = tk.BooleanVar()
        self.music_enabled.set(self.app.settings.get("background_music_enabled", True))
        music_check = ttk.Checkbutton(audio_box, text="Enable", variable=self.music_enabled, command=self.on_music_toggle)
        music_check.grid(row=0, column=1, sticky="w", padx=8)
        
        # Volume Control
        ttk.Label(audio_box, text="Volume", style="Card.TLabel").grid(row=1, column=0, sticky="w", pady=5)
        volume_frame = ttk.Frame(audio_box)
        volume_frame.grid(row=1, column=1, sticky="ew", padx=8, pady=5)
        volume_frame.columnconfigure(0, weight=1)
        
        self.volume_var = tk.IntVar()
        current_volume = int(self.app.settings.get("music_volume", 30))
        self.volume_var.set(current_volume)
        
        self.volume_scale = ttk.Scale(volume_frame, from_=0, to=100, orient="horizontal", 
                                     variable=self.volume_var, command=self.on_volume_change)
        self.volume_scale.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        
        self.volume_label = ttk.Label(volume_frame, text=f"{current_volume}%", style="Card.TLabel")
        self.volume_label.grid(row=0, column=1)
        
        # Control Buttons
        control_frame = ttk.Frame(audio_box)
        control_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        ttk.Button(control_frame, text="🎵 Play", command=self.play_music).grid(row=0, column=0, padx=5)
        ttk.Button(control_frame, text="⏸ Pause", command=self.pause_music).grid(row=0, column=1, padx=5)
        ttk.Button(control_frame, text="⏹ Stop", command=self.stop_music).grid(row=0, column=2, padx=5)
        
        # Save/Reset Buttons
        button_frame = ttk.Frame(box)
        button_frame.grid(row=3, column=0, columnspan=2, pady=12)
        
        ttk.Button(button_frame, text=self.app.t("settings.save"), command=self.save).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text=self.app.t("settings.reset"), command=self.reset).grid(row=0, column=1, padx=5)

    def on_music_toggle(self):
        """Xử lý khi bật/tắt nhạc nền"""
        enabled = self.music_enabled.get()
        self.app.settings.set("background_music_enabled", enabled)
        self.app.settings.save()
        
        if hasattr(self.app, 'audio_manager'):
            if enabled:
                self.app.audio_manager.play_background_music()
            else:
                self.app.audio_manager.stop_music()
        
        self.app.update_topbar_text()

    def on_volume_change(self, value):
        """Xử lý khi thay đổi âm lượng"""
        volume = int(float(value))
        self.volume_label.configure(text=f"{volume}%")
        
        if hasattr(self.app, 'audio_manager'):
            self.app.audio_manager.set_volume(volume / 100.0)
        
        self.app.settings.set("music_volume", volume)
        self.app.settings.save()

    def play_music(self):
        """Phát nhạc nền"""
        if hasattr(self.app, 'audio_manager'):
            self.app.audio_manager.play_background_music()
            self.music_enabled.set(True)
            self.app.settings.set("background_music_enabled", True)
            self.app.settings.save()
            self.app.update_topbar_text()

    def pause_music(self):
        """Tạm dừng nhạc"""
        if hasattr(self.app, 'audio_manager'):
            self.app.audio_manager.pause_music()

    def stop_music(self):
        """Dừng nhạc"""
        if hasattr(self.app, 'audio_manager'):
            self.app.audio_manager.stop_music()
            self.music_enabled.set(False)
            self.app.settings.set("background_music_enabled", False)
            self.app.settings.save()
            self.app.update_topbar_text()

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
        self.music_enabled.set(self.app.settings.get("background_music_enabled", True))
        volume = int(self.app.settings.get("music_volume", 30))
        self.volume_var.set(volume)
        self.volume_label.configure(text=f"{volume}%")
        self.save()
