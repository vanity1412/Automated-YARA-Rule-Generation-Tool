#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Audio Manager - Quản lý phát nhạc nền cho ứng dụng.

pygame là tính năng tùy chọn. Nếu máy chưa cài pygame hoặc không có thiết bị âm
thanh, app vẫn khởi động bình thường và chỉ tắt phần nhạc nền.
"""
from pathlib import Path
import logging

try:
    import pygame  # type: ignore
except Exception as exc:  # pragma: no cover - depends on local environment
    pygame = None
    _PYGAME_IMPORT_ERROR = exc
else:
    _PYGAME_IMPORT_ERROR = None


class AudioManager:
    def __init__(self, app_root_dir):
        self.app_root_dir = Path(app_root_dir)
        self.music_dir = self.app_root_dir / "music"
        self.background_music_file = self.music_dir / "background.mp3"
        self.report_music_file = self.music_dir / "report.mp3"

        self.is_initialized = False
        self.is_playing = False
        self.volume = 0.3
        self.current_music = None

        self._init_pygame()

    def _init_pygame(self):
        """Khởi tạo pygame mixer nếu pygame khả dụng."""
        if pygame is None:
            logging.warning("pygame is not installed; background music disabled: %s", _PYGAME_IMPORT_ERROR)
            self.is_initialized = False
            return
        try:
            pygame.mixer.pre_init(frequency=22050, size=-16, channels=2, buffer=512)
            pygame.mixer.init()
            self.is_initialized = True
            logging.info("Audio Manager initialized successfully")
        except Exception as e:
            logging.warning("Failed to initialize audio; app will continue without music: %s", e)
            self.is_initialized = False

    def play_background_music(self, loop=True):
        """Phát nhạc nền."""
        if not self.is_initialized or pygame is None:
            return False
        if not self.background_music_file.exists():
            logging.warning("Background music file not found: %s", self.background_music_file)
            return False
        try:
            pygame.mixer.music.load(str(self.background_music_file))
            pygame.mixer.music.set_volume(self.volume)
            pygame.mixer.music.play(-1 if loop else 0)
            self.is_playing = True
            self.current_music = "background"
            return True
        except Exception as e:
            logging.warning("Failed to play background music: %s", e)
            return False

    def play_report_music(self, loop=False):
        """Phát nhạc báo cáo."""
        if not self.is_initialized or pygame is None:
            return False
        if not self.report_music_file.exists():
            logging.warning("Report music file not found: %s", self.report_music_file)
            return False
        try:
            pygame.mixer.music.load(str(self.report_music_file))
            pygame.mixer.music.set_volume(self.volume)
            pygame.mixer.music.play(-1 if loop else 0)
            self.is_playing = True
            self.current_music = "report"
            return True
        except Exception as e:
            logging.warning("Failed to play report music: %s", e)
            return False

    def stop_music(self):
        if not self.is_initialized or pygame is None:
            return
        try:
            pygame.mixer.music.stop()
        except Exception as e:
            logging.warning("Failed to stop music: %s", e)
        finally:
            self.is_playing = False
            self.current_music = None

    def pause_music(self):
        if not self.is_initialized or not self.is_playing or pygame is None:
            return
        try:
            pygame.mixer.music.pause()
        except Exception as e:
            logging.warning("Failed to pause music: %s", e)

    def resume_music(self):
        if not self.is_initialized or pygame is None:
            return
        try:
            pygame.mixer.music.unpause()
        except Exception as e:
            logging.warning("Failed to resume music: %s", e)

    def set_volume(self, volume):
        self.volume = max(0.0, min(1.0, float(volume)))
        if not self.is_initialized or pygame is None:
            return
        try:
            pygame.mixer.music.set_volume(self.volume)
        except Exception as e:
            logging.warning("Failed to set volume: %s", e)

    def get_volume(self):
        return self.volume

    def is_music_playing(self):
        if not self.is_initialized or pygame is None:
            return False
        try:
            return bool(pygame.mixer.music.get_busy())
        except Exception:
            return False

    def toggle_music(self):
        if self.is_music_playing():
            self.stop_music()
        else:
            self.play_background_music()

    def cleanup(self):
        if self.is_initialized and pygame is not None:
            try:
                pygame.mixer.music.stop()
                pygame.mixer.quit()
            except Exception as e:
                logging.warning("Failed to cleanup audio: %s", e)
