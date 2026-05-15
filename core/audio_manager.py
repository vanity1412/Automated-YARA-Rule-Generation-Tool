#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Audio Manager - Quản lý phát nhạc nền cho ứng dụng
"""
import pygame
import threading
import os
from pathlib import Path
import logging

class AudioManager:
    def __init__(self, app_root_dir):
        self.app_root_dir = Path(app_root_dir)
        self.music_dir = self.app_root_dir / "music"
        self.background_music_file = self.music_dir / "background.mp3"
        self.report_music_file = self.music_dir / "report.mp3"
        
        self.is_initialized = False
        self.is_playing = False
        self.volume = 0.3  # Âm lượng mặc định (30%)
        self.current_music = None
        
        self._init_pygame()
    
    def _init_pygame(self):
        """Khởi tạo pygame mixer"""
        try:
            pygame.mixer.pre_init(frequency=22050, size=-16, channels=2, buffer=512)
            pygame.mixer.init()
            self.is_initialized = True
            logging.info("Audio Manager initialized successfully")
        except Exception as e:
            logging.error(f"Failed to initialize audio: {e}")
            self.is_initialized = False
    
    def play_background_music(self, loop=True):
        """Phát nhạc nền"""
        if not self.is_initialized:
            return False
            
        if not self.background_music_file.exists():
            logging.warning(f"Background music file not found: {self.background_music_file}")
            return False
        
        try:
            pygame.mixer.music.load(str(self.background_music_file))
            pygame.mixer.music.set_volume(self.volume)
            
            # -1 means loop indefinitely, 0 means play once
            loops = -1 if loop else 0
            pygame.mixer.music.play(loops)
            
            self.is_playing = True
            self.current_music = "background"
            logging.info("Background music started")
            return True
            
        except Exception as e:
            logging.error(f"Failed to play background music: {e}")
            return False
    
    def play_report_music(self, loop=False):
        """Phát nhạc báo cáo"""
        if not self.is_initialized:
            return False
            
        if not self.report_music_file.exists():
            logging.warning(f"Report music file not found: {self.report_music_file}")
            return False
        
        try:
            pygame.mixer.music.load(str(self.report_music_file))
            pygame.mixer.music.set_volume(self.volume)
            
            loops = -1 if loop else 0
            pygame.mixer.music.play(loops)
            
            self.is_playing = True
            self.current_music = "report"
            logging.info("Report music started")
            return True
            
        except Exception as e:
            logging.error(f"Failed to play report music: {e}")
            return False
    
    def stop_music(self):
        """Dừng phát nhạc"""
        if not self.is_initialized:
            return
            
        try:
            pygame.mixer.music.stop()
            self.is_playing = False
            self.current_music = None
            logging.info("Music stopped")
        except Exception as e:
            logging.error(f"Failed to stop music: {e}")
    
    def pause_music(self):
        """Tạm dừng nhạc"""
        if not self.is_initialized or not self.is_playing:
            return
            
        try:
            pygame.mixer.music.pause()
            logging.info("Music paused")
        except Exception as e:
            logging.error(f"Failed to pause music: {e}")
    
    def resume_music(self):
        """Tiếp tục phát nhạc"""
        if not self.is_initialized:
            return
            
        try:
            pygame.mixer.music.unpause()
            logging.info("Music resumed")
        except Exception as e:
            logging.error(f"Failed to resume music: {e}")
    
    def set_volume(self, volume):
        """Đặt âm lượng (0.0 - 1.0)"""
        if not self.is_initialized:
            return
            
        self.volume = max(0.0, min(1.0, volume))
        try:
            pygame.mixer.music.set_volume(self.volume)
            logging.info(f"Volume set to {self.volume * 100:.0f}%")
        except Exception as e:
            logging.error(f"Failed to set volume: {e}")
    
    def get_volume(self):
        """Lấy âm lượng hiện tại"""
        return self.volume
    
    def is_music_playing(self):
        """Kiểm tra xem có đang phát nhạc không"""
        if not self.is_initialized:
            return False
        return pygame.mixer.music.get_busy()
    
    def toggle_music(self):
        """Bật/tắt nhạc nền"""
        if self.is_music_playing():
            self.stop_music()
        else:
            self.play_background_music()
    
    def cleanup(self):
        """Dọn dẹp tài nguyên"""
        if self.is_initialized:
            try:
                pygame.mixer.music.stop()
                pygame.mixer.quit()
                logging.info("Audio Manager cleaned up")
            except Exception as e:
                logging.error(f"Failed to cleanup audio: {e}")