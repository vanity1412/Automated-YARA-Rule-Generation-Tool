# -*- coding: utf-8 -*-
"""Generation monitor screen with a polished wuxia/anime waiting UX.

The yarGen engine can take a while on real sample folders.  This screen keeps the
existing monitor behavior but adds a lightweight animated dashboard made only with
Tkinter canvas widgets.  No external images/assets are required, so the app stays
portable and safe for offline demo machines.
"""
import math
import random
import re
import time
import tkinter as tk
from pathlib import Path
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
import threading
import subprocess
import os

from core.utils import open_path
from core.scrollable_screen import ScrollableScreen


STAGE_ROWS = [
    ("1", "☯  Preflight", "Waiting", "Chờ nhập môn"),
    ("2", "⛩  Load goodware DB", "Waiting", "Đang chuẩn bị"),
    ("3", "📜  Extract strings/opcodes", "Waiting", "Chưa tới lượt"),
    ("4", "📘  Generate statistics", "Waiting", "Chưa tới lượt"),
    ("5", "⚔  Generate simple/super rules", "Waiting", "Chưa tới lượt"),
    ("6", "🛡  Validate/Test", "Waiting", "Chưa tới lượt"),
]

WUXIA_TIPS = [
    "Uống ngụm trà, rule mạnh lên từng chút 🍵",
    "Trust the process, YARA đang tụ khí 💪",
    "Không malware nào qua mắt được kiếm khách phân tích 😎",
    "Đừng nóng vội, cao thủ cần thời gian luyện công ✨",
    "DB càng lớn, nội lực càng sâu. Kiên nhẫn nhé ⏳",
    "Nếu log còn chạy, kiếm khí vẫn đang bay ⚔",
]

STAGE_EXP = {
    "Idle": 0,
    "Preflight": 50,
    "Load goodware DB": 120,
    "Extract strings/opcodes": 260,
    "Generate statistics": 420,
    "Generate rules": 700,
    "Validate/Test": 850,
    "Finished": 999,
    "Error": 0,
}


class VideoPlayer(tk.Frame):
    """Simple video player using tkinter and external video player"""
    
    def __init__(self, parent, app, **kwargs):
        super().__init__(parent, **kwargs)
        self.app = app
        self.video_process = None
        self.video_files = []
        self.current_video = 0
        self.is_playing = False
        self.video_enabled = tk.BooleanVar(value=True)
        
        # Tìm video files
        self._find_video_files()
        self._build_ui()
    
    def _find_video_files(self):
        """Tìm các file video trong thư mục video"""
        video_dir = Path("video")
        if video_dir.exists():
            video_extensions = ['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm']
            self.video_files = [f for f in video_dir.iterdir() 
                              if f.suffix.lower() in video_extensions and f.is_file()]
            print(f"[VIDEO] Tìm thấy {len(self.video_files)} video files:")
            for video in self.video_files:
                print(f"[VIDEO]   - {video.name}")
        else:
            print("[VIDEO] Thư mục 'video' không tồn tại")
    
    def _build_ui(self):
        """Xây dựng giao diện video player"""
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        
        # Header với controls
        header = ttk.Frame(self)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        header.columnconfigure(1, weight=1)
        
        ttk.Label(header, text="🎬 Video giải trí", style="H1.TLabel").grid(row=0, column=0, sticky="w")
        
        # Controls
        controls = ttk.Frame(header)
        controls.grid(row=0, column=1, sticky="e")
        
        ttk.Checkbutton(controls, text="Bật video", variable=self.video_enabled, 
                       command=self._toggle_video).grid(row=0, column=0, padx=(0, 8))
        ttk.Button(controls, text="▶️ Play", command=self.play_video, 
                  style="Secondary.TButton").grid(row=0, column=1, padx=(0, 4))
        ttk.Button(controls, text="⏸️ Pause", command=self.pause_video, 
                  style="Secondary.TButton").grid(row=0, column=2, padx=(0, 4))
        ttk.Button(controls, text="⏭️ Next", command=self.next_video, 
                  style="Secondary.TButton").grid(row=0, column=3, padx=(0, 4))
        ttk.Button(controls, text="🔊 Volume", command=self._adjust_volume, 
                  style="Secondary.TButton").grid(row=0, column=4)
        
        # Video display area
        self.video_frame = ttk.Frame(self, style="Card.TFrame", padding=14)
        self.video_frame.grid(row=1, column=0, sticky="nsew")
        self.video_frame.columnconfigure(0, weight=1)
        self.video_frame.rowconfigure(0, weight=1)
        
        # Placeholder khi không có video
        video_info = f"Tìm thấy {len(self.video_files)} video" if self.video_files else "Không tìm thấy video nào"
        if self.video_files:
            video_list = "\n".join([f"• {v.name}" for v in self.video_files[:3]])
            if len(self.video_files) > 3:
                video_list += f"\n• ... và {len(self.video_files) - 3} video khác"
        else:
            video_list = "Đặt file video (.mp4, .avi, .mkv) vào thư mục 'video'"
            
        self.placeholder = ttk.Label(self.video_frame, 
                                   text=f"🎬 Video giải trí trong lúc tạo YARA rules\n\n"
                                        f"{video_info}:\n{video_list}\n\n"
                                        "Video sẽ tự động phát khi bắt đầu generate 😊",
                                   style="Card.TLabel", justify="center")
        self.placeholder.grid(row=0, column=0)
        
        # Status label
        self.status_label = ttk.Label(self, text="Sẵn sàng phát video", style="Muted.TLabel")
        self.status_label.grid(row=2, column=0, sticky="ew", pady=(8, 0))
    
    def _toggle_video(self):
        """Bật/tắt video"""
        if not self.video_enabled.get():
            self.stop_video()
    
    def play_video(self):
        """Phát video"""
        if not self.video_enabled.get():
            self.status_label.config(text="Video đã bị tắt")
            return
            
        if not self.video_files:
            self.status_label.config(text="Không có file video nào để phát")
            return
            
        if self.is_playing:
            self.status_label.config(text="Video đang phát rồi")
            return
            
        video_file = self.video_files[self.current_video]
        self.status_label.config(text=f"Đang phát: {video_file.name}")
        
        try:
            if os.name == 'nt':  # Windows
                # Thử các video player theo thứ tự ưu tiên
                players_to_try = [
                    # VLC
                    (r"C:\Program Files\VideoLAN\VLC\vlc.exe", [
                        str(video_file), "--intf", "dummy", "--loop", 
                        "--no-video-title-show", "--play-and-exit"
                    ]),
                    (r"C:\Program Files (x86)\VideoLAN\VLC\vlc.exe", [
                        str(video_file), "--intf", "dummy", "--loop", 
                        "--no-video-title-show", "--play-and-exit"
                    ]),
                    # Windows Media Player
                    ("wmplayer.exe", [str(video_file)]),
                    # Movies & TV (Windows 10/11)
                    ("microsoft.windows.photos.exe", [str(video_file)]),
                    # Default system player
                    ("start", ["/wait", str(video_file)]),
                    # Fallback - mở với default app
                    ("explorer.exe", [str(video_file)])
                ]
                
                success = False
                for player_path, args in players_to_try:
                    try:
                        if player_path.endswith('.exe') and not player_path.startswith(('start', 'explorer')):
                            # Kiểm tra file tồn tại
                            if not Path(player_path).exists():
                                continue
                        
                        print(f"[VIDEO] Thử player: {player_path}")
                        
                        if player_path == "start":
                            # Sử dụng start command
                            self.video_process = subprocess.Popen([
                                "cmd", "/c", "start", "/wait", str(video_file)
                            ], creationflags=subprocess.CREATE_NO_WINDOW)
                        else:
                            # Sử dụng player trực tiếp
                            self.video_process = subprocess.Popen([
                                player_path
                            ] + args, creationflags=subprocess.CREATE_NO_WINDOW)
                        
                        success = True
                        print(f"[VIDEO] Thành công với: {player_path}")
                        break
                        
                    except Exception as e:
                        print(f"[VIDEO] Lỗi với {player_path}: {e}")
                        continue
                
                if not success:
                    raise Exception("Không tìm thấy video player nào hoạt động")
                    
            else:
                # Linux/Mac - sử dụng mpv hoặc vlc
                try:
                    print("[VIDEO] Sử dụng mpv")
                    self.video_process = subprocess.Popen([
                        "mpv", str(video_file), "--loop"
                    ])
                except FileNotFoundError:
                    print("[VIDEO] mpv không tìm thấy, sử dụng vlc")
                    self.video_process = subprocess.Popen([
                        "vlc", str(video_file), "--loop"
                    ])
            
            self.is_playing = True
            self.placeholder.config(text=f"🎬 Đang phát: {video_file.name}\n\n"
                                         "Video đang chạy trong cửa sổ riêng\n\n"
                                         "Thư giãn và chờ YARA rules hoàn thành! 😊\n\n"
                                         "Bấm Pause để tạm dừng")
            
            print(f"[VIDEO] Bắt đầu phát video: {video_file.name}")
            
        except Exception as e:
            error_msg = f"Lỗi phát video: {e}"
            self.status_label.config(text=error_msg)
            print(f"[VIDEO ERROR] {error_msg}")
            
            # Hiển thị hướng dẫn cài đặt
            self.placeholder.config(text="❌ Không thể phát video\n\n"
                                         "Cần cài đặt video player:\n"
                                         "• VLC: https://www.videolan.org/vlc/\n"
                                         "• Hoặc đảm bảo Windows có app mở video\n\n"
                                         "Video sẽ mở bằng app mặc định của hệ thống")
    
    def pause_video(self):
        """Tạm dừng video"""
        if self.video_process:
            try:
                self.video_process.terminate()
                self.is_playing = False
                self.status_label.config(text="Video đã tạm dừng")
                self.placeholder.config(text="⏸️ Video đã tạm dừng\n\nBấm Play để tiếp tục")
            except Exception as e:
                self.status_label.config(text=f"Lỗi tạm dừng: {e}")
    
    def stop_video(self):
        """Dừng video"""
        if self.video_process:
            try:
                self.video_process.terminate()
                self.video_process = None
                self.is_playing = False
                self.status_label.config(text="Video đã dừng")
                self.placeholder.config(text="⏹️ Video đã dừng")
            except Exception as e:
                self.status_label.config(text=f"Lỗi dừng video: {e}")
    
    def next_video(self):
        """Chuyển video tiếp theo"""
        if not self.video_files:
            return
            
        was_playing = self.is_playing
        self.stop_video()
        
        self.current_video = (self.current_video + 1) % len(self.video_files)
        
        if was_playing:
            self.play_video()
        else:
            next_video = self.video_files[self.current_video]
            self.status_label.config(text=f"Video tiếp theo: {next_video.name}")
    
    def _adjust_volume(self):
        """Điều chỉnh âm lượng (placeholder)"""
        from tkinter import messagebox
        messagebox.showinfo("Volume", "Điều chỉnh âm lượng trong cửa sổ video player")
    
    def auto_play_on_generate_start(self):
        """Tự động phát video khi bắt đầu generate"""
        if self.video_enabled.get() and self.video_files and not self.is_playing:
            self.play_video()
    
    def auto_stop_on_generate_end(self):
        """Tự động dừng video khi kết thúc generate"""
        if self.is_playing:
            self.stop_video()


class WuxiaEnergyBar(tk.Canvas):
    """Canvas based progress bar with a subtle moving qi/energy shimmer."""

    def __init__(self, parent, variable, height=78, **kwargs):
        super().__init__(parent, height=height, highlightthickness=0, bg="#FFFFFF", **kwargs)
        self.variable = variable
        self.phase = 0.0
        self._job = None
        self.bind("<Configure>", lambda _e: self.draw())
        try:
            self.variable.trace_add("write", lambda *_: self.draw())
        except Exception:
            pass
        self.start()

    def start(self):
        if self._job is None:
            self._tick()

    def stop(self):
        if self._job is not None:
            self.after_cancel(self._job)
            self._job = None

    def _tick(self):
        self.phase += 0.16
        self.draw()
        self._job = self.after(80, self._tick)

    def draw(self):
        self.delete("all")
        w = max(self.winfo_width(), 400)
        h = max(self.winfo_height(), 60)
        pct = 0.0
        try:
            pct = max(0.0, min(100.0, float(self.variable.get())))
        except Exception:
            pct = 0.0

        # Soft misty mountain banner background.
        self.create_rectangle(0, 0, w, h, fill="#F8FBFF", outline="#D8E5F5")
        for i in range(6):
            x = i * w / 5 - 60
            y = 24 + (i % 2) * 10
            self.create_polygon(
                x, h - 8, x + 110, y, x + 220, h - 8,
                fill="#E7F0FA", outline="", smooth=True,
            )
        for i in range(0, int(w), 110):
            self.create_arc(i - 40, 6, i + 100, 50, start=10, extent=160, outline="#DCEBFA", width=1)

        pad_x, bar_y, bar_h = 28, 26, 28
        bar_w = max(120, w - 190)
        radius = 14
        fill_w = max(radius * 2, bar_w * pct / 100.0)

        # Track.
        self._rounded_rect(pad_x, bar_y, pad_x + bar_w, bar_y + bar_h, radius, fill="#E8EDF6", outline="#A7B2C6", width=1)
        self._rounded_rect(pad_x + 2, bar_y + 2, pad_x + bar_w - 2, bar_y + bar_h - 2, radius - 2, fill="#1E2B4A", outline="")

        # Energy fill.
        self._rounded_rect(pad_x + 3, bar_y + 3, pad_x + fill_w - 3, bar_y + bar_h - 3, radius - 3, fill="#1689FF", outline="")
        self._rounded_rect(pad_x + 4, bar_y + 5, pad_x + fill_w - 4, bar_y + 14, 7, fill="#7BE7FF", outline="")
        self._rounded_rect(pad_x + 4, bar_y + 14, pad_x + fill_w - 4, bar_y + bar_h - 4, 7, fill="#0B4BD2", outline="")

        # Moving qi waves inside the filled section.
        clip_right = pad_x + fill_w - 4
        if fill_w > 34:
            for wave in range(3):
                points = []
                offset = self.phase * (18 + wave * 5) + wave * 25
                for x in range(pad_x + 8, int(clip_right), 8):
                    y = bar_y + bar_h / 2 + math.sin((x + offset) / 22.0) * (4 + wave)
                    points.extend([x, y])
                if len(points) >= 4:
                    self.create_line(*points, fill="#C9FAFF", width=2, smooth=True)
            orb_x = max(pad_x + radius, min(clip_right, pad_x + fill_w - 8))
            glow = 5 + math.sin(self.phase) * 2
            self.create_oval(orb_x - 15 - glow, bar_y - glow, orb_x + 15 + glow, bar_y + bar_h + glow, fill="#89F8FF", outline="")
            self.create_oval(orb_x - 12, bar_y + 3, orb_x + 12, bar_y + bar_h - 3, fill="#EFFFFF", outline="#7BE7FF")

        self.create_text(pad_x + bar_w / 2, bar_y + bar_h / 2, text=f"{pct:.0f}%", fill="#FFFFFF", font=("Segoe UI", 11, "bold"))
        self.create_text(w - 78, bar_y + 12, text=f"Nội lực {pct:.0f}%", fill="#1976F2", font=("Segoe UI", 16, "bold italic"))
        self.create_text(w - 76, bar_y + 36, text="☁", fill="#4A9CFF", font=("Segoe UI", 22, "bold"))

    def _rounded_rect(self, x1, y1, x2, y2, r, **kwargs):
        points = [
            x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
            x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
            x1, y2, x1, y2 - r, x1, y1 + r, x1, y1,
        ]
        return self.create_polygon(points, smooth=True, **kwargs)


class WuxiaMascotPanel(tk.Canvas):
    """Cute waiting panel.  It is deliberately lightweight: no image files."""

    def __init__(self, parent, app, width=520, height=300, **kwargs):
        super().__init__(parent, width=width, height=height, bg="#F8FBFF", highlightthickness=0, **kwargs)
        self.app = app
        self.phase = 0.0
        self.tip_index = 0
        self._last_tip = time.time()
        self._job = None
        self.bind("<Configure>", lambda _e: self.draw())
        self.start()

    def start(self):
        if self._job is None:
            self._tick()

    def stop(self):
        if self._job is not None:
            self.after_cancel(self._job)
            self._job = None

    def _tick(self):
        self.phase += 0.13
        if time.time() - self._last_tip > 5:
            self.tip_index = (self.tip_index + 1) % len(WUXIA_TIPS)
            self._last_tip = time.time()
        self.draw()
        self._job = self.after(90, self._tick)

    def draw(self):
        self.delete("all")
        w = max(self.winfo_width(), 420)
        h = max(self.winfo_height(), 260)
        stage = self.app.state.progress_stage.get()
        detail = self.app.state.progress_detail.get()
        pct = 0
        try:
            pct = int(float(self.app.state.progress_percent.get()))
        except Exception:
            pass

        # Card background.
        self.create_rectangle(0, 0, w, h, fill="#F8FBFF", outline="#CAD8EA")
        self.create_rectangle(2, 2, w - 2, h - 2, fill="#FFFFFF", outline="#E3EAF5")
        self._misty_background(w, h)
        self._draw_chibi(max(128, w * 0.30), h * 0.62)
        self._draw_info_card(w, h, stage, detail, pct)
        self._draw_tips_box(w, h)

    def _misty_background(self, w, h):
        for i in range(5):
            x = i * w / 4 - 60
            y = h * 0.32 + (i % 2) * 14
            self.create_polygon(x, h - 52, x + 92, y, x + 190, h - 52, fill="#DDECF8", outline="", smooth=True)
        for x in range(-20, int(w), 82):
            self.create_line(x, h - 65, x + 10, h - 130, fill="#8FBCA8", width=2)
            self.create_line(x + 12, h - 70, x + 22, h - 144, fill="#B2D4BD", width=1)
        for i in range(10):
            x = (i * 77 + int(self.phase * 7)) % int(max(w, 1))
            y = 28 + (i * 37) % int(max(h - 100, 1))
            self.create_text(x, y, text="✦", fill="#9CDFFF", font=("Segoe UI", 10 + (i % 3)))

    def _draw_chibi(self, cx, base_y):
        bob = math.sin(self.phase) * 3
        qi_r = 56 + math.sin(self.phase * 1.6) * 6
        # Qi rings.
        for i in range(3):
            r = qi_r + i * 15
            self.create_arc(cx - r, base_y - 86 - r / 4, cx + r, base_y + 16 + r / 4,
                            start=20 + self.phase * 40 + i * 55, extent=130,
                            outline="#45B8FF", width=2)
        # Legs/body.
        self.create_oval(cx - 70, base_y - 25, cx + 70, base_y + 32, fill="#DCE7F4", outline="#5B6F8D", width=2)
        self.create_oval(cx - 38, base_y - 92 + bob, cx + 38, base_y - 18 + bob, fill="#263A5A", outline="#15243D", width=2)
        self.create_polygon(cx - 42, base_y - 68 + bob, cx + 42, base_y - 68 + bob, cx + 26, base_y - 14 + bob, cx - 26, base_y - 14 + bob,
                            fill="#E9EEF8", outline="#425B7F", width=2)
        self.create_polygon(cx - 10, base_y - 68 + bob, cx + 22, base_y - 66 + bob, cx + 5, base_y - 12 + bob,
                            fill="#BFD7F2", outline="")
        # Head and hair.
        self.create_oval(cx - 38, base_y - 150 + bob, cx + 38, base_y - 76 + bob, fill="#F6D2B8", outline="#3A2E39", width=2)
        self.create_arc(cx - 46, base_y - 157 + bob, cx + 46, base_y - 80 + bob, start=0, extent=180, fill="#1A2438", outline="#111827", width=2)
        self.create_polygon(cx - 36, base_y - 116 + bob, cx - 18, base_y - 148 + bob, cx - 6, base_y - 116 + bob, fill="#1A2438", outline="")
        self.create_polygon(cx + 6, base_y - 116 + bob, cx + 22, base_y - 147 + bob, cx + 38, base_y - 116 + bob, fill="#1A2438", outline="")
        self.create_oval(cx - 12, base_y - 185 + bob, cx + 24, base_y - 145 + bob, fill="#1A2438", outline="#111827")
        self.create_text(cx + 6, base_y - 166 + bob, text="☯", fill="#9CE7FF", font=("Segoe UI", 13, "bold"))
        # Face.
        self.create_arc(cx - 21, base_y - 117 + bob, cx - 6, base_y - 107 + bob, start=200, extent=130, outline="#1F2937", width=2)
        self.create_arc(cx + 8, base_y - 117 + bob, cx + 23, base_y - 107 + bob, start=200, extent=130, outline="#1F2937", width=2)
        self.create_line(cx - 8, base_y - 94 + bob, cx + 8, base_y - 94 + bob, fill="#9B4A4A", width=2)
        # Hands.
        self.create_oval(cx - 25, base_y - 52 + bob, cx - 8, base_y - 35 + bob, fill="#F6D2B8", outline="#6B4B41")
        self.create_oval(cx + 8, base_y - 52 + bob, cx + 25, base_y - 35 + bob, fill="#F6D2B8", outline="#6B4B41")
        # Sword and laptop.
        self.create_line(cx + 68, base_y - 22, cx + 106, base_y - 124, fill="#25344F", width=5)
        self.create_line(cx + 58, base_y - 76, cx + 85, base_y - 66, fill="#B08D57", width=5)
        self.create_rectangle(cx + 36, base_y - 28, cx + 112, base_y + 24, fill="#22314F", outline="#0F172A", width=2)
        self.create_text(cx + 74, base_y - 2, text="☯", fill="#7BE7FF", font=("Segoe UI", 22, "bold"))

    def _draw_info_card(self, w, h, stage, detail, pct):
        x1, y1 = w * 0.56, 34
        x2, y2 = w - 24, min(h - 78, 190)
        self._rounded_rect(x1, y1, x2, y2, 18, fill="#FFFFFF", outline="#CAD8EA", width=2)
        self.create_text(x1 + 18, y1 + 22, text="Đang luyện công tạo YARA...", anchor="w", fill="#13264A", font=("Segoe UI", 14, "bold"))
        self.create_text(x1 + 18, y1 + 50, text="Nội lực đang tụ...", anchor="w", fill="#334155", font=("Segoe UI", 10, "bold"))
        # Mini progress.
        bx1, by1, bw, bh = x1 + 18, y1 + 72, max(130, x2 - x1 - 95), 14
        self._rounded_rect(bx1, by1, bx1 + bw, by1 + bh, 7, fill="#E4E9F2", outline="#B9C4D8")
        self._rounded_rect(bx1 + 2, by1 + 2, bx1 + 2 + (bw - 4) * pct / 100.0, by1 + bh - 2, 6, fill="#42BEFF", outline="")
        self.create_text(bx1 + bw + 10, by1 + 7, text=f"{pct}%", anchor="w", fill="#13264A", font=("Segoe UI", 9, "bold"))
        self.create_text(x1 + 18, y1 + 105, text=f"☯  Tầng hiện tại: {stage}", anchor="w", fill="#1D4ED8", font=("Segoe UI", 10, "bold"))
        exp = STAGE_EXP.get(stage, max(0, pct * 8))
        self.create_text(x1 + 18, y1 + 132, text=f"✨  Kinh nghiệm: +{exp} exp", anchor="w", fill="#B7791F", font=("Segoe UI", 10, "bold"))
        if detail:
            short = detail if len(detail) < 38 else detail[:35] + "..."
            self.create_text(x1 + 18, y1 + 156, text=f"📌  {short}", anchor="w", fill="#64748B", font=("Segoe UI", 9))

    def _draw_tips_box(self, w, h):
        x1, y1 = w * 0.56, max(198, h - 86)
        x2, y2 = w - 24, h - 18
        self._rounded_rect(x1, y1, x2, y2, 14, fill="#FFFCF5", outline="#F4D8A8", width=1)
        self.create_text(x1 + 16, y1 + 18, text="Mẹo chờ cho vui ✨", anchor="w", fill="#7C4A03", font=("Segoe UI", 10, "bold"))
        tips = [WUXIA_TIPS[self.tip_index], WUXIA_TIPS[(self.tip_index + 2) % len(WUXIA_TIPS)]]
        for i, tip in enumerate(tips):
            self.create_text(x1 + 16, y1 + 42 + i * 22, text="• " + tip, anchor="w", fill="#475569", font=("Segoe UI", 9))

    def _rounded_rect(self, x1, y1, x2, y2, r, **kwargs):
        points = [
            x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
            x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
            x1, y2, x1, y2 - r, x1, y1 + r, x1, y1,
        ]
        return self.create_polygon(points, smooth=True, **kwargs)


class MonitorScreen(ScrollableScreen):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        self._status_started_at = None
        self._ticker_job = None
        
        # Layout configuration variables
        self.layout_mode = tk.StringVar(value="horizontal")  # horizontal, vertical, tabbed
        self.log_height = tk.IntVar(value=15)
        self.mascot_height = tk.IntVar(value=300)
        self.show_advanced = tk.BooleanVar(value=False)
        self.show_video = tk.BooleanVar(value=True)  # Thêm option hiển thị video
        
        # Video player
        self.video_player = None
        
        self.build()

    def refresh_text(self):
        # Labels are intentionally mostly static because this screen is demo-oriented
        # and contains Vietnamese humor even when the app language is English.
        pass

    def on_mode_changed(self):
        pass

    def on_show(self):
        self._start_footer_timer()

    def build(self):
        # Create scrollable content
        content = self.create_scrollable_content(self.app.t("monitor.title"))
        
        # Layout configuration frame
        layout_frame = ttk.LabelFrame(content, text="Cấu hình giao diện", padding=8)
        layout_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        layout_frame.columnconfigure(2, weight=1)
        
        ttk.Label(layout_frame, text="Layout:", style="Card.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8))
        layout_combo = ttk.Combobox(layout_frame, textvariable=self.layout_mode, 
                                   values=["horizontal", "vertical", "tabbed"], 
                                   state="readonly", width=12)
        layout_combo.grid(row=0, column=1, sticky="w", padx=(0, 16))
        layout_combo.bind("<<ComboboxSelected>>", self._on_layout_changed)
        
        ttk.Label(layout_frame, text="Chiều cao log:", style="Card.TLabel").grid(row=0, column=2, sticky="w", padx=(0, 8))
        log_height_spin = ttk.Spinbox(layout_frame, from_=10, to=50, textvariable=self.log_height, 
                                     width=8, command=self._on_layout_changed)
        log_height_spin.grid(row=0, column=3, sticky="w", padx=(0, 16))
        
        ttk.Label(layout_frame, text="Chiều cao mascot:", style="Card.TLabel").grid(row=0, column=4, sticky="w", padx=(0, 8))
        mascot_height_spin = ttk.Spinbox(layout_frame, from_=200, to=500, textvariable=self.mascot_height, 
                                        width=8, command=self._on_layout_changed)
        mascot_height_spin.grid(row=0, column=5, sticky="w", padx=(0, 16))
        
        ttk.Checkbutton(layout_frame, text="Hiện cài đặt nâng cao", 
                       variable=self.show_advanced, 
                       command=self._on_layout_changed).grid(row=0, column=6, sticky="w", padx=(0, 8))
        
        ttk.Checkbutton(layout_frame, text="Hiện video giải trí", 
                       variable=self.show_video, 
                       command=self._on_layout_changed).grid(row=0, column=7, sticky="w")
        
        # Title and status
        title_row = ttk.Frame(content, style="App.TFrame")
        title_row.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        title_row.columnconfigure(0, weight=1)
        
        self.status_badge = ttk.Label(title_row, text="Sẵn sàng nhập môn ☯", style="Pill.TLabel")
        self.status_badge.grid(row=0, column=1, sticky="e", padx=4)

        # Progress dashboard
        dash = ttk.Frame(content, style="Card.TFrame", padding=12)
        dash.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        dash.columnconfigure(0, weight=1)

        stage_header = ttk.Frame(dash, style="Surface.TFrame")
        stage_header.grid(row=0, column=0, sticky="ew")
        stage_header.columnconfigure(1, weight=1)
        ttk.Label(stage_header, text="Stage:", style="Card.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(stage_header, textvariable=self.app.state.progress_stage, style="Accent.H2.TLabel").grid(row=0, column=1, sticky="w", padx=(4, 0))

        self.energy = WuxiaEnergyBar(dash, self.app.state.progress_percent)
        self.energy.grid(row=1, column=0, sticky="ew", pady=(8, 4))
        ttk.Label(dash, textvariable=self.app.state.progress_detail, style="Muted.TLabel").grid(row=2, column=0, sticky="w", pady=(2, 7))

        self.stage_tree = ttk.Treeview(dash, columns=("stage", "status", "detail"), show="headings", height=6)
        for col, width in [("stage", 300), ("status", 145), ("detail", 720)]:
            self.stage_tree.heading(col, text=col)
            self.stage_tree.column(col, width=width, anchor="w")
        self.stage_tree.tag_configure("current", background="#EAF4FF", foreground="#0F2C59")
        self.stage_tree.tag_configure("done", background="#F0FDF4", foreground="#166534")
        self.stage_tree.tag_configure("wait", background="#FFFFFF", foreground="#475569")
        self.stage_tree.tag_configure("error", background="#FEF2F2", foreground="#991B1B")
        self.stage_tree.grid(row=3, column=0, sticky="ew", pady=(0, 2))

        # Quick actions
        actions = ttk.LabelFrame(content, text="Quick actions", padding=(8, 6))
        actions.grid(row=3, column=0, sticky="ew", pady=(0, 8))
        for c in range(4):
            actions.columnconfigure(c, weight=1, uniform="actions")
        action_buttons = [
            (self.app.t("monitor.clear"), lambda: self.log_text.delete("1.0", "end"), "🧹"),
            (self.app.t("monitor.open_rule"), lambda: open_path(Path(self.app.state.var_output.get())), "📂"),
            (self.app.t("monitor.open_folder"), lambda: open_path(Path(self.app.state.var_output.get()).parent), "🗂"),
            ("Validate output rule", lambda: self.app.screens["validate"].validate_rule_file(Path(self.app.state.var_output.get()), True), "🛡"),
            ("Rule Score Report", self.open_rule_score_report, "📊"),
            ("Copy Rule", self.copy_rule_to_clipboard, "📋"),
            ("Refresh Status", self.refresh_all_status, "🔄"),
        ]
        for idx, (label, command, emoji) in enumerate(action_buttons):
            btn = ttk.Button(actions, text=f"{emoji}  {label}", command=command, style="Wuxia.TButton")
            btn.grid(row=idx // 4, column=idx % 4, sticky="ew", padx=4, pady=3)

        # Main content area
        self.main_frame = ttk.Frame(content, style="App.TFrame")
        self.main_frame.grid(row=4, column=0, sticky="nsew", pady=(8, 0))
        content.rowconfigure(4, weight=1)
        
        # Summary footer
        self.summary = ttk.Label(content, text="YARA summary: no rule yet.", style="Footer.TLabel")
        self.summary.grid(row=5, column=0, sticky="ew", pady=(8, 0))
        
        self._build_layout()
        self.reset_progress()
        self._start_footer_timer()

    def _build_layout(self):
        # Clear existing widgets
        for widget in self.main_frame.winfo_children():
            widget.destroy()
            
        layout = self.layout_mode.get()
        
        if layout == "tabbed":
            self._build_tabbed_layout()
        elif layout == "vertical":
            self._build_vertical_layout()
        else:  # horizontal
            self._build_horizontal_layout()

    def _build_tabbed_layout(self):
        """Build tabbed interface layout"""
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(0, weight=1)
        
        notebook = ttk.Notebook(self.main_frame)
        notebook.grid(row=0, column=0, sticky="nsew")
        
        # Log Tab
        log_frame = ttk.Frame(notebook, style="App.TFrame", padding=14)
        notebook.add(log_frame, text="📜 Process Log")
        self._build_log_area(log_frame, full_height=True)
        
        # Mascot Tab
        mascot_frame = ttk.Frame(notebook, style="App.TFrame", padding=14)
        notebook.add(mascot_frame, text="🎭 Wuxia Mascot")
        self._build_mascot_area(mascot_frame, full_height=True)
        
        # Advanced Settings Tab
        if self.show_advanced.get():
            settings_frame = ttk.Frame(notebook, style="App.TFrame", padding=14)
            notebook.add(settings_frame, text="⚙️ Advanced Settings")
            self._build_advanced_settings(settings_frame)

    def _build_vertical_layout(self):
        """Build vertical stacked layout"""
        self.main_frame.columnconfigure(0, weight=1)
        row_count = 1
        
        # Mascot on top
        mascot_card = ttk.Frame(self.main_frame, style="Card.TFrame", padding=14)
        mascot_card.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        self._build_mascot_area(mascot_card)
        
        # Video area if enabled
        if self.show_video.get():
            video_card = ttk.Frame(self.main_frame, style="Card.TFrame", padding=14)
            video_card.grid(row=row_count, column=0, sticky="ew", pady=(0, 10))
            self._build_video_area(video_card)
            row_count += 1
        
        # Log below
        log_card = ttk.Frame(self.main_frame, style="Card.TFrame", padding=14)
        log_card.grid(row=row_count, column=0, sticky="nsew")
        self._build_log_area(log_card)
        self.main_frame.rowconfigure(row_count, weight=1)
        row_count += 1
        
        # Advanced settings at bottom if enabled
        if self.show_advanced.get():
            settings_card = ttk.Frame(self.main_frame, style="Card.TFrame", padding=14)
            settings_card.grid(row=row_count, column=0, sticky="ew", pady=(10, 0))
            self._build_advanced_settings(settings_card)

    def _build_horizontal_layout(self):
        """Build horizontal side-by-side layout (original)"""
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.columnconfigure(1, weight=1)
        self.main_frame.rowconfigure(0, weight=1)
        
        # Log on left
        log_card = ttk.Frame(self.main_frame, style="Card.TFrame", padding=14)
        log_card.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        self._build_log_area(log_card)
        
        # Mascot on right
        mascot_card = ttk.Frame(self.main_frame, style="Card.TFrame", padding=14)
        mascot_card.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        self._build_mascot_area(mascot_card)
        
        # Advanced settings below if enabled
        if self.show_advanced.get():
            self.main_frame.rowconfigure(1, weight=0)
            settings_card = ttk.Frame(self.main_frame, style="Card.TFrame", padding=14)
            settings_card.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(10, 0))
            self._build_advanced_settings(settings_card)

    def _build_log_area(self, parent, full_height=False):
        """Build log display area"""
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)
        
        # Log header with controls
        log_header = ttk.Frame(parent, style="Surface.TFrame")
        log_header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        log_header.columnconfigure(0, weight=1)
        
        ttk.Label(log_header, text="📜 Process Log", style="H1.TLabel").grid(row=0, column=0, sticky="w")
        
        # Log controls
        controls_frame = ttk.Frame(log_header, style="Surface.TFrame")
        controls_frame.grid(row=0, column=1, sticky="e")
        
        ttk.Button(controls_frame, text="Clear", command=lambda: self.log_text.delete("1.0", "end"), 
                  style="Secondary.TButton").grid(row=0, column=0, padx=(0, 4))
        ttk.Button(controls_frame, text="Save Log", command=self._save_log, 
                  style="Secondary.TButton").grid(row=0, column=1, padx=(0, 4))
        ttk.Button(controls_frame, text="Find", command=self._find_in_log, 
                  style="Secondary.TButton").grid(row=0, column=2)
        
        # Log text area
        log_frame = ttk.Frame(parent, style="Surface.TFrame")
        log_frame.grid(row=1, column=0, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        height = 30 if full_height else self.log_height.get()
        self.log_text = ScrolledText(log_frame, wrap="word", font=("Consolas", 9), 
                                    background="#FBFDFF", foreground="#0F172A", 
                                    insertbackground="#0F172A", relief="flat", 
                                    borderwidth=8, height=height)
        self.log_text.grid(row=0, column=0, sticky="nsew")

    def _build_mascot_area(self, parent, full_height=False):
        """Build mascot display area"""
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)
        
        # Mascot header
        mascot_header = ttk.Frame(parent, style="Surface.TFrame")
        mascot_header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        mascot_header.columnconfigure(0, weight=1)
        
        ttk.Label(mascot_header, text="🎭 Wuxia Mascot", style="H1.TLabel").grid(row=0, column=0, sticky="w")
        
        # Mascot controls
        controls_frame = ttk.Frame(mascot_header, style="Surface.TFrame")
        controls_frame.grid(row=0, column=1, sticky="e")
        
        ttk.Button(controls_frame, text="Pause", command=self._toggle_mascot, 
                  style="Secondary.TButton").grid(row=0, column=0, padx=(0, 4))
        ttk.Button(controls_frame, text="Reset", command=self._reset_mascot, 
                  style="Secondary.TButton").grid(row=0, column=1)
        
        # Mascot canvas
        mascot_frame = ttk.Frame(parent, style="Surface.TFrame")
        mascot_frame.grid(row=1, column=0, sticky="nsew")
        mascot_frame.columnconfigure(0, weight=1)
        mascot_frame.rowconfigure(0, weight=1)
        
        height = 400 if full_height else self.mascot_height.get()
        self.preview = WuxiaMascotPanel(mascot_frame, self.app, height=height)
        self.preview.grid(row=0, column=0, sticky="nsew")

    def _build_advanced_settings(self, parent):
        """Build advanced settings panel"""
        parent.columnconfigure(0, weight=1)
        
        ttk.Label(parent, text="⚙️ Advanced Monitor Settings", style="H1.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 8))
        
        settings_notebook = ttk.Notebook(parent)
        settings_notebook.grid(row=1, column=0, sticky="ew")
        
        # Log settings
        log_frame = ttk.Frame(settings_notebook, padding=10)
        settings_notebook.add(log_frame, text="Log")
        
        ttk.Label(log_frame, text="Log retention lines:", style="Card.TLabel").grid(row=0, column=0, sticky="w", pady=4)
        log_retention_var = tk.IntVar(value=8000)
        ttk.Spinbox(log_frame, from_=1000, to=50000, textvariable=log_retention_var, width=10).grid(row=0, column=1, sticky="w", padx=(8, 0), pady=4)
        
        ttk.Checkbutton(log_frame, text="Auto-scroll to bottom").grid(row=1, column=0, sticky="w", pady=2)
        ttk.Checkbutton(log_frame, text="Highlight errors").grid(row=2, column=0, sticky="w", pady=2)
        ttk.Checkbutton(log_frame, text="Show timestamps").grid(row=3, column=0, sticky="w", pady=2)
        
        # Animation settings
        animation_frame = ttk.Frame(settings_notebook, padding=10)
        settings_notebook.add(animation_frame, text="Animation")
        
        ttk.Label(animation_frame, text="Animation speed:", style="Card.TLabel").grid(row=0, column=0, sticky="w", pady=4)
        speed_var = tk.DoubleVar(value=1.0)
        ttk.Scale(animation_frame, from_=0.1, to=3.0, variable=speed_var, orient="horizontal").grid(row=0, column=1, sticky="ew", padx=(8, 0), pady=4)
        
        ttk.Checkbutton(animation_frame, text="Enable mascot animation").grid(row=1, column=0, sticky="w", pady=2)
        ttk.Checkbutton(animation_frame, text="Enable energy bar effects").grid(row=2, column=0, sticky="w", pady=2)
        ttk.Checkbutton(animation_frame, text="Show floating particles").grid(row=3, column=0, sticky="w", pady=2)

    def _on_layout_changed(self, event=None):
        """Handle layout mode change"""
        self._build_layout()

    def _save_log(self):
        """Save log to file"""
        from tkinter import filedialog
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Process Log"
        )
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.log_text.get(1.0, tk.END))
                self.log(f"[SAVED] Log saved to {filename}\n")
            except Exception as e:
                self.log(f"[ERROR] Failed to save log: {e}\n")

    def _find_in_log(self):
        """Find text in log"""
        from tkinter import simpledialog
        search_text = simpledialog.askstring("Find", "Enter text to search:")
        if search_text:
            # Simple search implementation
            content = self.log_text.get(1.0, tk.END)
            start_pos = content.find(search_text)
            if start_pos != -1:
                # Convert to tkinter text position
                lines_before = content[:start_pos].count('\n')
                char_pos = start_pos - content[:start_pos].rfind('\n') - 1
                if char_pos < 0:
                    char_pos = start_pos
                pos = f"{lines_before + 1}.{char_pos}"
                end_pos = f"{lines_before + 1}.{char_pos + len(search_text)}"
                
                self.log_text.tag_remove("search", 1.0, tk.END)
                self.log_text.tag_add("search", pos, end_pos)
                self.log_text.tag_config("search", background="yellow")
                self.log_text.see(pos)
            else:
                self.log(f"[INFO] Text '{search_text}' not found\n")

    def _toggle_mascot(self):
        """Toggle mascot animation"""
        if hasattr(self, 'preview'):
            if self.preview._job:
                self.preview.stop()
            else:
                self.preview.start()

    def _reset_mascot(self):
        """Reset mascot animation"""
        if hasattr(self, 'preview'):
            self.preview.phase = 0.0
            self.preview.tip_index = 0
            self.preview._last_tip = time.time()

    def _start_footer_timer(self):
        if self._ticker_job is None:
            self._status_started_at = self._status_started_at or time.time()
            self._footer_tick()

    def _footer_tick(self):
        elapsed = int(time.time() - (self._status_started_at or time.time()))
        pct = 0.0
        try:
            pct = float(self.app.state.progress_percent.get())
        except Exception:
            pass
        remaining = "--:--"
        if pct > 2 and pct < 100:
            total = elapsed / max(pct / 100.0, 0.01)
            left = max(0, int(total - elapsed))
            remaining = f"~00:{left:02d}" if left < 60 else f"~{left//60:02d}:{left%60:02d}"
        elif pct >= 100:
            remaining = "done"
        self.status_badge.configure(text=self._badge_text())
        self._ticker_job = self.after(1000, self._footer_tick)

    def _badge_text(self):
        stage = self.app.state.progress_stage.get()
        pct = 0
        try:
            pct = int(float(self.app.state.progress_percent.get()))
        except Exception:
            pass
        if stage == "Finished" or pct >= 100:
            return "Xuất quan thành công ✅"
        if stage == "Error":
            return "Tẩu hỏa nhập ma ⚠"
        if stage == "Idle":
            return "Sẵn sàng nhập môn ☯"
        return "Đang luyện công... ⏳"

    def reset_progress(self):
        s = self.app.state
        s.progress_stage.set("Idle")
        s.progress_percent.set(0)
        s.progress_detail.set("No process running.")
        s.progress_db_loaded = 0
        s.progress_samples_done = 0
        s.progress_simple_rules = 0
        s.progress_super_rules = 0
        self._status_started_at = time.time()
        for item in self.stage_tree.get_children():
            self.stage_tree.delete(item)
        for stage in STAGE_ROWS:
            self.stage_tree.insert("", "end", iid=stage[0], values=stage[1:], tags=("wait",))

    def set_stage(self, iid, status, detail=""):
        if self.stage_tree.exists(iid):
            vals = list(self.stage_tree.item(iid, "values"))
            self.stage_tree.item(iid, values=(vals[0], status, detail))
            low = str(status).lower()
            tag = "wait"
            if "run" in low:
                tag = "current"
            elif "done" in low or "ok" in low:
                tag = "done"
            elif "error" in low or "fail" in low:
                tag = "error"
            self.stage_tree.item(iid, tags=(tag,))

    def log(self, text):
        self.log_text.insert("end", text)
        try:
            lines = int(float(self.log_text.index("end-1c").split(".")[0]))
            limit = int(self.app.settings.get("log_retention_lines", 8000))
            if lines > limit:
                self.log_text.delete("1.0", "1200.0")
                self.log_text.insert("1.0", "[Log trimmed]\n")
        except Exception:
            pass
        self.log_text.see("end")

    def update_progress_from_log_line(self, line):
        s = self.app.state
        low = line.lower()
        if self._status_started_at is None:
            self._status_started_at = time.time()
        if "generate yara rules" in low or "cmd:" in low:
            s.progress_stage.set("Preflight")
            s.progress_percent.set(max(s.progress_percent.get(), 3))
            s.progress_detail.set("Command prepared. Waiting for yarGen output...")
            self.set_stage("1", "Running", "Starting subprocess")
        if "reading goodware strings" in low:
            s.progress_stage.set("Load goodware DB")
            s.progress_percent.set(max(s.progress_percent.get(), 5))
            self.set_stage("1", "Done", "Preflight OK")
            self.set_stage("2", "Running", "Loading DB")
        if "[+] loading ./dbs/" in low or "[+] loading .\\dbs\\" in low:
            s.progress_db_loaded += 1
            s.progress_percent.set(max(s.progress_percent.get(), min(45, 8 + s.progress_db_loaded)))
            s.progress_detail.set(line.strip())
            self.set_stage("2", "Running", f"{s.progress_db_loaded} DB files")
        if "[+] processing malware files" in low:
            s.progress_stage.set("Extract strings/opcodes")
            s.progress_percent.set(max(s.progress_percent.get(), 50))
            self.set_stage("2", "Done", "DB loaded")
            self.set_stage("3", "Running", "Processing samples")
        if "[+] processing " in low and "processing malware files" not in low and "pestudio" not in low:
            s.progress_samples_done += 1
            s.progress_percent.set(max(s.progress_percent.get(), min(70, 50 + s.progress_samples_done * 4)))
            s.progress_detail.set(f"Sample: {s.progress_samples_done}")
            self.set_stage("3", "Running", f"{s.progress_samples_done} samples")
        if "generating statistical data" in low:
            s.progress_stage.set("Generate statistics")
            s.progress_percent.set(max(s.progress_percent.get(), 74))
            self.set_stage("3", "Done", f"{s.progress_samples_done} samples")
            self.set_stage("4", "Running", "Calculating overlap/score")
        if "generating simple rules" in low or "generating super rules" in low:
            s.progress_stage.set("Generate rules")
            s.progress_percent.set(max(s.progress_percent.get(), 86))
            self.set_stage("4", "Done", "Statistics ready")
            self.set_stage("5", "Running", "Creating rules")
        m = re.search(r"Generated\s+(\d+)\s+SIMPLE", line, re.I)
        if m:
            s.progress_simple_rules = int(m.group(1))
            s.progress_percent.set(max(s.progress_percent.get(), 92))
        m = re.search(r"Generated\s+(\d+)\s+SUPER", line, re.I)
        if m:
            s.progress_super_rules = int(m.group(1))
            s.progress_percent.set(max(s.progress_percent.get(), 96))
            self.set_stage("5", "Done", f"{s.progress_simple_rules} simple, {s.progress_super_rules} super")
            self.set_stage("6", "Running", "Ready for validation")
        if "[process exited]" in low:
            if "code=0" in low:
                s.progress_stage.set("Finished")
                s.progress_percent.set(100)
                s.progress_detail.set(f"Done. Simple={s.progress_simple_rules}, Super={s.progress_super_rules}")
                self.set_stage("6", "Done", "Process completed")
            else:
                s.progress_stage.set("Error")
                s.progress_detail.set(line.strip())
                self.set_stage("6", "Error", line.strip())

    def preview_output_rule(self, silent=False):
        # The right panel is now a live waiting mascot.  Keep rule preview available
        # through Open rule / Validate / Reports buttons rather than replacing it.
        p = Path(self.app.state.var_output.get())
        if not p.exists() and not silent:
            self.log(f"[WARN] Rule file not found: {p}\n")

    def refresh_yara_summary(self):
        p = Path(self.app.state.var_output.get())
        if not p.exists():
            return
        data = p.read_text(encoding="utf-8", errors="replace")
        rules = len(re.findall(r"(?m)^\s*(?:global\s+|private\s+)*rule\s+\w+", data))
        strings = len(re.findall(r"(?m)^\s*\$[A-Za-z0-9_]+\s*=", data))
        x_strings = len(re.findall(r"(?m)^\s*\$x\d+\s*=", data))
        s_strings = len(re.findall(r"(?m)^\s*\$s\d+\s*=", data))
        simple = rules
        super_rules = 0
        if "/* Super Rules" in data:
            before, after = data.split("/* Super Rules", 1)
            simple = len(re.findall(r"(?m)^\s*(?:global\s+|private\s+)*rule\s+\w+", before))
            super_rules = len(re.findall(r"(?m)^\s*(?:global\s+|private\s+)*rule\s+\w+", after))
        self.summary.configure(
            text=(
                f"☯ Engine: yarGen | Mode: {self.app.state.var_mode.get()} | "
                f"Output: {p.name} | rules={rules}, simple={simple}, super={super_rules}, "
                f"strings={strings}, $x={x_strings}, $s={s_strings}"
            )
        )

    def copy_rule_to_clipboard(self):
        try:
            rule_path = Path(self.app.state.var_output.get())
            if not rule_path.exists():
                self.log(f"[WARN] No rule file found to copy: {rule_path}\n")
                return
            self.app.clipboard_clear()
            self.app.clipboard_append(rule_path.read_text(encoding="utf-8", errors="replace"))
            self.log("[INFO] YARA rule copied to clipboard.\n")
        except Exception as exc:
            self.log(f"[ERROR] Failed to copy rule: {exc}\n")

    def refresh_all_status(self):
        try:
            self.refresh_yara_summary()
            self.preview_output_rule(silent=True)
            self.status_badge.configure(text=self._badge_text())
            self.log("[INFO] Status refreshed.\n")
        except Exception as exc:
            self.log(f"[ERROR] Failed to refresh status: {exc}\n")

    def open_rule_score_report(self):
        self.app.state.var_rule_score_file.set(self.app.state.var_output.get())
        self.app.show_screen("reports")
        self.app.screens["reports"].analyze_rule_scores()
