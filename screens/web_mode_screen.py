# -*- coding: utf-8 -*-
import os
import socket
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox
from core.scrollable_screen import ScrollableScreen

class WebModeScreen(ScrollableScreen):
    """Start/stop the built-in local web UI from the desktop app with scrollable interface and customizable layout."""
    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.process = None
        self.reader_thread = None
        self.url = tk.StringVar(value="http://127.0.0.1:8088")
        self.status = tk.StringVar(value="Stopped")
        self.host = tk.StringVar(value="127.0.0.1")
        self.port = tk.StringVar(value="8088")
        
        # Layout configuration variables
        self.layout_mode = tk.StringVar(value="horizontal")  # horizontal, vertical, tabbed
        self.log_height = tk.IntVar(value=15)
        self.show_advanced = tk.BooleanVar(value=False)
        
        self.build()

    def refresh_text(self):
        pass
    def on_mode_changed(self):
        pass
    def on_show(self):
        self._refresh_status()

    def build(self):
        # Create scrollable content
        content = self.create_scrollable_content("Web Mode - YARA Kiếm Các")
        
        # Description
        desc_frame = ttk.Frame(content, style="App.TFrame")
        desc_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        desc_frame.columnconfigure(0, weight=1)
        
        ttk.Label(desc_frame, 
                 text="Bấm Start để mở web local: upload sample/zip, chạy yarGen, xem progress, log và tải rule/report.", 
                 style="AppMuted.TLabel").grid(row=0, column=0, sticky="w")
        
        # Layout configuration frame
        layout_frame = ttk.LabelFrame(desc_frame, text="Cấu hình giao diện", padding=8)
        layout_frame.grid(row=1, column=0, sticky="ew", pady=(8, 0))
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
        
        ttk.Checkbutton(layout_frame, text="Hiện cài đặt nâng cao", 
                       variable=self.show_advanced, 
                       command=self._on_layout_changed).grid(row=0, column=4, sticky="w")
        
        # Main content area
        self.main_frame = ttk.Frame(content, style="App.TFrame")
        self.main_frame.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        content.rowconfigure(1, weight=1)
        
        self._build_layout()

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
        
        # Server Control Tab
        server_frame = ttk.Frame(notebook, style="App.TFrame", padding=14)
        notebook.add(server_frame, text="🚀 Server Control")
        self._build_server_controls(server_frame)
        
        # Logs Tab
        log_frame = ttk.Frame(notebook, style="App.TFrame", padding=14)
        notebook.add(log_frame, text="📜 Server Logs")
        self._build_log_area(log_frame, full_height=True)
        
        # Settings Tab
        if self.show_advanced.get():
            settings_frame = ttk.Frame(notebook, style="App.TFrame", padding=14)
            notebook.add(settings_frame, text="⚙️ Advanced Settings")
            self._build_advanced_settings(settings_frame)

    def _build_vertical_layout(self):
        """Build vertical stacked layout"""
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(1, weight=1)
        
        # Server controls on top
        server_card = ttk.Frame(self.main_frame, style="Card.TFrame", padding=14)
        server_card.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        self._build_server_controls(server_card)
        
        # Logs below
        log_card = ttk.Frame(self.main_frame, style="Card.TFrame", padding=14)
        log_card.grid(row=1, column=0, sticky="nsew")
        self._build_log_area(log_card)
        
        # Advanced settings at bottom if enabled
        if self.show_advanced.get():
            settings_card = ttk.Frame(self.main_frame, style="Card.TFrame", padding=14)
            settings_card.grid(row=2, column=0, sticky="ew", pady=(10, 0))
            self._build_advanced_settings(settings_card)

    def _build_horizontal_layout(self):
        """Build horizontal side-by-side layout (original)"""
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.columnconfigure(1, weight=1)
        self.main_frame.rowconfigure(0, weight=1)
        
        card = ttk.Frame(self.main_frame, style="Card.TFrame", padding=14)
        card.grid(row=0, column=0, columnspan=2, sticky="nsew")
        card.columnconfigure(0, weight=1)
        card.columnconfigure(1, weight=1)
        card.rowconfigure(0, weight=1)

        left = ttk.Frame(card, style="Surface.TFrame")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        right = ttk.Frame(card, style="Surface.TFrame")
        right.grid(row=0, column=1, sticky="nsew")
        
        self._build_server_controls(left)
        self._build_log_area(right)
        
        # Advanced settings below if enabled
        if self.show_advanced.get():
            card.rowconfigure(1, weight=0)
            settings_frame = ttk.Frame(card, style="Surface.TFrame")
            settings_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(12, 0))
            self._build_advanced_settings(settings_frame)

    def _build_server_controls(self, parent):
        """Build server control widgets"""
        parent.columnconfigure(1, weight=1)
        
        ttk.Label(parent, text="⚔ Local Web Server", style="H1.TLabel").grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 8))
        
        ttk.Label(parent, text="Host", style="Card.TLabel").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(parent, textvariable=self.host, width=18).grid(row=1, column=1, sticky="ew", pady=4, padx=6)
        
        ttk.Label(parent, text="Port", style="Card.TLabel").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Entry(parent, textvariable=self.port, width=18).grid(row=2, column=1, sticky="ew", pady=4, padx=6)
        
        # Button frame
        btn_frame = ttk.Frame(parent, style="Surface.TFrame")
        btn_frame.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(12, 4))
        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=1)
        btn_frame.columnconfigure(2, weight=1)
        
        ttk.Button(btn_frame, text="Start Web", command=self.start_server, style="Primary.TButton").grid(row=0, column=0, sticky="ew", padx=(0, 3))
        ttk.Button(btn_frame, text="Open Browser", command=self.open_browser, style="Wuxia.TButton").grid(row=0, column=1, sticky="ew", padx=3)
        ttk.Button(btn_frame, text="Stop", command=self.stop_server, style="Danger.TButton").grid(row=0, column=2, sticky="ew", padx=(3, 0))
        
        ttk.Label(parent, text="URL", style="Card.TLabel").grid(row=4, column=0, sticky="w", pady=4)
        ttk.Entry(parent, textvariable=self.url).grid(row=4, column=1, columnspan=2, sticky="ew", pady=4, padx=6)
        
        ttk.Label(parent, textvariable=self.status, style="Pill.TLabel").grid(row=5, column=0, columnspan=3, sticky="w", pady=(10, 0))

        # Safety notes
        notes = ttk.LabelFrame(parent, text="Lưu ý an toàn", padding=10)
        notes.grid(row=6, column=0, columnspan=3, sticky="ew", pady=(14, 0))
        ttk.Label(notes, text="• Web chạy local/sandbox, mặc định 127.0.0.1:8088.\n• Muốn điện thoại cùng Wi-Fi truy cập: đổi Host thành 0.0.0.0 rồi dùng IP máy tính.\n• Không execute malware; web chỉ lưu upload, chạy yarGen static, export rule/report.\n• Upload được file đơn hoặc .zip chứa nhiều sample.", 
                 style="Card.TLabel", justify="left").pack(anchor="w")

    def _build_log_area(self, parent, full_height=False):
        """Build log display area"""
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)
        
        # Log header with controls
        log_header = ttk.Frame(parent, style="Surface.TFrame")
        log_header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        log_header.columnconfigure(0, weight=1)
        
        ttk.Label(log_header, text="📜 Web Server Log", style="H1.TLabel").grid(row=0, column=0, sticky="w")
        
        # Log controls
        controls_frame = ttk.Frame(log_header, style="Surface.TFrame")
        controls_frame.grid(row=0, column=1, sticky="e")
        
        ttk.Button(controls_frame, text="Clear", command=self._clear_log, 
                  style="Secondary.TButton").grid(row=0, column=0, padx=(0, 4))
        ttk.Button(controls_frame, text="Save Log", command=self._save_log, 
                  style="Secondary.TButton").grid(row=0, column=1)
        
        # Log text area with scrollbar
        log_frame = ttk.Frame(parent, style="Surface.TFrame")
        log_frame.grid(row=1, column=0, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        height = 30 if full_height else self.log_height.get()
        self.log_box = tk.Text(log_frame, height=height, wrap="word", 
                              bg="#081223", fg="#DBEAFE", insertbackground="#DBEAFE", 
                              relief="flat", font=("Consolas", 9))
        
        log_scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_box.yview)
        self.log_box.configure(yscrollcommand=log_scrollbar.set)
        
        self.log_box.grid(row=0, column=0, sticky="nsew")
        log_scrollbar.grid(row=0, column=1, sticky="ns")
        
        self.log("[READY] Web mode is stopped. Click Start Web.\n")

    def _build_advanced_settings(self, parent):
        """Build advanced settings panel"""
        parent.columnconfigure(0, weight=1)
        
        ttk.Label(parent, text="⚙️ Advanced Settings", style="H1.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 8))
        
        settings_notebook = ttk.Notebook(parent)
        settings_notebook.grid(row=1, column=0, sticky="ew")
        
        # Network settings
        network_frame = ttk.Frame(settings_notebook, padding=10)
        settings_notebook.add(network_frame, text="Network")
        
        ttk.Label(network_frame, text="Timeout (seconds):", style="Card.TLabel").grid(row=0, column=0, sticky="w", pady=4)
        timeout_var = tk.IntVar(value=30)
        ttk.Spinbox(network_frame, from_=5, to=300, textvariable=timeout_var, width=10).grid(row=0, column=1, sticky="w", padx=(8, 0), pady=4)
        
        ttk.Label(network_frame, text="Max connections:", style="Card.TLabel").grid(row=1, column=0, sticky="w", pady=4)
        max_conn_var = tk.IntVar(value=10)
        ttk.Spinbox(network_frame, from_=1, to=100, textvariable=max_conn_var, width=10).grid(row=1, column=1, sticky="w", padx=(8, 0), pady=4)
        
        # Security settings
        security_frame = ttk.Frame(settings_notebook, padding=10)
        settings_notebook.add(security_frame, text="Security")
        
        ttk.Checkbutton(security_frame, text="Enable CORS").grid(row=0, column=0, sticky="w", pady=2)
        ttk.Checkbutton(security_frame, text="Log all requests").grid(row=1, column=0, sticky="w", pady=2)
        ttk.Checkbutton(security_frame, text="Restrict file types").grid(row=2, column=0, sticky="w", pady=2)

    def _on_layout_changed(self, event=None):
        """Handle layout mode change"""
        self._build_layout()

    def _clear_log(self):
        """Clear the log display"""
        self.log_box.delete(1.0, tk.END)
        self.log("[LOG CLEARED]\n")

    def _save_log(self):
        """Save log to file"""
        from tkinter import filedialog
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Web Server Log"
        )
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.log_box.get(1.0, tk.END))
                self.log(f"[SAVED] Log saved to {filename}\n")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save log: {e}")

    def log(self, text):
        self.log_box.insert("end", text)
        self.log_box.see("end")

    def _refresh_status(self):
        running = self.process is not None and self.process.poll() is None
        self.status.set("Running" if running else "Stopped")

    def _port_available(self, host, port):
        test_host = "127.0.0.1" if host == "0.0.0.0" else host
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            return s.connect_ex((test_host, port)) != 0

    def start_server(self):
        if self.process and self.process.poll() is None:
            self.open_browser()
            return
        try:
            port = int(self.port.get())
            if not (1024 <= port <= 65535):
                raise ValueError("Port must be 1024-65535")
        except Exception as exc:
            messagebox.showerror("Invalid port", str(exc))
            return
        host = self.host.get().strip() or "127.0.0.1"
        if not self._port_available(host, port):
            messagebox.showwarning("Port busy", f"Port {port} is already in use. Try another port.")
            return
        script = Path(self.app.root_dir) / "web_server.py"
        if not script.exists():
            messagebox.showerror("Missing web_server.py", str(script))
            return
        cmd = [sys.executable, str(script), "--host", host, "--port", str(port)]
        env = dict(os.environ) if "os" in globals() else None
        if env is not None:
            env.setdefault("PYTHONIOENCODING", "utf-8")
            env.setdefault("PYTHONUTF8", "1")
        try:
            self.process = subprocess.Popen(cmd, cwd=str(self.app.root_dir), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", env=env)
        except Exception as exc:
            messagebox.showerror("Failed to start web server", str(exc))
            return
        browser_host = "127.0.0.1" if host == "0.0.0.0" else host
        self.url.set(f"http://{browser_host}:{port}")
        self.status.set("Running")
        self.log(f"\n[START] {' '.join(cmd)}\n[URL] {self.url.get()}\n")
        self.reader_thread = threading.Thread(target=self._reader, daemon=True)
        self.reader_thread.start()
        self.after(900, self.open_browser)

    def _reader(self):
        if not self.process or not self.process.stdout:
            return
        for line in self.process.stdout:
            self.after(0, lambda x=line: self.log(x))
        code = self.process.wait() if self.process else None
        self.after(0, lambda: self.status.set(f"Stopped (code={code})"))

    def open_browser(self):
        webbrowser.open(self.url.get())

    def stop_server(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.log("\n[STOP] Web server terminate signal sent.\n")
            self.status.set("Stopping")
        else:
            self.status.set("Stopped")
            self.log("\n[INFO] Web server is not running.\n")
