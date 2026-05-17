# -*- coding: utf-8 -*-
import os
import socket
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from core.scrollable_screen import ScrollableScreen

class WebModeScreen(ScrollableScreen):
    """Start/stop the friendly local web UI from the desktop app."""
    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.process = None
        self.reader_thread = None
        self.host = tk.StringVar(value="127.0.0.1")
        self.port = tk.StringVar(value="8088")
        self.url = tk.StringVar(value="http://127.0.0.1:8088")
        self.status = tk.StringVar(value="Stopped")
        self.build()

    def refresh_text(self):
        pass
    def on_mode_changed(self):
        pass
    def on_show(self):
        self._refresh_status()

    def build(self):
        content = self.create_scrollable_content("Web Mode - YARA Malware Signature")
        content.columnconfigure(0, weight=1)
        hero = ttk.Frame(content, style="Card.TFrame", padding=18)
        hero.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        hero.columnconfigure(0, weight=1)
        ttk.Label(hero, text="🌐 YARA Web Mode", style="H1.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(hero, text="Mở giao diện web dễ dùng: Analyze Sample, Family Rule, yarGen Generate Monitor và Validate/Test bằng VirusTotal/YARA CLI.", style="AppMuted.TLabel").grid(row=1, column=0, sticky="w", pady=(4, 0))

        flow = ttk.Frame(content, style="App.TFrame")
        flow.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        for i, txt in enumerate([
            "1. Analyze Sample\nUpload 1 malware, tự đánh giá",
            "2. Family Rule\nNhiều sample cùng họ, sinh rule chung",
            "3. Validate/Test\nKiểm thử rule sau khi sinh",
            "4. Download Report\nTải rule/report/zip",
        ]):
            flow.columnconfigure(i, weight=1)
            card = ttk.Frame(flow, style="Card.TFrame", padding=12)
            card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 6, 0 if i == 3 else 6))
            ttk.Label(card, text=txt, style="Card.TLabel", justify="left").pack(anchor="w")

        main = ttk.Frame(content, style="App.TFrame")
        main.grid(row=2, column=0, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=1)
        content.rowconfigure(2, weight=1)

        left = ttk.Frame(main, style="Card.TFrame", padding=16)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.columnconfigure(1, weight=1)
        ttk.Label(left, text="Server Control", style="H1.TLabel").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))
        ttk.Label(left, text="Host", style="Card.TLabel").grid(row=1, column=0, sticky="w", pady=5)
        ttk.Entry(left, textvariable=self.host).grid(row=1, column=1, sticky="ew", pady=5, padx=(8,0))
        ttk.Label(left, text="Port", style="Card.TLabel").grid(row=2, column=0, sticky="w", pady=5)
        ttk.Entry(left, textvariable=self.port).grid(row=2, column=1, sticky="ew", pady=5, padx=(8,0))
        ttk.Label(left, text="URL", style="Card.TLabel").grid(row=3, column=0, sticky="w", pady=5)
        ttk.Entry(left, textvariable=self.url).grid(row=3, column=1, sticky="ew", pady=5, padx=(8,0))
        buttons = ttk.Frame(left, style="Card.TFrame")
        buttons.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(12, 8))
        for i in range(3): buttons.columnconfigure(i, weight=1)
        ttk.Button(buttons, text="Start Web", command=self.start_server, style="Primary.TButton").grid(row=0, column=0, sticky="ew", padx=(0,4))
        ttk.Button(buttons, text="Open Browser", command=self.open_browser, style="Wuxia.TButton").grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Button(buttons, text="Stop", command=self.stop_server, style="Danger.TButton").grid(row=0, column=2, sticky="ew", padx=(4,0))
        ttk.Label(left, textvariable=self.status, style="Pill.TLabel").grid(row=5, column=0, columnspan=2, sticky="w", pady=(6, 0))
        notes = ttk.LabelFrame(left, text="Cách dùng đúng", padding=10)
        notes.grid(row=6, column=0, columnspan=2, sticky="ew", pady=(14, 0))
        ttk.Label(notes, text="• Analyze Sample: upload 1 malware để app tự đánh giá.\n• Family Rule: upload nhiều sample cùng họ để sinh rule từ đặc trưng chung.\n• Validate/Test: chỉ dùng sau khi đã có rule .yar.\n• Web chỉ phân tích tĩnh và gọi YARA scan; không execute malware.", style="Card.TLabel", justify="left").pack(anchor="w")

        right = ttk.Frame(main, style="Card.TFrame", padding=16)
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)
        header = ttk.Frame(right, style="Card.TFrame")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="Server Log", style="H1.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Button(header, text="Save Log", command=self._save_log, style="Secondary.TButton").grid(row=0, column=1, sticky="e", padx=(0, 5))
        ttk.Button(header, text="Clear", command=self._clear_log, style="Secondary.TButton").grid(row=0, column=2, sticky="e")
        self.log_box = tk.Text(right, height=22, wrap="word", bg="#071224", fg="#dbeafe", insertbackground="#dbeafe", relief="flat", font=("Consolas", 9))
        scroll = ttk.Scrollbar(right, orient="vertical", command=self.log_box.yview)
        self.log_box.configure(yscrollcommand=scroll.set)
        self.log_box.grid(row=1, column=0, sticky="nsew")
        scroll.grid(row=1, column=1, sticky="ns")
        self.log("[READY] Click Start Web. Web has realtime yarGen monitor + waiting video support.\n")

    def log(self, text):
        self.log_box.insert("end", text)
        self.log_box.see("end")

    def _clear_log(self):
        self.log_box.delete(1.0, tk.END)
        self.log("[LOG CLEARED]\n")

    def _save_log(self):
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")], title="Save Web Server Log")
        if filename:
            try:
                Path(filename).write_text(self.log_box.get(1.0, tk.END), encoding="utf-8")
                self.log(f"[SAVED] {filename}\n")
            except Exception as exc:
                messagebox.showerror("Save failed", str(exc))

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
        env = dict(os.environ)
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
        self.after(800, self.open_browser)

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
