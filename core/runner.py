# -*- coding: utf-8 -*-
import os, queue, subprocess, threading
from pathlib import Path
from tkinter import messagebox
from core.utils import quoted_command

class ProcessRunner:
    def __init__(self, app):
        self.app = app
        self.process = None
        self.thread = None
        self.output_queue = queue.Queue()

    def run_command(self, cmd, title, cwd: Path | None = None, task: str = ""):
        s = self.app.state
        if self.process and self.process.poll() is None:
            messagebox.showwarning("Process running", "Another process is already running.")
            return
        cwd = cwd or Path(s.var_workdir.get())
        s.current_task = task
        s.last_exit_code = None
        s.var_run_status.set("Running")
        self.app.refresh_status()
        if task == "generate":
            self.app.screens["monitor"].reset_progress()
            self.app.screens["monitor"].set_stage("1", "Running", "Starting subprocess")
            s.progress_stage.set("Preflight")
            s.progress_percent.set(2)
            s.progress_detail.set("Command prepared. Waiting for yarGen output...")
        self.app.show_screen("monitor")
        mon = self.app.screens["monitor"]
        mon.log("\n" + "=" * 90 + "\n")
        mon.log(f"{title}\nCWD: {cwd}\nCMD: {quoted_command(cmd)}\n")
        mon.log("=" * 90 + "\n")
        try:
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            self.process = subprocess.Popen(cmd, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True, bufsize=1, encoding="utf-8", errors="replace", env=env)
        except Exception as e:
            messagebox.showerror("Failed to start", str(e))
            mon.log(f"[ERROR] Failed to start: {e}\n")
            s.var_run_status.set("Error")
            self.app.refresh_status()
            return
        self.thread = threading.Thread(target=self._reader_loop, daemon=True)
        self.thread.start()

    def _reader_loop(self):
        if not self.process or not self.process.stdout:
            return
        for line in self.process.stdout:
            self.output_queue.put(line)
        code = self.process.wait()
        self.app.state.last_exit_code = code
        self.output_queue.put(f"\n[PROCESS EXITED] code={code}\n")
        self.output_queue.put("__PROCESS_DONE__")

    def drain_output_queue(self):
        try:
            pending = []
            while True:
                line = self.output_queue.get_nowait()
                if line == "__PROCESS_DONE__":
                    if pending:
                        self.app.screens["monitor"].log("".join(pending)); pending.clear()
                    finished = self.app.state.current_task
                    self.app.state.current_task = ""
                    self.app.state.var_run_status.set("Idle")
                    self.app.refresh_status()
                    self.app.screens["monitor"].preview_output_rule(silent=True)
                    self.app.screens["monitor"].refresh_yara_summary()
                    if finished == "generate" and self.app.state.last_exit_code == 0:
                        self.app.after(100, self.app.screens["generate"].after_generate_success)
                    continue
                self.app.screens["monitor"].update_progress_from_log_line(line)
                pending.append(line)
        except queue.Empty:
            if "pending" in locals() and pending:
                self.app.screens["monitor"].log("".join(pending))
        self.app.after(100, self.drain_output_queue)

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.app.screens["monitor"].log("\n[STOP] Terminate signal sent.\n")
            self.app.state.var_run_status.set("Stopping")
            self.app.refresh_status()
