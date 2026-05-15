#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stable standard-library Web Mode for yarGen.

Flow:
1. Browser uploads sample files or .zip by normal multipart form.
2. Server saves uploads into web_workspace/<job_id>/samples/.
3. Server runs the same simple yarGen.py command as the desktop GUI.
4. Job page polls /api/job/<job_id> and exposes rule/report/log downloads.

Uploaded samples are never executed. The only subprocess is yarGen.py.
"""
from __future__ import annotations

import argparse
import html
import json
import mimetypes
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, unquote, urlparse

try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

WEB_VERSION = "stable-simple-2026-05-15.2"
ROOT_DIR = Path(__file__).resolve().parent
WORK_ROOT = ROOT_DIR / "web_workspace"
MAX_UPLOAD_BYTES = 500 * 1024 * 1024
MAX_EXTRACTED_BYTES = 900 * 1024 * 1024
MAX_EXTRACTED_FILES = 3000
JOBS: dict[str, "Job"] = {}
JOBS_LOCK = threading.Lock()

# Keep presets simple. Preset only fills options; the user can override flags.
GUI_PRESETS = {
    "Beginner": {"y":"8", "z":"0", "x":"30", "w":"5", "s":"128", "rc":"20", "fs":"10", "fm":"3", "n":"3", "flags":["score"]},
    "Advanced": {"y":"8", "z":"0", "x":"30", "w":"5", "s":"128", "rc":"20", "fs":"10", "fm":"3", "n":"3", "flags":["score", "strings", "opcodes"]},
    "Loose Debug": {"y":"4", "z":"0", "x":"1", "w":"1", "s":"2048", "rc":"100", "fs":"100", "fm":"5", "n":"3", "flags":["score", "strings", "debug", "noscorefilter"]},
}
ALL_FLAGS = ["score", "strings", "opcodes", "oe", "excludegood", "nosuper", "nosimple", "nomagic", "nofilesize", "globalrule", "nr", "noextras", "debug", "trace", "noscorefilter"]
FLAG_ARG = {name: "--" + name for name in ALL_FLAGS}

@dataclass
class Job:
    id: str
    family: str
    preset: str
    workdir: Path
    samples_dir: Path
    rules_dir: Path
    strings_dir: Path
    reports_dir: Path
    output_rule: Path
    author: str = "yarGen GUI"
    status: str = "queued"  # queued/saving/running/done/warning/failed
    stage: str = "Queued"
    percent: int = 0
    message: str = "Queued."
    created_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    started_at: float | None = None
    finished_at: float | None = None
    uploaded_files: int = 0
    uploaded_bytes: int = 0
    extracted_files: int = 0
    extracted_bytes: int = 0
    cmd: list[str] = field(default_factory=list)
    cwd: Path | None = None
    flags: list[str] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)
    exit_code: int | None = None
    rule_count: int = 0
    simple_rules: int = 0
    super_rules: int = 0
    syntax_status: str = "not checked"
    quality_status: str = "not available"
    issues_count: int = 0
    ioc_count: int = 0
    mitre_count: int = 0
    downloads: dict[str, str] = field(default_factory=dict)
    summary_html: str = ""
    last_log_at: float = field(default_factory=time.time)
    reports_exported: bool = False

    def log(self, text: str) -> None:
        for line in str(text).replace("\r", "").split("\n"):
            if line:
                self.logs.append(line)
                self.last_log_at = time.time()
        if len(self.logs) > 6000:
            self.logs = self.logs[-6000:]

    def elapsed(self) -> int:
        if not self.started_at:
            return 0
        return int((self.finished_at or time.time()) - self.started_at)


def safe_name(value: str, fallback: str = "file") -> str:
    value = (value or "").strip().replace("\\", "/").split("/")[-1]
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return value[:140] or fallback


def read_int(fields: dict[str, str], key: str, default: str, min_v: int = -9999, max_v: int = 999999) -> str:
    try:
        v = int(str(fields.get(key, default)).strip())
    except Exception:
        v = int(default)
    return str(max(min_v, min(max_v, v)))


def count_rules(path: Path) -> int:
    if not path.exists():
        return 0
    text = path.read_text(encoding="utf-8", errors="replace")
    return len(re.findall(r"(?m)^\s*(?:private\s+|global\s+)*rule\s+[A-Za-z_][A-Za-z0-9_]*", text))


def validate_yara_syntax(rule_path: Path) -> str:
    if not rule_path.exists():
        return "missing"
    try:
        import yara  # type: ignore
        yara.compile(filepath=str(rule_path))
        return "valid"
    except ImportError:
        yarac = shutil.which("yarac")
        if not yarac:
            return "not checked"
        out = rule_path.with_suffix(rule_path.suffix + ".compiled.tmp")
        proc = subprocess.run([yarac, str(rule_path), str(out)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
        try:
            out.unlink(missing_ok=True)
        except Exception:
            pass
        return "valid" if proc.returncode == 0 else "invalid"
    except Exception:
        return "invalid"


def parse_multipart(body: bytes, content_type: str) -> tuple[dict[str, str], list[tuple[str, bytes]]]:
    match = re.search(r'boundary=(?:"([^"]+)"|([^;]+))', content_type or "")
    if not match:
        raise ValueError("Missing multipart boundary")
    boundary = (match.group(1) or match.group(2)).strip().encode("utf-8")
    marker = b"--" + boundary
    fields: dict[str, str] = {}
    files: list[tuple[str, bytes]] = []
    for part in body.split(marker):
        part = part.strip(b"\r\n")
        if not part or part == b"--" or b"\r\n\r\n" not in part:
            continue
        raw_headers, data = part.split(b"\r\n\r\n", 1)
        data = data.rstrip(b"\r\n")
        headers = raw_headers.decode("utf-8", errors="replace")
        disposition = ""
        for header in headers.split("\r\n"):
            if header.lower().startswith("content-disposition:"):
                disposition = header
                break
        name_match = re.search(r'name="([^"]+)"', disposition)
        file_match = re.search(r'filename="([^"]*)"', disposition)
        if not name_match:
            continue
        name = name_match.group(1)
        if file_match is not None and file_match.group(1):
            files.append((safe_name(file_match.group(1), "sample.bin"), data))
        elif file_match is None:
            fields[name] = data.decode("utf-8", errors="replace")
    return fields, files


def safe_extract_zip(zip_path: Path, dest: Path, job: Job) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    with zipfile.ZipFile(zip_path) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            if job.extracted_files >= MAX_EXTRACTED_FILES:
                job.log(f"[ZIP] Stop extracting: file limit {MAX_EXTRACTED_FILES} reached.")
                break
            size = int(info.file_size or 0)
            if job.extracted_bytes + size > MAX_EXTRACTED_BYTES:
                job.log(f"[ZIP] Stop extracting: byte limit {MAX_EXTRACTED_BYTES} reached.")
                break
            raw_name = info.filename.replace("\\", "/").lstrip("/")
            if ".." in Path(raw_name).parts:
                job.log(f"[ZIP] Skip unsafe member: {raw_name}")
                continue
            target = (dest / raw_name).resolve()
            if not str(target).startswith(str(root)):
                job.log(f"[ZIP] Skip unsafe member: {raw_name}")
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, target.open("wb") as out:
                shutil.copyfileobj(source, out, 1024 * 1024)
            job.extracted_files += 1
            job.extracted_bytes += size
    job.log(f"[ZIP] Extracted {job.extracted_files} files, {job.extracted_bytes} bytes.")


def save_uploads(files: list[tuple[str, bytes]], job: Job) -> None:
    if not files:
        raise ValueError("No uploaded samples.")
    for filename, data in files:
        name = safe_name(filename, "sample.bin")
        dest = job.samples_dir / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        job.uploaded_files += 1
        job.uploaded_bytes += len(data)
        job.log(f"[UPLOAD] Server saved {name} -> {dest} ({len(data)} bytes)")
        if dest.suffix.lower() == ".zip":
            safe_extract_zip(dest, job.samples_dir / (dest.stem + "_extracted"), job)
    if job.uploaded_files == 0:
        raise ValueError("No uploaded samples were saved.")


def build_command(job: Job, fields: dict[str, str]) -> tuple[list[str], Path]:
    """Build the simple real yarGen command, close to desktop GUI output."""
    yargen = ROOT_DIR / "yarGen.py"
    prefix = fields.get("prefix", "Malware family rule").strip() or "Malware family rule"
    reference = fields.get("reference", "").strip()
    license_text = fields.get("license", "").strip()
    identifier = fields.get("identifier_file", "").strip()
    flags = [name for name in ALL_FLAGS if fields.get(name) in {"1", "on", "true", name}]
    job.flags = [FLAG_ARG[name] for name in flags]
    job.author = fields.get("author", job.author).strip() or "yarGen GUI"

    cmd = [sys.executable, "-W", "ignore", str(yargen), "-m", str(job.samples_dir), "-o", str(job.output_rule)]
    if "strings" in flags:
        cmd += ["-e", str(job.strings_dir)]
    cmd += ["-a", job.author]
    if reference:
        cmd += ["-r", reference]
    if license_text:
        cmd += ["-l", license_text]
    cmd += ["-p", prefix]
    if identifier:
        cmd += ["-b", identifier]
    for key, flag, default, min_v in [
        ("y", "-y", "8", 0), ("z", "-z", "0", -9999), ("x", "-x", "30", 0), ("w", "-w", "5", 0),
        ("s", "-s", "128", 1), ("rc", "-rc", "20", 0), ("fs", "-fs", "10", 0), ("fm", "-fm", "3", 0), ("n", "-n", "3", 0),
    ]:
        cmd += [flag, read_int(fields, key, default, min_v, 999999)]
    cmd += job.flags
    return cmd, ROOT_DIR


def infer_stage(job: Job, line: str) -> None:
    lower = line.lower()
    if "goodware" in lower or ("loading" in lower and "db" in lower):
        job.stage = "Load goodware DB"; job.percent = max(job.percent, 18)
    elif "processing" in lower or "sample" in lower:
        job.stage = "Process samples"; job.percent = max(job.percent, 35)
    elif "statistical" in lower or "statistics" in lower:
        job.stage = "Generate statistics"; job.percent = max(job.percent, 52)
    elif "generating" in lower or "simple rule" in lower or "super rule" in lower:
        job.stage = "Generate rules"; job.percent = max(job.percent, 70)
    elif "filter" in lower:
        job.stage = "Filter findings"; job.percent = max(job.percent, 80)
    elif "all rules written" in lower:
        job.stage = "Post analysis"; job.percent = max(job.percent, 88)
    match = re.search(r"Generated\s+(\d+)\s+SIMPLE", line, re.I)
    if match:
        job.simple_rules = int(match.group(1))
    match = re.search(r"Generated\s+(\d+)\s+SUPER", line, re.I)
    if match:
        job.super_rules = int(match.group(1))


def export_reports(job: Job) -> None:
    if job.reports_exported:
        return
    job.stage = "Reports"; job.percent = max(job.percent, 92)
    job.reports_dir.mkdir(parents=True, exist_ok=True)
    log_path = job.reports_dir / "job_log.txt"
    log_path.write_text("\n".join(job.logs), encoding="utf-8", errors="replace")
    job.downloads["job_log.txt"] = str(log_path)
    if job.output_rule.exists():
        job.downloads[job.output_rule.name] = str(job.output_rule)
    job.syntax_status = validate_yara_syntax(job.output_rule)
    try:
        sys.path.insert(0, str(ROOT_DIR))
        from core.quality_gate import analyze_quality_gate, export_quality_gate
        from core.rule_doctor import analyze_rule_doctor, export_rule_doctor
        from core.ioc_extractor import extract_iocs, export_ioc_reports
        from core.mitre_mapper import map_mitre, export_mitre_reports
        qg = analyze_quality_gate(job.output_rule)
        job.quality_status = qg.get("status", "unknown") if isinstance(qg, dict) else "unknown"
        qmd, qcsv = export_quality_gate(qg, job.reports_dir)
        issues = analyze_rule_doctor(job.output_rule)
        job.issues_count = len(issues)
        rmd, rcsv = export_rule_doctor(issues, job.reports_dir)
        iocs = extract_iocs(job.samples_dir, include_rules=False, include_samples=True, include_logs=False)
        if job.output_rule.exists():
            iocs += extract_iocs(job.output_rule, include_rules=True, include_samples=False, include_logs=False)
        job.ioc_count = len(iocs)
        imd, icsv = export_ioc_reports(iocs, job.reports_dir)
        mitre = map_mitre(source=job.output_rule if job.output_rule.exists() else job.samples_dir, iocs=iocs)
        job.mitre_count = len(mitre)
        mmd, mcsv = export_mitre_reports(mitre, job.reports_dir)
        for path in [qmd, qcsv, rmd, rcsv, imd, icsv, mmd, mcsv]:
            job.downloads[Path(path).name] = str(path)
        job.summary_html = f"""
        <div class='metrics'>
          <div><b>Syntax</b><span>{html.escape(job.syntax_status)}</span></div>
          <div><b>Quality</b><span>{html.escape(str(job.quality_status))}</span></div>
          <div><b>Doctor issues</b><span>{job.issues_count}</span></div>
          <div><b>IOCs</b><span>{job.ioc_count}</span></div>
          <div><b>MITRE mappings</b><span>{job.mitre_count}</span></div>
        </div>"""
    except Exception as exc:
        job.log(f"[REPORT] Post-analysis failed: {exc}")
        job.summary_html = f"<p class='warn'>Post-analysis failed: {html.escape(str(exc))}</p>"
    try:
        archive = shutil.make_archive(str(job.workdir / f"{job.id}_results"), "zip", root_dir=str(job.workdir))
        job.downloads["all_results.zip"] = archive
    except Exception as exc:
        job.log(f"[ZIP] Result archive failed: {exc}")
    job.reports_exported = True


def refresh_job_from_disk(job: Job) -> None:
    """Make the UI recover if the browser is watching while the rule already exists on disk."""
    if job.output_rule.exists():
        job.rule_count = count_rules(job.output_rule)
        if job.rule_count > 0 and job.status == "running" and job.exit_code is None and job.elapsed() >= 3:
            job.log("[WEB] Output rule detected on disk. Preparing downloads while yarGen finalizes.")
            try:
                export_reports(job)
            except Exception as exc:
                job.log(f"[WEB] Disk refresh report export failed: {exc}")
            job.status = "done"
            job.stage = "Done"
            job.percent = 100
            job.finished_at = job.finished_at or time.time()
            job.message = "Rule detected and downloads are ready."
    # Keep log/download files visible even after restart-like edge cases.
    if (job.reports_dir / "job_log.txt").exists():
        job.downloads.setdefault("job_log.txt", str(job.reports_dir / "job_log.txt"))
    if job.output_rule.exists():
        job.downloads.setdefault(job.output_rule.name, str(job.output_rule))
    archives = sorted(job.workdir.glob("*_results.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
    if archives:
        job.downloads.setdefault("all_results.zip", str(archives[0]))


def run_job(job: Job, fields: dict[str, str]) -> None:
    job.status = "running"; job.stage = "Preflight"; job.percent = 5; job.started_at = time.time()
    job.message = "Building yarGen command."
    job.strings_dir.mkdir(parents=True, exist_ok=True); job.rules_dir.mkdir(parents=True, exist_ok=True)
    cmd, cwd = build_command(job, fields)
    job.cmd = cmd; job.cwd = cwd
    job.log("[WEB] Upload saved in isolated job folder. Uploaded samples are never executed.")
    job.log(f"[WEB] Samples folder passed to yarGen: {job.samples_dir}")
    job.log(f"[WEB] Output rule: {job.output_rule}")
    job.log(f"[CMD] {' '.join(('\"' + c + '\"') if ' ' in c else c for c in cmd)}")
    if "--score" in job.flags:
        job.log("[INFO] --score enabled: this can take longer because yarGen loads goodware DBs.")
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    env["PYTHONUNBUFFERED"] = "1"
    q: queue.Queue[str | None] = queue.Queue()
    def reader(pipe) -> None:
        try:
            for line in iter(pipe.readline, ""):
                q.put(line)
        finally:
            q.put(None)
    try:
        process = subprocess.Popen(cmd, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace", bufsize=1, env=env)
        assert process.stdout is not None
        threading.Thread(target=reader, args=(process.stdout,), daemon=True).start()
        last_heartbeat = time.time()
        while True:
            try:
                line = q.get(timeout=1)
                if line is None:
                    if process.poll() is not None:
                        break
                    continue
                infer_stage(job, line)
                job.log(line)
                job.message = line.strip()[:220] or job.message
            except queue.Empty:
                if process.poll() is not None:
                    break
                elapsed = job.elapsed()
                job.percent = min(86, max(job.percent, 8 + elapsed // 10))
                refresh_job_from_disk(job)
                if job.status == "done":
                    # The rule is ready for the user. Let the process finish naturally, but the UI can download now.
                    pass
                if time.time() - last_heartbeat > 15:
                    job.message = "yarGen is still running. Waiting for engine output."
                    job.log(f"[HEARTBEAT] {job.message} elapsed={elapsed}s")
                    last_heartbeat = time.time()
        job.exit_code = process.wait()
        while not q.empty():
            line = q.get_nowait()
            if line:
                infer_stage(job, line); job.log(line)
        job.rule_count = count_rules(job.output_rule)
        job.log(f"[PROCESS EXITED] code={job.exit_code}")
        job.log(f"[POST] SIMPLE={job.simple_rules} SUPER={job.super_rules} rule_count={job.rule_count}")
        export_reports(job)
        job.finished_at = time.time(); job.percent = 100
        if job.exit_code == 0 and job.rule_count > 0:
            job.status = "done"; job.stage = "Done"; job.message = "Rule generated successfully."
        elif job.exit_code == 0:
            job.status = "warning"; job.stage = "0 rules"; job.message = "yarGen ran successfully but generated 0 rules. Adjust options or use more related samples."
        else:
            job.status = "failed"; job.stage = "Failed"; job.message = f"yarGen failed with code {job.exit_code}."
    except Exception as exc:
        job.finished_at = time.time(); job.status = "failed"; job.stage = "Error"; job.percent = 100; job.message = str(exc); job.log(f"[ERROR] {exc}")
        try:
            export_reports(job)
        except Exception:
            pass


def css() -> str:
    return """
:root{--bg:#eef6fb;--surface:#fff;--line:#cfe3fb;--ink:#09213f;--muted:#5c6b82;--blue:#2563eb;--cyan:#06b6d4;--danger:#dc2626;--ok:#059669;--warn:#b7791f}*{box-sizing:border-box}body{margin:0;background:linear-gradient(135deg,#f8fbff,#eaf6ff);font-family:Segoe UI,Arial,sans-serif;color:var(--ink)}.wrap{max-width:1260px;margin:0 auto;padding:22px}h1{margin:0;font-size:30px}.sub{color:var(--muted)}.top{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:16px}.brand{display:flex;align-items:center;gap:12px}.sigil{width:52px;height:52px;border-radius:16px;background:linear-gradient(135deg,var(--blue),var(--cyan));display:grid;place-items:center;color:white;font-size:28px;box-shadow:0 12px 28px #2563eb33}.card{background:rgba(255,255,255,.96);border:1px solid var(--line);border-radius:18px;padding:18px;box-shadow:0 14px 36px #2563eb14;margin-bottom:14px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.three{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.field{margin-bottom:10px}.field label{display:block;font-weight:800;margin-bottom:5px}input,select{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:10px;background:#fbfdff}.checks{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}.check{border:1px solid var(--line);border-radius:10px;background:#f7fbff;padding:9px;font-weight:700}.drop{display:block;border:2px dashed #93c5fd;border-radius:16px;background:#f7fbff;padding:24px;text-align:center;cursor:pointer}.btn{border:0;border-radius:12px;padding:12px 16px;font-weight:900;cursor:pointer;text-decoration:none;display:inline-block}.primary{background:linear-gradient(135deg,var(--blue),var(--cyan));color:white}.secondary{background:#eaf3ff;color:#1d4ed8}.bar{height:17px;background:#dbeafe;border-radius:99px;overflow:hidden}.fill{height:100%;background:linear-gradient(90deg,#2563eb,#06b6d4);transition:.3s}.pill{display:inline-block;background:#eff6ff;border:1px solid #bfdbfe;border-radius:999px;padding:7px 11px;font-weight:800;margin:3px}.timeline{display:grid;gap:8px}.step{display:grid;grid-template-columns:160px 110px 1fr;gap:10px;padding:10px;border:1px solid var(--line);border-radius:12px;background:#fbfdff}.step.now{background:#eff6ff;border-color:#60a5fa}.log{height:390px;overflow:auto;background:#071224;color:#dbeafe;border-radius:14px;padding:13px;font:13px Consolas,monospace;white-space:pre-wrap}.downloads{display:flex;flex-wrap:wrap;gap:8px}.download{background:#eff6ff;border:1px solid #bfdbfe;border-radius:10px;padding:8px 10px;font-weight:800;text-decoration:none;color:#1d4ed8}.metrics{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}.metrics div{background:#f8fbff;border:1px solid var(--line);border-radius:12px;padding:10px}.metrics b,.metrics span{display:block}.metrics span{font-size:18px;font-weight:900}.footer{font-size:13px;color:var(--muted);margin:18px 0}.mascot{min-height:240px;background:radial-gradient(circle at 80% 20%,#dff7ff,transparent 35%),#fff}.hero{font-size:80px;text-align:center;filter:drop-shadow(0 10px 14px #2563eb33);animation:pulse 1.8s infinite}.warn{color:#b7791f;font-weight:800}@keyframes pulse{50%{transform:scale(1.06)}}@media(max-width:900px){.grid,.three,.checks,.metrics{grid-template-columns:1fr}.step{grid-template-columns:1fr}}
"""


def page(title: str, body: str) -> bytes:
    return f"<!doctype html><html lang='vi'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><meta http-equiv='Cache-Control' content='no-store'><title>{html.escape(title)}</title><style>{css()}</style></head><body><div class='wrap'>{body}<div class='footer'>Web version {WEB_VERSION} • Static analysis only • uploads saved under web_workspace/job_id/samples • only yarGen.py is executed</div></div></body></html>".encode("utf-8")


def index_page() -> bytes:
    options = "".join(f"<option>{html.escape(name)}</option>" for name in GUI_PRESETS)
    presets = json.dumps(GUI_PRESETS, ensure_ascii=False)
    flag_html = "".join(f"<label class='check'><input id='{flag}' name='{flag}' value='1' type='checkbox'> --{flag}</label>" for flag in ALL_FLAGS)
    flag_json = json.dumps(ALL_FLAGS)
    body = f"""
<div class='top'><div class='brand'><div class='sigil'>⚔</div><div><h1>Tạo YARA rule</h1><div class='sub'>Upload sample/zip → server lưu vào job folder riêng → chạy yarGen.py thật giống GUI → tải rule/report.</div></div></div><a class='btn secondary' href='/jobs'>Job history</a></div>
<form action='/start' method='post' enctype='multipart/form-data'>
<div class='card'><div class='grid'><div class='field'><label>Preset</label><select id='preset' name='preset'>{options}</select></div><div class='field'><label>Author (-a)</label><input name='author' value='yarGen GUI'></div></div><p class='sub'>Beginner mặc định tạo command đơn giản: -m, -o, -a, -p, tham số số, --score. Advanced chỉ thêm flag khi user tự chọn.</p></div>
<div class='grid'>
 <div class='card'><h2>Samples</h2><label class='drop' for='samples'><b>Drop files here or click to choose</b><br><span class='sub'>Supports multiple files and .zip archives.</span></label><input required multiple type='file' id='samples' name='samples' style='display:none'><p id='files' class='sub'>No files selected.</p><div class='field'><label>Family name</label><input name='family' value='malware_family'></div><div class='field'><label>Output YARA file</label><input name='output_name' value='malware_family.yar'></div><div class='field'><label>Reference (-r, optional)</label><input name='reference'></div></div>
 <div class='card mascot'><div class='hero'>⚔️</div><h2>YARA Web Forge</h2><p class='sub'>Server không execute malware. Server chỉ lưu sample rồi chạy yarGen.py với folder sample đó.</p><p><button class='btn primary' type='submit'>Upload & Generate</button> <button class='btn secondary' type='button' onclick='previewCmd()'>Xem command</button></p><pre id='cmdprev' class='sub'></pre></div>
</div>
<div class='card'><h2>Options giống GUI</h2><div class='three'><div class='field'><label>License (-l)</label><input name='license'></div><div class='field'><label>Prefix/description (-p)</label><input id='prefix' name='prefix' value='Malware family rule'></div><div class='field'><label>Identifier file (-b)</label><input name='identifier_file'></div><div class='field'><label>Min string length (-y)</label><input id='y' name='y' value='8'></div><div class='field'><label>Min score (-z)</label><input id='z' name='z' value='0'></div><div class='field'><label>High specific score (-x)</label><input id='x' name='x' value='30'></div><div class='field'><label>Super rule min overlap (-w)</label><input id='w' name='w' value='5'></div><div class='field'><label>Max string length (-s)</label><input id='s' name='s' value='128'></div><div class='field'><label>Max strings per rule (-rc)</label><input id='rc' name='rc' value='20'></div><div class='field'><label>Max file size MB (-fs)</label><input id='fs' name='fs' value='10'></div><div class='field'><label>Filesize multiplier (-fm)</label><input id='fm' name='fm' value='3'></div><div class='field'><label>Opcode number (-n)</label><input id='n' name='n' value='3'></div></div><h3>Advanced flags</h3><div class='checks'>{flag_html}</div></div>
</form>
<script>
const PRESETS={presets};
const FLAGS={flag_json};
function applyPreset(){{
  const p=PRESETS[document.getElementById('preset').value]; if(!p)return;
  ['y','z','x','w','s','rc','fs','fm','n'].forEach(k=>document.getElementById(k).value=p[k]||'');
  FLAGS.forEach(f=>document.getElementById(f).checked=(p.flags||[]).includes(f));
}}
document.getElementById('preset').addEventListener('change',applyPreset); applyPreset();
document.getElementById('samples').addEventListener('change',e=>{{const fs=[...e.target.files]; document.getElementById('files').textContent=fs.length?fs.map(f=>`${{f.name}} (${{Math.round(f.size/1024)}} KB)`).join(', '):'No files selected.';}});
function previewCmd(){{const flags=FLAGS.filter(f=>document.getElementById(f).checked).map(f=>'--'+f).join(' '); const e=document.getElementById('strings').checked?' -e <job>/strings_out':''; document.getElementById('cmdprev').textContent=`python -W ignore yarGen.py -m <job>/samples -o <job>/rules/malware_family.yar${{e}} -a "yarGen GUI" -p "Malware family rule" -y 8 -z 0 -x 30 -w 5 -s 128 -rc 20 -fs 10 -fm 3 -n 3 ${{flags}}`;}}
</script>"""
    return page("Tạo YARA rule", body)


def jobs_page() -> bytes:
    with JOBS_LOCK:
        jobs = list(JOBS.values())[::-1]
    rows = "".join(f"<div class='step'><b><a href='/job/{job.id}'>{job.id}</a></b><span>{job.status}</span><span>{html.escape(job.family)} • rules {job.rule_count} • {job.created_at}</span></div>" for job in jobs) or "<p class='sub'>No jobs yet.</p>"
    return page("Jobs", f"<div class='top'><h1>Job history</h1><a class='btn secondary' href='/'>New job</a></div><div class='card timeline'>{rows}</div>")


def job_page(job: Job) -> bytes:
    refresh_job_from_disk(job)
    stage_json = json.dumps(job.stage)
    status_json = json.dumps(job.status)
    
    # Read rule content for display
    rule_content = ""
    if job.output_rule.exists():
        try:
            rule_content = job.output_rule.read_text(encoding="utf-8", errors="replace")
        except Exception:
            rule_content = "Error reading rule file"
    
    return page("Generation Monitor", f"""
<div class='top'>
    <div class='brand'>
        <div class='sigil'>⚔</div>
        <div>
            <h1>Generation Monitor</h1>
            <div class='sub'>Job {job.id} • Family: {html.escape(job.family)}</div>
        </div>
    </div>
    <div class='actions'>
        <a class='btn secondary' href='/jobs'>Job History</a>
        <a class='btn secondary' href='/'>New Job</a>
    </div>
</div>

<div class='grid'>
    <div class='card main-status'>
        <div class='status-header'>
            <span class='pill stage'>Stage: <b id='stage'>{html.escape(job.stage)}</b></span>
            <span class='pill status-{job.status}'>Status: <b id='status'>{html.escape(job.status)}</b></span>
            <span class='pill rules'>Rules: <b id='rules'>{job.rule_count}</b></span>
        </div>
        <div class='progress-section'>
            <div class='bar'><div id='fill' class='fill' style='width:{job.percent}%'></div></div>
            <p class='progress-text'><b id='pct'>{job.percent}%</b> — <span id='msg'>{html.escape(job.message)}</span></p>
        </div>
        
        <div class='tabs'>
            <button class='tab-btn active' onclick='showTab("timeline")'>Timeline</button>
            <button class='tab-btn' onclick='showTab("logs")'>Logs</button>
            <button class='tab-btn' onclick='showTab("rule")' id='rule-tab' {'style="display:none"' if job.rule_count == 0 else ''}>YARA Rule</button>
            <button class='tab-btn' onclick='showTab("reports")'>Reports</button>
        </div>
        
        <div id='tab-timeline' class='tab-content active'>
            <h3>Stage Timeline</h3>
            <div id='timeline' class='timeline'></div>
        </div>
        
        <div id='tab-logs' class='tab-content'>
            <h3>yarGen Log</h3>
            <div id='log' class='log'>{html.escape(chr(10).join(job.logs[-300:]))}</div>
        </div>
        
        <div id='tab-rule' class='tab-content'>
            <div class='rule-header'>
                <h3>Generated YARA Rule</h3>
                <div class='rule-actions'>
                    <button class='btn small' onclick='copyRule()'>📋 Copy</button>
                    <button class='btn small' onclick='downloadRule()'>⬇ Download</button>
                    <button class='btn small' onclick='validateRule()'>✓ Validate</button>
                </div>
            </div>
            <div class='rule-container'>
                <pre id='rule-content' class='rule-code'>{html.escape(rule_content)}</pre>
            </div>
        </div>
        
        <div id='tab-reports' class='tab-content'>
            <h3>Analysis Reports</h3>
            <div id='summary'>{job.summary_html or '<p class="sub">Analysis reports will appear here when job completes.</p>'}</div>
            <div id='downloads' class='downloads'></div>
        </div>
    </div>
    
    <div class='card sidebar'>
        <div class='stats-card'>
            <div class='stat'>
                <div class='stat-icon'>⏱️</div>
                <div class='stat-info'>
                    <div class='stat-label'>Elapsed Time</div>
                    <div class='stat-value' id='elapsed'>{job.elapsed()}s</div>
                </div>
            </div>
            <div class='stat'>
                <div class='stat-icon'>🚩</div>
                <div class='stat-info'>
                    <div class='stat-label'>Flags Used</div>
                    <div class='stat-value' id='flags'>{html.escape(' '.join(job.flags) or 'none')}</div>
                </div>
            </div>
            <div class='stat'>
                <div class='stat-icon'>📁</div>
                <div class='stat-info'>
                    <div class='stat-label'>Samples</div>
                    <div class='stat-value'>{len(list(job.samples_dir.glob('*'))) if job.samples_dir.exists() else 0}</div>
                </div>
            </div>
        </div>
        
        <div class='quick-actions'>
            <h4>Quick Actions</h4>
            <button class='action-btn' onclick='refreshJob()'>🔄 Refresh Status</button>
            <button class='action-btn' onclick='downloadAll()'>📦 Download All</button>
            <button class='action-btn' onclick='shareJob()'>🔗 Share Job</button>
        </div>
        
        <div class='mascot-section'>
            <div class='hero'>⚔️</div>
            <div class='mascot-text'>
                <p><strong>YARA Forge</strong></p>
                <p class='sub'>Static analysis complete. Rules ready for deployment.</p>
            </div>
        </div>
    </div>
</div>

<style>
.top {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }}
.actions {{ display: flex; gap: 10px; }}
.grid {{ display: grid; grid-template-columns: 2fr 1fr; gap: 20px; }}
.main-status {{ min-height: 600px; }}
.status-header {{ display: flex; gap: 10px; margin-bottom: 15px; flex-wrap: wrap; }}
.pill.status-done {{ background: #dcfce7; color: #166534; }}
.pill.status-running {{ background: #dbeafe; color: #1d4ed8; }}
.pill.status-failed {{ background: #fecaca; color: #dc2626; }}
.pill.status-warning {{ background: #fef3c7; color: #d97706; }}
.progress-section {{ margin-bottom: 20px; }}
.progress-text {{ margin: 8px 0 0; }}

.tabs {{ display: flex; border-bottom: 2px solid #e5e7eb; margin-bottom: 20px; }}
.tab-btn {{ background: none; border: none; padding: 12px 20px; cursor: pointer; font-weight: 600; color: #6b7280; border-bottom: 2px solid transparent; }}
.tab-btn.active {{ color: #2563eb; border-bottom-color: #2563eb; }}
.tab-btn:hover {{ background: #f3f4f6; }}

.tab-content {{ display: none; }}
.tab-content.active {{ display: block; }}

.rule-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }}
.rule-actions {{ display: flex; gap: 8px; }}
.btn.small {{ padding: 6px 12px; font-size: 13px; }}
.rule-container {{ background: #1e293b; border-radius: 8px; overflow: hidden; }}
.rule-code {{ background: #1e293b; color: #e2e8f0; padding: 20px; margin: 0; font-family: 'Consolas', 'Monaco', monospace; font-size: 14px; line-height: 1.5; overflow-x: auto; }}

.sidebar {{ display: flex; flex-direction: column; gap: 20px; }}
.stats-card {{ background: #f8fafc; border-radius: 12px; padding: 16px; }}
.stat {{ display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }}
.stat:last-child {{ margin-bottom: 0; }}
.stat-icon {{ font-size: 24px; }}
.stat-info {{ flex: 1; }}
.stat-label {{ font-size: 12px; color: #64748b; text-transform: uppercase; font-weight: 600; }}
.stat-value {{ font-size: 16px; font-weight: 700; color: #1e293b; }}

.quick-actions h4 {{ margin: 0 0 12px; color: #374151; }}
.action-btn {{ width: 100%; padding: 10px; background: #f1f5f9; border: 1px solid #e2e8f0; border-radius: 8px; cursor: pointer; margin-bottom: 8px; text-align: left; font-weight: 500; }}
.action-btn:hover {{ background: #e2e8f0; }}

.mascot-section {{ text-align: center; padding: 20px; background: linear-gradient(135deg, #dbeafe, #e0f2fe); border-radius: 12px; }}
.hero {{ font-size: 48px; margin-bottom: 10px; }}
.mascot-text p {{ margin: 4px 0; }}

@media (max-width: 900px) {{
    .grid {{ grid-template-columns: 1fr; }}
    .status-header {{ flex-direction: column; align-items: stretch; }}
    .rule-header {{ flex-direction: column; align-items: stretch; gap: 10px; }}
}}
</style>

<script>
const stages=['Queued','Saving upload','Preflight','Load goodware DB','Process samples','Generate statistics','Generate rules','Filter findings','Post analysis','Reports','Done','0 rules','Failed','Error'];
function esc(s){{return String(s).replace(/[&<>"']/g,m=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[m]));}}

function showTab(tabName) {{
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    
    // Show selected tab
    document.getElementById('tab-' + tabName).classList.add('active');
    event.target.classList.add('active');
}}

function timeline(cur,status){{
    let ci=stages.indexOf(cur); if(ci<0)ci=0; 
    let h=''; 
    for(const st of stages.slice(0,10)){{
        const i=stages.indexOf(st), now=st==cur; 
        h+=`<div class='step ${{now?'now':''}}'><b>${{esc(st)}}</b><span>${{i<ci?'Done':now?status:'Waiting'}}</span><span>${{now?'Current stage':'Auto tracked from yarGen log'}}</span></div>`;
    }} 
    document.getElementById('timeline').innerHTML=h;
}}

function copyRule() {{
    const ruleContent = document.getElementById('rule-content').textContent;
    navigator.clipboard.writeText(ruleContent).then(() => {{
        alert('YARA rule copied to clipboard!');
    }});
}}

function downloadRule() {{
    window.location.href = '/download/{job.id}/malware_family.yar';
}}

function validateRule() {{
    alert('Rule validation feature coming soon!');
}}

function refreshJob() {{
    location.reload();
}}

function downloadAll() {{
    window.location.href = '/download/{job.id}/all_results.zip';
}}

function shareJob() {{
    navigator.clipboard.writeText(window.location.href).then(() => {{
        alert('Job URL copied to clipboard!');
    }});
}}

async function tick(){{
    try{{
        const r=await fetch('/api/job/{job.id}?t='+Date.now(),{{cache:'no-store'}}); 
        const j=await r.json(); 
        
        // Update status elements
        ['stage','status'].forEach(k=>document.getElementById(k).textContent=j[k]); 
        document.getElementById('rules').textContent=j.rule_count; 
        document.getElementById('fill').style.width=j.percent+'%'; 
        document.getElementById('pct').textContent=j.percent+'%'; 
        document.getElementById('msg').textContent=j.message;
        document.getElementById('elapsed').textContent=j.elapsed+'s';
        document.getElementById('flags').textContent=j.flags.join(' ')||'none';
        
        // Update log
        document.getElementById('log').textContent=j.logs.join('\\n'); 
        document.getElementById('log').scrollTop=document.getElementById('log').scrollHeight;
        
        // Update downloads
        document.getElementById('downloads').innerHTML=j.downloads_html; 
        
        // Update summary
        if(j.summary_html) document.getElementById('summary').innerHTML=j.summary_html;
        
        // Show rule tab if rules generated
        if(j.rule_count > 0) {{
            document.getElementById('rule-tab').style.display = 'block';
        }}
        
        // Update timeline
        timeline(j.stage,j.status);
        
        // Update status pill class
        const statusPill = document.querySelector('.pill.status-done, .pill.status-running, .pill.status-failed, .pill.status-warning');
        if(statusPill) {{
            statusPill.className = statusPill.className.replace(/status-\\w+/, 'status-' + j.status);
        }}
        
        // Continue polling if not finished
        if(!['done','warning','failed'].includes(j.status)) {{
            setTimeout(tick,2000);
        }}
    }} catch(e) {{
        console.error('Failed to update job status:', e);
        setTimeout(tick,5000);
    }}
}}

// Initialize
timeline({stage_json},{status_json}); 
setTimeout(tick,1000);
</script>""")


class Handler(BaseHTTPRequestHandler):
    server_version = "YarGenWebStable/4.1"

    def send_bytes(self, data: bytes, ctype: str = "text/html; charset=utf-8", status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/favicon.ico":
            return self.send_bytes(b"", "image/x-icon", 204)
        if path == "/":
            return self.send_bytes(index_page())
        if path == "/jobs":
            return self.send_bytes(jobs_page())
        if path.startswith("/job/"):
            job = JOBS.get(path.split("/", 2)[2])
            if not job:
                return self.send_bytes(page("Not found", "<div class='card'>Job not found. Use Job history for current jobs.</div>"), status=404)
            return self.send_bytes(job_page(job))
        if path.startswith("/api/job/"):
            job = JOBS.get(path.split("/", 3)[3])
            if not job:
                return self.send_bytes(b'{"error":"not found"}', "application/json", 404)
            refresh_job_from_disk(job)
            downloads_html = "".join(f"<a class='download' href='/download/{job.id}/{quote(name)}'>Download {html.escape(name)}</a>" for name in sorted(job.downloads)) or "<span class='sub'>No downloads yet.</span>"
            data = {"id": job.id, "status": job.status, "stage": job.stage, "percent": job.percent, "message": job.message, "logs": job.logs[-300:], "elapsed": job.elapsed(), "rule_count": job.rule_count, "flags": job.flags, "downloads_html": downloads_html, "summary_html": job.summary_html}
            return self.send_bytes(json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json")
        if path.startswith("/download/"):
            parts = path.split("/", 3)
            job = JOBS.get(parts[2]) if len(parts) > 3 else None
            name = unquote(parts[3]) if len(parts) > 3 else ""
            fp = Path(job.downloads.get(name, "")) if job else None
            if not fp or not fp.exists():
                return self.send_error(404)
            data = fp.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", mimetypes.guess_type(str(fp))[0] or "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{Path(name).name}"')
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
            return
        return self.send_error(404)

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/start":
            return self.send_error(404)
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0 or length > MAX_UPLOAD_BYTES:
            return self.send_bytes(page("Upload rejected", "<div class='card'>Upload too large.</div>"), status=413)
        raw = self.rfile.read(length)
        try:
            fields_in, files_in = parse_multipart(raw, self.headers.get("Content-Type", ""))
        except Exception as exc:
            return self.send_bytes(page("Upload failed", f"<div class='card'><h1>Upload failed</h1><p>{html.escape(str(exc))}</p></div>"), status=400)
        def f(name: str, default: str = "") -> str:
            return fields_in.get(name, default)
        jid = datetime.now().strftime("%Y%m%d_%H%M%S_") + uuid.uuid4().hex[:8]
        family = safe_name(f("family", "malware_family"), "malware_family")
        out_name = safe_name(f("output_name", family + ".yar"), family + ".yar")
        if not out_name.lower().endswith((".yar", ".yara")):
            out_name += ".yar"
        work = WORK_ROOT / jid
        job = Job(jid, family, f("preset", "Beginner"), work, work / "samples", work / "rules", work / "strings_out", work / "reports", work / "rules" / out_name, author=f("author", "yarGen GUI"), status="saving", stage="Saving upload", percent=2, message="Saving uploaded files to server folder.")
        for directory in [job.samples_dir, job.rules_dir, job.strings_dir, job.reports_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        try:
            save_uploads(files_in, job)
        except Exception as exc:
            return self.send_bytes(page("Upload failed", f"<div class='card'><h1>Upload failed</h1><p>{html.escape(str(exc))}</p></div>"), status=400)
        fields = {key: f(key, "") for key in ["preset", "family", "output_name", "author", "reference", "license", "prefix", "identifier_file", "y", "z", "x", "w", "s", "rc", "fs", "fm", "n"] + ALL_FLAGS}
        with JOBS_LOCK:
            JOBS[jid] = job
        threading.Thread(target=run_job, args=(job, fields), daemon=True).start()
        self.send_response(303)
        self.send_header("Location", f"/job/{jid}")
        self.end_headers()

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("[web] " + (fmt % args) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8088)
    args = parser.parse_args()
    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"YARA Web Forge {WEB_VERSION} running at http://{args.host}:{args.port}", flush=True)
    print("Upload -> isolated job folder -> simple real yarGen.py command -> rule/report downloads", flush=True)
    httpd.serve_forever()

if __name__ == "__main__":
    main()
