#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Friendly local web UI for the YARA malware-signature app.

This server is intentionally static-analysis only. Uploaded samples are saved
under web_workspace/<job_id>/ and are never executed.  The official
VirusTotal/YARA CLI is used only for rule validation and rule matching when the
user provides rules or asks to validate/test a generated rule.
"""
from __future__ import annotations

import argparse
import html
import json
import mimetypes
import os
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

ROOT_DIR = Path(__file__).resolve().parent
WORK_ROOT = ROOT_DIR / "web_workspace"
WEB_VERSION = "3.6.1-realtime-monitor-video"
MAX_UPLOAD_BYTES = 700 * 1024 * 1024
MAX_EXTRACTED_BYTES = 1200 * 1024 * 1024
MAX_EXTRACTED_FILES = 5000

try:
    sys.path.insert(0, str(ROOT_DIR))
    from core.sample_analyzer import analyze_file, render_quick_rule, render_markdown_report
    from core.family_signature import build_common_profile, write_profile_reports
    from core.yara_engine import YaraEngine
except Exception as exc:  # shown on / if imports fail
    analyze_file = None  # type: ignore
    render_quick_rule = None  # type: ignore
    render_markdown_report = None  # type: ignore
    build_common_profile = None  # type: ignore
    write_profile_reports = None  # type: ignore
    YaraEngine = None  # type: ignore
    IMPORT_ERROR = exc
else:
    IMPORT_ERROR = None

JOBS: dict[str, dict] = {}


GUI_PRESETS = {
    "Beginner": {"y":"8", "z":"0", "x":"30", "w":"5", "s":"128", "rc":"20", "fs":"10", "fm":"3", "n":"3", "flags":["score"]},
    "Advanced": {"y":"8", "z":"0", "x":"30", "w":"5", "s":"128", "rc":"20", "fs":"10", "fm":"3", "n":"3", "flags":["score", "strings", "opcodes"]},
    "Loose Debug": {"y":"4", "z":"0", "x":"1", "w":"1", "s":"2048", "rc":"100", "fs":"100", "fm":"5", "n":"3", "flags":["score", "strings", "debug", "noscorefilter"]},
}
ALL_FLAGS = ["score", "strings", "opcodes", "oe", "excludegood", "nosuper", "nosimple", "nomagic", "nofilesize", "globalrule", "nr", "noextras", "debug", "trace", "noscorefilter"]
FLAG_ARG = {name: "--" + name for name in ALL_FLAGS}
JOBS_LOCK = threading.Lock()

@dataclass
class YargenJob:
    id: str
    family: str
    workdir: Path
    samples_dir: Path
    rules_dir: Path
    strings_dir: Path
    reports_dir: Path
    output_rule: Path
    author: str = "yarGen Web"
    status: str = "queued"
    stage: str = "Queued"
    percent: int = 0
    message: str = "Queued."
    created_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    started_at: float | None = None
    finished_at: float | None = None
    uploaded_files: int = 0
    uploaded_bytes: int = 0
    cmd: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)
    exit_code: int | None = None
    rule_count: int = 0
    syntax_status: str = "not checked"
    summary_html: str = ""
    downloads: dict[str, str] = field(default_factory=dict)

    def log(self, text: str) -> None:
        for line in str(text).replace("\r", "").split("\n"):
            if line:
                self.logs.append(line)
        if len(self.logs) > 5000:
            self.logs = self.logs[-5000:]

    def elapsed(self) -> int:
        if not self.started_at:
            return 0
        return int((self.finished_at or time.time()) - self.started_at)


def safe_name(value: str, fallback: str = "file") -> str:
    value = (value or "").replace("\\", "/").split("/")[-1].strip()
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return value[:150] or fallback


def job_id(prefix: str) -> str:
    return f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"


def esc(value) -> str:
    return html.escape(str(value if value is not None else ""))


def human_size(n: int) -> str:
    n = int(n or 0)
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n} B"


def parse_multipart(body: bytes, content_type: str) -> tuple[dict[str, str], dict[str, list[tuple[str, bytes]]]]:
    match = re.search(r'boundary=(?:"([^"]+)"|([^;]+))', content_type or "")
    if not match:
        raise ValueError("Missing multipart boundary")
    boundary = (match.group(1) or match.group(2)).strip().encode("utf-8")
    fields: dict[str, str] = {}
    files: dict[str, list[tuple[str, bytes]]] = {}
    for part in body.split(b"--" + boundary):
        part = part.strip(b"\r\n")
        if not part or part == b"--" or b"\r\n\r\n" not in part:
            continue
        raw_headers, data = part.split(b"\r\n\r\n", 1)
        data = data.rstrip(b"\r\n")
        headers = raw_headers.decode("utf-8", errors="replace")
        disp = ""
        for line in headers.split("\r\n"):
            if line.lower().startswith("content-disposition:"):
                disp = line
                break
        name_m = re.search(r'name="([^"]+)"', disp)
        file_m = re.search(r'filename="([^"]*)"', disp)
        if not name_m:
            continue
        name = name_m.group(1)
        if file_m is not None:
            filename = file_m.group(1)
            if filename:
                files.setdefault(name, []).append((safe_name(filename, "upload.bin"), data))
        else:
            fields[name] = data.decode("utf-8", errors="replace")
    return fields, files


def safe_extract_zip(zip_path: Path, dest: Path) -> list[Path]:
    created: list[Path] = []
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    total = 0
    count = 0
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            if count >= MAX_EXTRACTED_FILES:
                break
            size = int(info.file_size or 0)
            if total + size > MAX_EXTRACTED_BYTES:
                break
            raw = info.filename.replace("\\", "/").lstrip("/")
            if ".." in Path(raw).parts:
                continue
            target = (dest / raw).resolve()
            if not str(target).startswith(str(root)):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as out:
                shutil.copyfileobj(src, out, 1024 * 1024)
            created.append(target)
            total += size
            count += 1
    return created


def save_file_group(file_items: list[tuple[str, bytes]], dest: Path, extract_zip: bool = True) -> list[Path]:
    dest.mkdir(parents=True, exist_ok=True)
    saved: list[Path] = []
    used: set[str] = set()
    for filename, data in file_items:
        base = safe_name(filename, "upload.bin")
        name = base
        stem = Path(base).stem
        suffix = Path(base).suffix
        i = 2
        while name.lower() in used:
            name = f"{stem}_{i}{suffix}"
            i += 1
        used.add(name.lower())
        out = dest / name
        out.write_bytes(data)
        saved.append(out)
        if extract_zip and out.suffix.lower() == ".zip":
            saved.extend(safe_extract_zip(out, dest / f"{out.stem}_extracted"))
    return [p for p in saved if p.exists() and p.is_file()]


def iter_files(folder: Path) -> list[Path]:
    if not folder.exists():
        return []
    return sorted([p for p in folder.rglob("*") if p.is_file()])


def rule_files(folder: Path) -> list[Path]:
    return [p for p in iter_files(folder) if p.suffix.lower() in {".yar", ".yara"}]


def make_archive(job_dir: Path, jid: str) -> Path:
    archive = shutil.make_archive(str(job_dir / f"{jid}_results"), "zip", root_dir=str(job_dir))
    return Path(archive)


def count_rules(path: Path) -> int:
    if not path.exists():
        return 0
    text = path.read_text(encoding="utf-8", errors="replace")
    return len(re.findall(r"(?m)^\s*(?:private\s+|global\s+)*rule\s+[A-Za-z_][A-Za-z0-9_]*", text))


def read_int(fields: dict[str, str], key: str, default: str, min_v: int = 0, max_v: int = 999999) -> str:
    try:
        v = int(str(fields.get(key, default)).strip())
    except Exception:
        v = int(default)
    return str(max(min_v, min(max_v, v)))


def build_yargen_command(job: YargenJob, fields: dict[str, str]) -> tuple[list[str], Path]:
    yargen = ROOT_DIR / "yarGen.py"
    prefix = fields.get("prefix", f"{job.family} family rule").strip() or f"{job.family} family rule"
    reference = fields.get("reference", "").strip()
    license_text = fields.get("license", "").strip()
    identifier = fields.get("identifier_file", "").strip()
    flags = [name for name in ALL_FLAGS if fields.get(name) in {"1", "on", "true", name}]
    job.flags = [FLAG_ARG[name] for name in flags]
    job.author = fields.get("author", job.author).strip() or "yarGen Web"
    cmd = [sys.executable, "-W", "ignore", str(yargen), "-m", str(job.samples_dir), "-o", str(job.output_rule), "-a", job.author]
    if "strings" in flags:
        cmd += ["-e", str(job.strings_dir)]
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
        cmd += [flag, read_int(fields, key, default, min_v)]
    cmd += job.flags
    return cmd, ROOT_DIR


def infer_yargen_stage(job: YargenJob, line: str) -> None:
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


def export_yargen_reports(job: YargenJob) -> None:
    job.reports_dir.mkdir(parents=True, exist_ok=True)
    log_path = job.reports_dir / "yargen_job_log.txt"
    log_path.write_text("\n".join(job.logs), encoding="utf-8", errors="replace")
    job.downloads[log_path.name] = str(log_path)
    if job.output_rule.exists():
        job.downloads[job.output_rule.name] = str(job.output_rule)
        job.rule_count = count_rules(job.output_rule)
    engine = YaraEngine(ROOT_DIR, prefer_yara_x=False, prefer_cli=True) if YaraEngine else None
    if job.output_rule.exists() and engine and engine.available():
        try:
            engine.compile_rule(job.output_rule)
            job.syntax_status = "valid"
        except Exception as exc:
            job.syntax_status = f"invalid: {exc}"
    else:
        job.syntax_status = "not checked"
    summary = {
        "job_id": job.id,
        "family": job.family,
        "status": job.status,
        "rule_count": job.rule_count,
        "syntax_status": job.syntax_status,
        "command": job.cmd,
        "elapsed_seconds": job.elapsed(),
    }
    json_path = job.reports_dir / "yargen_summary.json"
    md_path = job.reports_dir / "yargen_summary.md"
    json_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text("# yarGen Generation Summary\n\n" + "\n".join(f"- {k}: {v}" for k, v in summary.items()), encoding="utf-8")
    job.downloads[json_path.name] = str(json_path)
    job.downloads[md_path.name] = str(md_path)
    try:
        zip_path = make_archive(job.workdir, job.id)
        job.downloads["all_results.zip"] = str(zip_path)
    except Exception as exc:
        job.log(f"[ZIP] Could not create archive: {exc}")
    job.summary_html = f"<div class='tri'><div class='metric'><span>Rule count</span><b>{job.rule_count}</b></div><div class='metric'><span>Syntax</span><b>{esc(job.syntax_status)}</b></div><div class='metric'><span>Exit code</span><b>{esc(job.exit_code)}</b></div></div>"


def run_yargen_job(job: YargenJob, fields: dict[str, str]) -> None:
    job.status = "running"; job.stage = "Preflight"; job.percent = 5; job.started_at = time.time()
    for d in [job.samples_dir, job.rules_dir, job.strings_dir, job.reports_dir]:
        d.mkdir(parents=True, exist_ok=True)
    try:
        cmd, cwd = build_yargen_command(job, fields)
        job.cmd = cmd
        job.log("[WEB] Running original yarGen.py in an isolated job folder.")
        job.log(f"[WEB] Samples folder: {job.samples_dir}")
        job.log(f"[WEB] Output rule: {job.output_rule}")
        job.log("[CMD] " + " ".join(('\"' + c + '\"') if ' ' in c else c for c in cmd))
        env = os.environ.copy(); env["PYTHONIOENCODING"] = "utf-8"; env["PYTHONUTF8"] = "1"; env["PYTHONUNBUFFERED"] = "1"
        proc = subprocess.Popen(cmd, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace", bufsize=1, env=env)
        assert proc.stdout is not None
        last_heartbeat = time.time()
        for line in iter(proc.stdout.readline, ""):
            infer_yargen_stage(job, line)
            job.log(line)
            job.message = line.strip()[:220] or job.message
            if time.time() - last_heartbeat > 10:
                job.percent = min(86, max(job.percent, 8 + job.elapsed() // 8))
                last_heartbeat = time.time()
        job.exit_code = proc.wait()
        job.rule_count = count_rules(job.output_rule)
        job.log(f"[PROCESS EXITED] code={job.exit_code}")
        job.log(f"[POST] rule_count={job.rule_count}")
        export_yargen_reports(job)
        job.finished_at = time.time(); job.percent = 100
        if job.exit_code == 0 and job.rule_count > 0:
            job.status = "done"; job.stage = "Done"; job.message = "yarGen generated rule successfully."
        elif job.exit_code == 0:
            job.status = "warning"; job.stage = "0 rules"; job.message = "yarGen finished but generated 0 rules. Try more related samples or lower thresholds."
        else:
            job.status = "failed"; job.stage = "Failed"; job.message = f"yarGen failed with code {job.exit_code}."
        export_yargen_reports(job)
    except Exception as exc:
        job.finished_at = time.time(); job.status = "failed"; job.stage = "Error"; job.percent = 100; job.message = str(exc); job.log(f"[ERROR] {exc}")
        try:
            export_yargen_reports(job)
        except Exception:
            pass


def engine_info() -> tuple[str, str, bool]:
    if YaraEngine is None:
        return "missing", f"Cannot import YaraEngine: {IMPORT_ERROR}", False
    engine = YaraEngine(ROOT_DIR, prefer_yara_x=False, prefer_cli=True)
    return engine.backend, engine.detail, bool(engine.available())


MEDIA_VIDEO_EXTENSIONS = {".mp4", ".webm", ".m4v", ".mov", ".avi", ".mkv"}
MEDIA_AUDIO_EXTENSIONS = {".mp3", ".wav", ".m4a", ".ogg"}


def first_media_file(folder_name: str, extensions: set[str], preferred_name: str | None = None) -> Path | None:
    folder = ROOT_DIR / folder_name
    if not folder.exists():
        return None
    if preferred_name:
        preferred = folder / preferred_name
        if preferred.exists() and preferred.is_file() and preferred.suffix.lower() in extensions:
            return preferred
    try:
        files = sorted([p for p in folder.iterdir() if p.is_file() and p.suffix.lower() in extensions], key=lambda p: p.name.lower())
        return files[0] if files else None
    except Exception:
        return None


def waiting_media_html() -> str:
    video = first_media_file("video", MEDIA_VIDEO_EXTENSIONS, "video.mp4")
    audio = first_media_file("music", MEDIA_AUDIO_EXTENSIONS, "report.mp3")
    if video:
        video_tag = """<video id='waitingVideo' class='waiting-video' loop muted playsinline controls preload='metadata'>
  <source src='/media/video' type='video/mp4'>
  Trinh duyet khong ho tro video.
</video>"""
    else:
        video_tag = """<div class='video-placeholder'>Chua co video cho.<br>Dat file vao <b>video/video.mp4</b> trong thu muc app.</div>"""
    audio_tag = ""
    music_button = ""
    if audio:
        audio_tag = "<audio id='reportMusic' src='/media/report.mp3' loop preload='auto'></audio>"
        music_button = "<button class='btn secondary small' type='button' onclick='toggleMusic()'>🔊 Bat/Tat nhac</button>"
    return f"""
<div class='media-card'>
  <h2>🎬 Video chờ khi yarGen chạy</h2>
  <p class='sub'>Bấm Play để xem video trong lúc chờ. Trình duyệt thường chặn autoplay có âm thanh, nên video mặc định mute.</p>
  {video_tag}
  {audio_tag}
  <div class='media-actions'>
    <button class='btn primary small' type='button' onclick='playWaitingVideo()'>▶ Play video</button>
    <button class='btn secondary small' type='button' onclick='toggleVideoMute()'>🎚 Bat/Tat tieng video</button>
    {music_button}
  </div>
</div>"""


def media_script() -> str:
    return """
function playWaitingVideo(){
  const v=document.getElementById('waitingVideo');
  if(!v){alert('Chua co video/video.mp4');return;}
  v.play().catch(()=>alert('Trinh duyet chan autoplay. Hay bam Play tren video.'));
}
function toggleVideoMute(){
  const v=document.getElementById('waitingVideo');
  if(!v)return;
  v.muted=!v.muted;
  v.play().catch(()=>{});
}
function toggleMusic(){
  const a=document.getElementById('reportMusic');
  if(!a){alert('Chua co music/report.mp3');return;}
  if(a.paused){a.play().catch(()=>alert('Trinh duyet chan autoplay am thanh. Hay bam lai.'));}
  else{a.pause();}
}
"""


def css() -> str:
    return r"""
:root{--bg:#f4f8ff;--surface:#ffffff;--ink:#102033;--muted:#64748b;--line:#d7e3f4;--blue:#2563eb;--cyan:#06b6d4;--green:#059669;--red:#dc2626;--yellow:#ca8a04;--dark:#0f172a}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 20% 0,#dff4ff 0,transparent 28%),linear-gradient(135deg,#f8fbff,#eef6ff);font-family:Segoe UI,Arial,sans-serif;color:var(--ink)}.wrap{max-width:1220px;margin:0 auto;padding:26px}.hero{display:flex;justify-content:space-between;gap:18px;align-items:center;margin-bottom:18px}.brand{display:flex;gap:14px;align-items:center}.logo{width:62px;height:62px;border-radius:22px;display:grid;place-items:center;background:linear-gradient(135deg,var(--blue),var(--cyan));color:#fff;font-size:32px;box-shadow:0 16px 36px #2563eb35}h1{margin:0;font-size:34px}h2{margin:0 0 10px;font-size:22px}h3{margin:12px 0 8px}.sub{color:var(--muted);line-height:1.55}.card{background:rgba(255,255,255,.96);border:1px solid var(--line);border-radius:22px;padding:20px;box-shadow:0 16px 44px #2563eb14;margin-bottom:16px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.tri{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.tabs{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}.tab{border:1px solid var(--line);background:#fff;border-radius:999px;padding:11px 16px;font-weight:800;cursor:pointer}.tab.active{background:linear-gradient(135deg,var(--blue),var(--cyan));color:white;border-color:transparent}.panel{display:none}.panel.active{display:block}.flow{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.step{border:1px solid var(--line);border-radius:16px;padding:12px;background:#f8fbff}.step b{display:block}.drop{display:block;border:2px dashed #93c5fd;background:#f8fbff;border-radius:18px;padding:22px;text-align:center;cursor:pointer;transition:.15s}.drop:hover{background:#eef7ff;border-color:var(--blue)}input,select{width:100%;padding:12px;border:1px solid var(--line);border-radius:12px;background:#fbfdff}.field{margin-bottom:12px}.field label{display:block;font-weight:800;margin-bottom:6px}.btn{border:0;border-radius:14px;padding:12px 17px;font-weight:900;text-decoration:none;cursor:pointer;display:inline-block}.primary{background:linear-gradient(135deg,var(--blue),var(--cyan));color:white}.secondary{background:#eaf3ff;color:#1d4ed8}.danger{background:#fee2e2;color:#991b1b}.ok{background:#dcfce7;color:#166534}.pill{display:inline-block;border-radius:999px;padding:7px 11px;font-weight:800;background:#eff6ff;border:1px solid #bfdbfe;margin:3px}.pill.ok{background:#dcfce7;border-color:#86efac;color:#166534}.pill.warn{background:#fef3c7;border-color:#fde68a;color:#92400e}.pill.bad{background:#fee2e2;border-color:#fecaca;color:#991b1b}.metric{background:#f8fbff;border:1px solid var(--line);border-radius:16px;padding:14px}.metric span{display:block;color:var(--muted);font-size:13px}.metric b{font-size:22px}.code{background:#071224;color:#dbeafe;border-radius:16px;padding:16px;overflow:auto;white-space:pre-wrap;font:13px Consolas,monospace;max-height:520px}.table{width:100%;border-collapse:collapse;background:#fff;border-radius:14px;overflow:hidden}.table th,.table td{border-bottom:1px solid var(--line);padding:10px;text-align:left;vertical-align:top}.table th{background:#f1f6ff}.downloads{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}.small{font-size:13px}.footer{color:var(--muted);font-size:13px;margin-top:18px}.notice{border-left:5px solid var(--blue);padding:12px 14px;background:#eff6ff;border-radius:12px}.warnbox{border-left:5px solid var(--yellow);padding:12px 14px;background:#fffbeb;border-radius:12px}.badbox{border-left:5px solid var(--red);padding:12px 14px;background:#fff1f2;border-radius:12px}.live-dot{display:inline-block;width:10px;height:10px;background:#22c55e;border-radius:50%;box-shadow:0 0 0 0 #22c55e99;animation:livepulse 1.4s infinite;margin-right:6px}.media-card{background:#f8fbff;border:1px solid var(--line);border-radius:18px;padding:16px}.waiting-video{width:100%;max-height:330px;object-fit:contain;background:#020617;border-radius:14px;border:1px solid #0f172a}.video-placeholder{min-height:220px;display:grid;place-items:center;text-align:center;background:#0f172a;color:#e5e7eb;border-radius:14px;padding:18px}.media-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}.statusbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.monitor-grid{display:grid;grid-template-columns:1.35fr .95fr;gap:16px}.sticky-side{position:sticky;top:12px}@keyframes livepulse{70%{box-shadow:0 0 0 10px #22c55e00}}@media(max-width:920px){.grid,.tri,.flow{grid-template-columns:1fr}.hero{display:block}.wrap{padding:16px}}
"""


def page(title: str, body: str) -> bytes:
    return f"""<!doctype html><html lang='vi'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{esc(title)}</title><style>{css()}</style></head><body><div class='wrap'>{body}<div class='footer'>YARA Malware Signature Web • version {WEB_VERSION} • Static analysis only • samples are saved under web_workspace and never executed</div></div></body></html>""".encode("utf-8")


def index_page() -> bytes:
    backend, detail, ok = engine_info()
    engine_class = "ok" if ok and backend == "yara-cli" else ("warn" if ok else "bad")
    import_warning = "" if IMPORT_ERROR is None else f"<div class='badbox'><b>Import error:</b> {esc(IMPORT_ERROR)}</div>"
    body = f"""
<div class='hero'>
  <div class='brand'><div class='logo'>🛡️</div><div><h1>YARA Malware Signature Web</h1><div class='sub'>Giao diện web dễ dùng: upload malware → tự đánh giá → sinh rule → kiểm thử bằng VirusTotal/YARA CLI.</div></div></div>
  <div><span class='pill {engine_class}'>Engine: {esc(backend)}</span></div>
</div>
{import_warning}
<div class='card notice'><b>Logic đúng của app:</b> Analyze Sample dùng cho <b>1 file malware</b>; Family Rule dùng cho <b>nhiều mẫu cùng họ</b>; Validate/Test chỉ dùng <b>sau khi có rule .yar</b>.</div>
<div class='card'><div class='flow'>
  <div class='step'><b>1. Analyze Sample</b><span class='sub'>Upload 1 file, app tự đánh giá static + gợi ý rule.</span></div>
  <div class='step'><b>2. Family Rule</b><span class='sub'>Upload nhiều mẫu cùng họ, tìm đặc trưng chung.</span></div>
  <div class='step'><b>3. Validate/Test</b><span class='sub'>Dùng yara64.exe/yarac64.exe kiểm thử rule.</span></div>
  <div class='step'><b>4. Download report</b><span class='sub'>Tải .yar, .md, .json, .zip.</span></div>
</div></div>
<div class='tabs'>
  <button class='tab active' onclick='openTab("sample")'>🔍 Analyze Sample</button>
  <button class='tab' onclick='openTab("family")'>🧬 Family Rule</button>
  <button class='tab' onclick='openTab("generate")'>⚙️ yarGen Monitor</button>
  <button class='tab' onclick='openTab("validate")'>✅ Validate/Test Rule</button>
  <button class='tab' onclick='openTab("about")'>ℹ️ Giải thích</button>
</div>
<div id='sample' class='panel active card'>
  <h2>🔍 Upload 1 malware để app tự đánh giá</h2>
  <p class='sub'>Màn này là chức năng bạn cần: chọn 1 file malware, app tính hash/entropy/string/PE info, scan với rule nếu bạn upload rule, sinh quick YARA rule và report.</p>
  <form action='/analyze' method='post' enctype='multipart/form-data'>
    <div class='grid'><div><label class='drop' for='sample_file'><b>Chọn 1 file malware</b><br><span class='sub'>.exe, .dll, .bin, .dat...</span></label><input id='sample_file' name='sample' type='file' required style='display:none'></div>
    <div><label class='drop' for='rules_for_sample'><b>Rule có sẵn để match thêm</b><br><span class='sub'>Tùy chọn: upload .yar/.yara</span></label><input id='rules_for_sample' name='rules' type='file' multiple style='display:none'></div></div>
    <div class='field'><label>Tên ca phân tích / family nghi ngờ</label><input name='case_name' value='malware_sample'></div>
    <button class='btn primary' type='submit'>Analyze uploaded malware</button>
  </form>
</div>
<div id='family' class='panel card'>
  <h2>🧬 Sinh rule từ đặc trưng chung của một họ malware</h2>
  <p class='sub'>Dùng khi bạn có nhiều sample cùng họ LockBit/Lumma/RedLine... Đây là phần sát đề tài nhất.</p>
  <form action='/family' method='post' enctype='multipart/form-data'>
    <div class='grid'><div><label class='drop' for='family_samples'><b>Upload nhiều sample hoặc .zip</b><br><span class='sub'>Các file phải cùng một họ malware</span></label><input id='family_samples' name='samples' type='file' required multiple style='display:none'></div>
    <div><label class='drop' for='family_goodware'><b>Goodware sạch để lọc bớt chuỗi chung</b><br><span class='sub'>Tùy chọn, không dùng folder chứa malware</span></label><input id='family_goodware' name='goodware' type='file' multiple style='display:none'></div></div>
    <div class='grid'><div class='field'><label>Family name</label><input name='family' value='LockBit'></div><div class='field'><label>Output rule name</label><input name='output' value='family_common_rule.yar'></div></div>
    <div class='grid'><div class='field'><label>Minimum coverage ratio</label><input name='coverage' value='0.60'></div><div class='field'><label>Max features</label><input name='max_features' value='40'></div></div>
    <button class='btn primary' type='submit'>Generate common family rule</button>
  </form>
</div>
<div id='generate' class='panel card'>
  <h2>⚙️ Generate Monitor bằng yarGen gốc</h2>
  <p class='sub'>Đây là phần giám sát quá trình generate monitor cũ: upload sample/zip → server chạy <b>yarGen.py</b> thật → xem progress/log theo thời gian thực → tải rule/report. Tab này dành cho bạn muốn dùng công cụ yarGen bình thường.</p>
  <form action='/generate' method='post' enctype='multipart/form-data'>
    <div class='grid'><div><label class='drop' for='gen_samples'><b>Upload sample hoặc .zip</b><br><span class='sub'>Có thể nhiều file; server chỉ lưu và phân tích tĩnh, không execute malware.</span></label><input id='gen_samples' name='samples' type='file' required multiple style='display:none'></div>
    <div><div class='field'><label>Preset</label><select name='preset'><option>Beginner</option><option>Advanced</option><option>Loose Debug</option></select></div><div class='field'><label>Family name</label><input name='family' value='malware_family'></div><div class='field'><label>Output YARA file</label><input name='output_name' value='malware_family.yar'></div></div></div>
    <div class='grid'><div class='field'><label>Author (-a)</label><input name='author' value='yarGen Web'></div><div class='field'><label>Prefix/description (-p)</label><input name='prefix' value='Malware family rule'></div></div>
    <div class='grid'><div class='field'><label>Reference (-r, optional)</label><input name='reference'></div><div class='field'><label>License (-l, optional)</label><input name='license'></div></div>
    <details class='card'><summary><b>Advanced yarGen options</b></summary>
      <div class='tri'><div class='field'><label>Min string length (-y)</label><input name='y' value='8'></div><div class='field'><label>Min score (-z)</label><input name='z' value='0'></div><div class='field'><label>High specific score (-x)</label><input name='x' value='30'></div><div class='field'><label>Super rule min overlap (-w)</label><input name='w' value='5'></div><div class='field'><label>Max string length (-s)</label><input name='s' value='128'></div><div class='field'><label>Max strings per rule (-rc)</label><input name='rc' value='20'></div><div class='field'><label>Max file size MB (-fs)</label><input name='fs' value='10'></div><div class='field'><label>Filesize multiplier (-fm)</label><input name='fm' value='3'></div><div class='field'><label>Opcode number (-n)</label><input name='n' value='3'></div></div>
      <div class='grid'><label><input type='checkbox' name='score' value='1' checked> --score</label><label><input type='checkbox' name='strings' value='1'> --strings</label><label><input type='checkbox' name='opcodes' value='1'> --opcodes</label><label><input type='checkbox' name='debug' value='1'> --debug</label><label><input type='checkbox' name='noscorefilter' value='1'> --noscorefilter</label><label><input type='checkbox' name='excludegood' value='1'> --excludegood</label></div>
    </details>
    <button class='btn primary' type='submit'>Run yarGen with live monitor</button>
  </form>
</div>
<div id='validate' class='panel card'>
  <h2>✅ Validate/Test rule sau khi sinh</h2>
  <p class='sub'>Màn này không phải để upload malware tự đánh giá. Nó chỉ kiểm thử rule .yar: cú pháp OK không, match malware bao nhiêu, false positive trên goodware bao nhiêu.</p>
  <form action='/validate' method='post' enctype='multipart/form-data'>
    <div class='grid'><div><label class='drop' for='val_rule'><b>Upload rule .yar/.yara</b></label><input id='val_rule' name='rule' type='file' required style='display:none'></div>
    <div><label class='drop' for='val_malware'><b>Upload malware test set</b><br><span class='sub'>Nhiều file hoặc .zip</span></label><input id='val_malware' name='malware' type='file' required multiple style='display:none'></div></div>
    <label class='drop' for='val_goodware'><b>Upload goodware sạch để test false positive</b><br><span class='sub'>Tùy chọn, nên là file sạch riêng</span></label><input id='val_goodware' name='goodware' type='file' multiple style='display:none'>
    <button class='btn primary' type='submit'>Validate syntax + scan test set</button>
  </form>
</div>
<div id='about' class='panel card'>
  <h2>ℹ️ Các tab dùng để làm gì?</h2>
  <table class='table'><tr><th>Tab</th><th>Dùng khi nào?</th><th>Kết quả</th></tr>
  <tr><td><b>Analyze Sample</b></td><td>Bạn chỉ có 1 malware file và muốn app tự đánh giá.</td><td>Risk score, IOC, YARA matches nếu có rule, quick rule, report.</td></tr>
  <tr><td><b>Family Rule</b></td><td>Bạn có nhiều malware cùng họ và cần chữ ký từ đặc trưng chung.</td><td>Common features CSV/MD và rule family .yar.</td></tr>
  <tr><td><b>yarGen Monitor</b></td><td>Bạn muốn chạy yarGen.py gốc như bản web cũ và xem progress/log.</td><td>Job monitor, log realtime, generated .yar và reports.</td></tr>
  <tr><td><b>Validate/Test</b></td><td>Bạn đã có rule và muốn kiểm thử bằng VirusTotal/YARA CLI.</td><td>Syntax OK/Fail, malware detection, goodware false positive.</td></tr></table>
  <h3>YARA engine</h3><p class='sub'>{esc(detail)}</p>
</div>
<script>
function openTab(id){{document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));document.getElementById(id).classList.add('active');event.target.classList.add('active')}}
for(const inp of document.querySelectorAll('input[type=file]')){{inp.addEventListener('change',()=>{{const label=document.querySelector('label[for="'+inp.id+'"]');if(label){{label.querySelector('b').textContent = inp.files.length + ' file selected';}}}})}}
</script>
"""
    return page("YARA Malware Signature Web", body)


def downloads_html(jid: str, downloads: dict[str, str]) -> str:
    if not downloads:
        return ""
    return "<div class='downloads'>" + "".join(
        f"<a class='btn secondary' href='/download/{jid}/{quote(name)}'>⬇ {esc(name)}</a>" for name in sorted(downloads)
    ) + "</div>"


def result_page(title: str, content: str, jid: str | None = None, downloads: dict[str, str] | None = None) -> bytes:
    dl = downloads_html(jid, downloads or {}) if jid else ""
    body = f"""
<div class='hero'><div class='brand'><div class='logo'>🛡️</div><div><h1>{esc(title)}</h1><div class='sub'>Kết quả được lưu trong web_workspace. Malware không bị execute.</div></div></div><a class='btn secondary' href='/'>← Back to Web Home</a></div>
{content}
{dl}
"""
    return page(title, body)




def handle_generate(fields: dict[str, str], files: dict[str, list[tuple[str, bytes]]]) -> tuple[bytes, int]:
    if not files.get("samples"):
        return result_page("yarGen failed", "<div class='badbox'>No samples uploaded for yarGen.</div>"), 400
    jid = job_id("yargen")
    family = safe_name(fields.get("family", "malware_family"), "malware_family")
    out_name = safe_name(fields.get("output_name", family + ".yar"), family + ".yar")
    if not out_name.lower().endswith((".yar", ".yara")):
        out_name += ".yar"
    work = WORK_ROOT / jid
    job = YargenJob(jid, family, work, work / "samples", work / "rules", work / "strings_out", work / "reports", work / "rules" / out_name, author=fields.get("author", "yarGen Web"), status="saving", stage="Saving upload", percent=2, message="Saving uploaded samples.")
    for d in [job.samples_dir, job.rules_dir, job.strings_dir, job.reports_dir]:
        d.mkdir(parents=True, exist_ok=True)
    sample_paths = save_file_group(files.get("samples", []), job.samples_dir, extract_zip=True)
    job.uploaded_files = len(sample_paths)
    job.uploaded_bytes = sum(p.stat().st_size for p in sample_paths if p.exists())
    job.log(f"[UPLOAD] Saved/extracted {job.uploaded_files} files ({job.uploaded_bytes} bytes).")
    yargen_fields = {key: fields.get(key, "") for key in ["preset", "family", "output_name", "author", "reference", "license", "prefix", "identifier_file", "y", "z", "x", "w", "s", "rc", "fs", "fm", "n"] + ALL_FLAGS}
    preset = GUI_PRESETS.get(fields.get("preset", "Beginner"), GUI_PRESETS["Beginner"])
    for k, v in preset.items():
        if k == "flags":
            for flag in v:
                yargen_fields.setdefault(flag, "1")
        else:
            if not yargen_fields.get(k):
                yargen_fields[k] = v
    with JOBS_LOCK:
        JOBS[jid] = job
    threading.Thread(target=run_yargen_job, args=(job, yargen_fields), daemon=True).start()
    # Open monitor immediately after upload is saved. The monitor itself streams realtime job events.
    return page("Starting yarGen", f"<script>window.location.replace('/job/{jid}');</script><div class='card'><h1>Starting yarGen...</h1><p>Opening realtime generate monitor...</p><p><a href='/job/{jid}'>Open generate monitor</a></p></div>"), 200
def handle_analyze(fields: dict[str, str], files: dict[str, list[tuple[str, bytes]]]) -> tuple[bytes, int]:
    if IMPORT_ERROR:
        return result_page("Import error", f"<div class='badbox'>{esc(IMPORT_ERROR)}</div>"), 500
    sample_items = files.get("sample", [])
    if not sample_items:
        return result_page("Analyze failed", "<div class='badbox'>No malware sample uploaded.</div>"), 400
    jid = job_id("sample")
    work = WORK_ROOT / jid
    sample_dir, rules_dir, report_dir = work / "sample", work / "rules", work / "reports"
    sample_paths = save_file_group(sample_items[:1], sample_dir, extract_zip=False)
    rule_paths = save_file_group(files.get("rules", []), rules_dir, extract_zip=False)
    rule_paths = [p for p in rule_paths if p.suffix.lower() in {".yar", ".yara"}]
    sample = sample_paths[0]
    engine = YaraEngine(ROOT_DIR, prefer_yara_x=False, prefer_cli=True) if YaraEngine else None
    profile = analyze_file(sample, rule_paths, engine=engine)
    report_dir.mkdir(parents=True, exist_ok=True)
    quick_rule = render_quick_rule(profile)
    rule_path = report_dir / f"{Path(sample.name).stem}_quick_triage.yar"
    md_path = report_dir / f"{Path(sample.name).stem}_analysis_report.md"
    json_path = report_dir / f"{Path(sample.name).stem}_profile.json"
    rule_path.write_text(quick_rule, encoding="utf-8")
    md_path.write_text(render_markdown_report(profile), encoding="utf-8")
    json_path.write_text(json.dumps(profile, ensure_ascii=False, indent=2), encoding="utf-8")
    zip_path = make_archive(work, jid)
    downloads = {rule_path.name: str(rule_path), md_path.name: str(md_path), json_path.name: str(json_path), "all_results.zip": str(zip_path)}
    JOBS[jid] = {"type": "sample", "downloads": downloads, "work": str(work)}
    a = profile.get("assessment", {})
    hashes = profile.get("hashes", {})
    matches = profile.get("yara_matches", []) or []
    susp = profile.get("suspicious_strings", []) or []
    imports = profile.get("suspicious_imports", []) or []
    pe_sections = profile.get("pe", {}).get("sections", []) or []
    match_rows = "".join(f"<tr><td>{esc(m.get('rule'))}</td><td>{esc(Path(m.get('rule_file','')).name)}</td></tr>" for m in matches) or "<tr><td colspan='2'>No uploaded YARA rule matched.</td></tr>"
    strings_rows = "".join(f"<tr><td>{esc(r.get('score'))}</td><td>{esc(r.get('reason'))}</td><td><code>{esc(r.get('value'))}</code></td></tr>" for r in susp[:18]) or "<tr><td colspan='3'>No strong suspicious strings found.</td></tr>"
    content = f"""
<div class='tri'><div class='metric'><span>Risk score</span><b>{esc(a.get('score',0))}/100</b></div><div class='metric'><span>YARA matches</span><b>{len(matches)}</b></div><div class='metric'><span>Entropy</span><b>{esc(profile.get('entropy'))}</b></div></div>
<div class='card'><h2>Assessment</h2><span class='pill {'bad' if a.get('score',0)>=75 else 'warn' if a.get('score',0)>=45 else 'ok'}'>{esc(a.get('label'))}</span><p class='sub'>{'<br>'.join(esc(x) for x in a.get('reasons',[])) or 'No strong reason generated.'}</p></div>
<div class='grid'><div class='card'><h2>File identity</h2><table class='table'><tr><th>Name</th><td>{esc(profile.get('name'))}</td></tr><tr><th>Size</th><td>{human_size(profile.get('size',0))}</td></tr><tr><th>Type</th><td>{esc(profile.get('file_type'))}</td></tr><tr><th>MD5</th><td><code>{esc(hashes.get('md5'))}</code></td></tr><tr><th>SHA1</th><td><code>{esc(hashes.get('sha1'))}</code></td></tr><tr><th>SHA256</th><td><code>{esc(hashes.get('sha256'))}</code></td></tr></table></div>
<div class='card'><h2>YARA scan</h2><p class='sub'>{esc(engine.detail if engine else 'No engine')}</p><table class='table'><tr><th>Matched rule</th><th>Rule file</th></tr>{match_rows}</table></div></div>
<div class='card'><h2>Suspicious strings</h2><table class='table'><tr><th>Score</th><th>Reason</th><th>String</th></tr>{strings_rows}</table></div>
<div class='grid'><div class='card'><h2>Suspicious imports</h2><p class='sub'>{', '.join(esc(x) for x in imports[:35]) or 'No suspicious PE imports found.'}</p></div><div class='card'><h2>PE sections</h2><p class='sub'>{', '.join(esc(s.get('name')) + ' entropy=' + esc(s.get('entropy')) for s in pe_sections[:20]) or 'No PE section info.'}</p></div></div>
<div class='card'><h2>Suggested quick rule</h2><pre class='code'>{esc(quick_rule)}</pre></div>
"""
    return result_page("Analyze Sample Result", content, jid, downloads), 200


def handle_family(fields: dict[str, str], files: dict[str, list[tuple[str, bytes]]]) -> tuple[bytes, int]:
    if IMPORT_ERROR:
        return result_page("Import error", f"<div class='badbox'>{esc(IMPORT_ERROR)}</div>"), 500
    if not files.get("samples"):
        return result_page("Family failed", "<div class='badbox'>No family samples uploaded.</div>"), 400
    jid = job_id("family")
    work = WORK_ROOT / jid
    sample_dir, good_dir, report_dir, rule_dir = work / "samples", work / "goodware", work / "reports", work / "rules"
    sample_paths = save_file_group(files.get("samples", []), sample_dir, extract_zip=True)
    save_file_group(files.get("goodware", []), good_dir, extract_zip=True)
    family = fields.get("family", "malware_family").strip() or "malware_family"
    out_name = safe_name(fields.get("output", "family_common_rule.yar"), "family_common_rule.yar")
    if not out_name.lower().endswith((".yar", ".yara")):
        out_name += ".yar"
    try:
        coverage = max(0.1, min(1.0, float(fields.get("coverage", "0.60"))))
    except Exception:
        coverage = 0.60
    try:
        max_features = max(5, min(100, int(fields.get("max_features", "40"))))
    except Exception:
        max_features = 40
    profile = build_common_profile(sample_dir, family, good_dir if iter_files(good_dir) else None, min_coverage_ratio=coverage, max_features=max_features)
    rule_path, csv_path, md_path = write_profile_reports(profile, rule_dir / out_name, report_dir)
    engine = YaraEngine(ROOT_DIR, prefer_yara_x=False, prefer_cli=True) if YaraEngine else None
    syntax = "not checked"
    syntax_detail = "No YARA engine"
    if engine and engine.available():
        try:
            engine.compile_rule(rule_path)
            syntax = "valid"
            syntax_detail = engine.detail
        except Exception as exc:
            syntax = "invalid"
            syntax_detail = str(exc)
    zip_path = make_archive(work, jid)
    downloads = {rule_path.name: str(rule_path), csv_path.name: str(csv_path), md_path.name: str(md_path), "all_results.zip": str(zip_path)}
    JOBS[jid] = {"type": "family", "downloads": downloads, "work": str(work)}
    features = profile.get("features", []) or []
    rows = "".join(f"<tr><td>{i}</td><td>{feat.get('coverage',0):.2f}</td><td>{esc(feat.get('count'))}</td><td>{esc(feat.get('score'))}</td><td><code>{esc(feat.get('value'))}</code></td><td>{esc(feat.get('examples'))}</td></tr>" for i, feat in enumerate(features[:30], 1)) or "<tr><td colspan='6'>No common feature found. Try lower coverage or more related samples.</td></tr>"
    rule_text = rule_path.read_text(encoding="utf-8", errors="replace")
    content = f"""
<div class='tri'><div class='metric'><span>Files uploaded/found</span><b>{len(sample_paths)}</b></div><div class='metric'><span>Files analyzed</span><b>{esc(profile.get('analyzed_count'))}</b></div><div class='metric'><span>Common features</span><b>{len(features)}</b></div></div>
<div class='card'><h2>Rule status</h2><span class='pill {'ok' if syntax=='valid' else 'bad' if syntax=='invalid' else 'warn'}'>Syntax: {esc(syntax)}</span><p class='sub'>{esc(syntax_detail)}</p></div>
<div class='card'><h2>Common family features</h2><table class='table'><tr><th>#</th><th>Coverage</th><th>Count</th><th>Score</th><th>Feature</th><th>Example files</th></tr>{rows}</table></div>
<div class='card'><h2>Generated family rule</h2><pre class='code'>{esc(rule_text)}</pre></div>
"""
    return result_page("Family Rule Result", content, jid, downloads), 200


def handle_validate(fields: dict[str, str], files: dict[str, list[tuple[str, bytes]]]) -> tuple[bytes, int]:
    if IMPORT_ERROR:
        return result_page("Import error", f"<div class='badbox'>{esc(IMPORT_ERROR)}</div>"), 500
    if not files.get("rule") or not files.get("malware"):
        return result_page("Validate failed", "<div class='badbox'>Rule and malware test set are required.</div>"), 400
    jid = job_id("validate")
    work = WORK_ROOT / jid
    rule_dir, malware_dir, goodware_dir, report_dir = work / "rules", work / "malware", work / "goodware", work / "reports"
    rule_path = save_file_group(files.get("rule", [])[:1], rule_dir, extract_zip=False)[0]
    malware_files = [p for p in save_file_group(files.get("malware", []), malware_dir, extract_zip=True) if p.name != rule_path.name]
    goodware_files = save_file_group(files.get("goodware", []), goodware_dir, extract_zip=True)
    engine = YaraEngine(ROOT_DIR, prefer_yara_x=False, prefer_cli=True) if YaraEngine else None
    syntax = "missing engine"
    syntax_error = ""
    malware_results: list[tuple[Path, list[str], str]] = []
    good_results: list[tuple[Path, list[str], str]] = []
    if engine and engine.available():
        try:
            engine.compile_rule(rule_path)
            syntax = "valid"
        except Exception as exc:
            syntax = "invalid"
            syntax_error = str(exc)
        if syntax == "valid":
            for p in malware_files:
                try:
                    malware_results.append((p, engine.scan_file(rule_path, p), ""))
                except Exception as exc:
                    malware_results.append((p, [], str(exc)))
            for p in goodware_files:
                try:
                    good_results.append((p, engine.scan_file(rule_path, p), ""))
                except Exception as exc:
                    good_results.append((p, [], str(exc)))
    else:
        syntax_error = engine.detail if engine else "No engine"
    malware_matched_files = sum(1 for _, m, _ in malware_results if m)
    malware_rule_matches = sum(len(m) for _, m, _ in malware_results)
    good_matched_files = sum(1 for _, m, _ in good_results if m)
    good_rule_matches = sum(len(m) for _, m, _ in good_results)
    scan_errors = sum(1 for _, _, e in malware_results + good_results if e)
    report_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "engine": engine.detail if engine else "missing",
        "syntax": syntax,
        "syntax_error": syntax_error,
        "malware_files": len(malware_results),
        "malware_matched_files": malware_matched_files,
        "malware_rule_matches": malware_rule_matches,
        "goodware_files": len(good_results),
        "goodware_false_positive_files": good_matched_files,
        "goodware_false_positive_rule_matches": good_rule_matches,
        "scan_errors": scan_errors,
    }
    json_path = report_dir / "validate_summary.json"
    md_path = report_dir / "validate_summary.md"
    json_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text("# Validate/Test Summary\n\n" + "\n".join(f"- {k}: {v}" for k, v in summary.items()), encoding="utf-8")
    zip_path = make_archive(work, jid)
    downloads = {json_path.name: str(json_path), md_path.name: str(md_path), "all_results.zip": str(zip_path)}
    JOBS[jid] = {"type": "validate", "downloads": downloads, "work": str(work)}
    def rows(results):
        return "".join(f"<tr><td>{esc(p.name)}</td><td>{esc(', '.join(m) if m else 'NO MATCH')}</td><td>{esc(e)}</td></tr>" for p, m, e in results) or "<tr><td colspan='3'>No files scanned.</td></tr>"
    fp_rate = (good_matched_files / len(good_results) * 100) if good_results else 0
    det_rate = (malware_matched_files / len(malware_results) * 100) if malware_results else 0
    verdict = "Rule OK for this test set" if syntax == "valid" and malware_matched_files and good_matched_files == 0 else "Need review"
    box = "notice" if verdict.startswith("Rule OK") else "warnbox"
    content = f"""
<div class='{box}'><b>Interpretation:</b> {esc(verdict)}. Malware detection {det_rate:.1f}%, false-positive rate {fp_rate:.1f}%.</div>
<div class='tri'><div class='metric'><span>Syntax</span><b>{esc(syntax)}</b></div><div class='metric'><span>Malware matched files</span><b>{malware_matched_files}/{len(malware_results)}</b></div><div class='metric'><span>Goodware FP files</span><b>{good_matched_files}/{len(good_results)}</b></div></div>
<div class='card'><h2>YARA engine</h2><p class='sub'>{esc(engine.detail if engine else 'missing')}</p><p class='sub'>{esc(syntax_error)}</p></div>
<div class='card'><h2>Malware scan result</h2><table class='table'><tr><th>File</th><th>Matched rules</th><th>Error</th></tr>{rows(malware_results)}</table></div>
<div class='card'><h2>Goodware false-positive result</h2><table class='table'><tr><th>File</th><th>Matched rules</th><th>Error</th></tr>{rows(good_results)}</table></div>
"""
    return result_page("Validate/Test Result", content, jid, downloads), 200




def jobs_page() -> bytes:
    rows = []
    with JOBS_LOCK:
        for jid, obj in sorted(JOBS.items(), reverse=True):
            if isinstance(obj, YargenJob):
                rows.append(f"<tr><td><a href='/job/{jid}'>{esc(jid)}</a></td><td>{esc(obj.family)}</td><td>{esc(obj.status)}</td><td>{esc(obj.rule_count)}</td><td>{esc(obj.created_at)}</td></tr>")
            elif isinstance(obj, dict):
                rows.append(f"<tr><td>{esc(jid)}</td><td>{esc(obj.get('type'))}</td><td>done</td><td>-</td><td>-</td></tr>")
    table = "".join(rows) or "<tr><td colspan='5'>No jobs yet.</td></tr>"
    return page("Job History", f"<div class='hero'><div class='brand'><div class='logo'>⚙️</div><div><h1>Job History</h1><div class='sub'>Danh sách job web hiện tại.</div></div></div><a class='btn secondary' href='/'>← Home</a></div><div class='card'><table class='table'><tr><th>Job</th><th>Type/Family</th><th>Status</th><th>Rules</th><th>Created</th></tr>{table}</table></div>")


def yargen_job_page(job: YargenJob) -> bytes:
    rule_text = ""
    if job.output_rule.exists():
        try:
            rule_text = job.output_rule.read_text(encoding="utf-8", errors="replace")
        except Exception:
            rule_text = "Could not read rule file."
    body = f"""
<div class='hero'>
  <div class='brand'><div class='logo'>⚙️</div><div><h1>yarGen Generate Monitor</h1><div class='sub'>Job {esc(job.id)} • Family {esc(job.family)} • chạy yarGen.py gốc, cập nhật realtime không cần refresh.</div></div></div>
  <div><a class='btn secondary' href='/'>← Home</a> <a class='btn secondary' href='/jobs'>Job history</a></div>
</div>
<div class='card notice'><b><span class='live-dot'></span>Realtime monitor:</b> trang này tự nhận log/progress từ server. Nếu EventSource bị trình duyệt chặn, trang sẽ tự fallback sang polling mỗi 1 giây.</div>
<div class='monitor-grid'>
  <div>
    <div class='card'>
      <div class='statusbar'>
        <span class='pill'><b>Status:</b> <span id='status'>{esc(job.status)}</span></span>
        <span class='pill'><b>Stage:</b> <span id='stage'>{esc(job.stage)}</span></span>
        <span class='pill'><b>Rules:</b> <span id='rules'>{job.rule_count}</span></span>
        <span class='pill'><b>Elapsed:</b> <span id='elapsed'>{job.elapsed()}s</span></span>
      </div>
      <div class='bar' style='margin-top:14px'><div id='fill' style='height:100%;background:linear-gradient(90deg,#2563eb,#06b6d4);width:{job.percent}%;transition:.3s'></div></div>
      <p class='sub'><b id='pct'>{job.percent}%</b> — <span id='msg'>{esc(job.message)}</span></p>
      <h3>Live yarGen log</h3>
      <pre id='log' class='code'>{esc(chr(10).join(job.logs[-300:]))}</pre>
    </div>
    <div class='card'><h2>Generated YARA rule</h2><pre id='ruletext' class='code'>{esc(rule_text or 'Rule will appear here as soon as yarGen writes the output file.')}</pre></div>
  </div>
  <div>
    <div class='sticky-side'>
      {waiting_media_html()}
      <div class='card'>
        <h2>Command</h2><pre class='code' id='cmd'>{esc(' '.join(job.cmd))}</pre>
        <h2>Downloads</h2><div id='downloads'>{downloads_html(job.id, job.downloads) or '<p class="sub">Downloads appear when ready.</p>'}</div>
        <h2>Post-check</h2><div id='summary'>{job.summary_html or '<p class="sub">Waiting for rule generation.</p>'}</div>
      </div>
    </div>
  </div>
</div>
<script>
let finished=false;
function applyJob(j){{
  if(j.error){{return;}}
  document.getElementById('status').textContent=j.status;
  document.getElementById('stage').textContent=j.stage;
  document.getElementById('rules').textContent=j.rule_count;
  document.getElementById('elapsed').textContent=j.elapsed+'s';
  document.getElementById('fill').style.width=j.percent+'%';
  document.getElementById('pct').textContent=j.percent+'%';
  document.getElementById('msg').textContent=j.message;
  const log=document.getElementById('log');
  const text=(j.logs||[]).join('\n');
  if(log.textContent!==text){{log.textContent=text; log.scrollTop=log.scrollHeight;}}
  document.getElementById('downloads').innerHTML=j.downloads_html || '<p class="sub">Downloads appear when ready.</p>';
  document.getElementById('summary').innerHTML=j.summary_html || '<p class="sub">Waiting for rule generation.</p>';
  if(j.rule_text){{document.getElementById('ruletext').textContent=j.rule_text;}}
  finished=['done','warning','failed'].includes(j.status);
}}
async function pollTick(){{
  if(finished)return;
  try{{
    const r=await fetch('/api/job/{job.id}?t='+Date.now(),{{cache:'no-store'}});
    applyJob(await r.json());
  }}catch(e){{}}
  if(!finished)setTimeout(pollTick,1000);
}}
function startRealtime(){{
  if(window.EventSource){{
    const es=new EventSource('/events/job/{job.id}');
    es.onmessage=(ev)=>{{try{{applyJob(JSON.parse(ev.data)); if(finished)es.close();}}catch(e){{}}}};
    es.onerror=()=>{{es.close(); setTimeout(pollTick,500);}};
  }}else{{
    pollTick();
  }}
}}
{media_script()}
startRealtime();
setTimeout(()=>{{playWaitingVideo();}},600);
</script>
"""
    return page("yarGen Generate Monitor", body)

class Handler(BaseHTTPRequestHandler):
    server_version = "YaraFriendlyWeb/3.5"

    def send_bytes(self, data: bytes, ctype: str = "text/html; charset=utf-8", status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def send_media_file(self, fp: Path) -> None:
        try:
            size = fp.stat().st_size
            ctype = mimetypes.guess_type(str(fp))[0] or "application/octet-stream"
            range_header = self.headers.get("Range", "")
            start, end = 0, size - 1
            status = 200
            if range_header.startswith("bytes="):
                status = 206
                spec = range_header.split("=", 1)[1].split(",", 1)[0].strip()
                if "-" in spec:
                    a, b = spec.split("-", 1)
                    if a:
                        start = max(0, int(a))
                    if b:
                        end = min(size - 1, int(b))
                if start > end:
                    self.send_error(416)
                    return
            length = end - start + 1
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Content-Length", str(length))
            if status == 206:
                self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            with fp.open("rb") as fh:
                fh.seek(start)
                remaining = length
                while remaining > 0:
                    chunk = fh.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
        except Exception:
            self.send_error(500)

    def job_payload(self, obj: YargenJob) -> dict:
        rule_text = ""
        if obj.output_rule.exists():
            try:
                rule_text = obj.output_rule.read_text(encoding="utf-8", errors="replace")[:200000]
            except Exception:
                rule_text = ""
        return {"id": obj.id, "status": obj.status, "stage": obj.stage, "percent": obj.percent, "message": obj.message, "logs": obj.logs[-300:], "elapsed": obj.elapsed(), "rule_count": obj.rule_count, "downloads_html": downloads_html(obj.id, obj.downloads), "summary_html": obj.summary_html, "rule_text": rule_text}

    def stream_job_events(self, obj: YargenJob) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        last_payload = None
        while True:
            payload = json.dumps(self.job_payload(obj), ensure_ascii=False)
            if payload != last_payload:
                try:
                    self.wfile.write(("data: " + payload + "\n\n").encode("utf-8"))
                    self.wfile.flush()
                except Exception:
                    break
                last_payload = payload
            if obj.status in {"done", "warning", "failed"}:
                break
            time.sleep(0.8)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/media/video":
            video = first_media_file("video", MEDIA_VIDEO_EXTENSIONS, "video.mp4")
            if not video:
                return self.send_error(404)
            return self.send_media_file(video)
        if path == "/media/report.mp3":
            audio = first_media_file("music", MEDIA_AUDIO_EXTENSIONS, "report.mp3")
            if not audio:
                return self.send_error(404)
            return self.send_media_file(audio)
        if path.startswith("/events/job/"):
            jid = path.split("/", 3)[3]
            obj = JOBS.get(jid)
            if not isinstance(obj, YargenJob):
                return self.send_bytes(b'{"error":"not found"}', "application/json", 404)
            return self.stream_job_events(obj)
        if path == "/" or path == "/index.html":
            return self.send_bytes(index_page())
        if path == "/jobs":
            return self.send_bytes(jobs_page())
        if path.startswith("/job/"):
            jid = path.split("/", 2)[2]
            obj = JOBS.get(jid)
            if not isinstance(obj, YargenJob):
                return self.send_error(404)
            return self.send_bytes(yargen_job_page(obj))
        if path.startswith("/api/job/"):
            jid = path.split("/", 3)[3]
            obj = JOBS.get(jid)
            if not isinstance(obj, YargenJob):
                return self.send_bytes(b'{"error":"not found"}', "application/json", 404)
            data = self.job_payload(obj)
            return self.send_bytes(json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json")
        if path.startswith("/download/"):
            parts = path.split("/", 3)
            jid = parts[2] if len(parts) > 2 else ""
            name = unquote(parts[3]) if len(parts) > 3 else ""
            job = JOBS.get(jid)
            if isinstance(job, YargenJob):
                path_value = job.downloads.get(name, "")
            elif isinstance(job, dict):
                path_value = job.get("downloads", {}).get(name, "")
            else:
                path_value = ""
            fp = Path(path_value) if path_value else None
            if not fp or not fp.exists():
                return self.send_error(404)
            data = fp.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", mimetypes.guess_type(str(fp))[0] or "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{fp.name}"')
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
            return
        return self.send_error(404)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0 or length > MAX_UPLOAD_BYTES:
            return self.send_bytes(result_page("Upload rejected", "<div class='badbox'>Upload too large.</div>"), status=413)
        try:
            fields, files = parse_multipart(self.rfile.read(length), self.headers.get("Content-Type", ""))
            if path == "/generate":
                data, status = handle_generate(fields, files)
            elif path == "/analyze":
                data, status = handle_analyze(fields, files)
            elif path == "/family":
                data, status = handle_family(fields, files)
            elif path == "/validate":
                data, status = handle_validate(fields, files)
            else:
                return self.send_error(404)
            return self.send_bytes(data, status=status)
        except Exception as exc:
            return self.send_bytes(result_page("Error", f"<div class='badbox'><b>Error:</b> {esc(exc)}</div>"), status=500)

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("[web] " + (fmt % args) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8088)
    args = parser.parse_args()
    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    backend, detail, ok = engine_info()
    print(f"YARA Malware Signature Web {WEB_VERSION} running at http://{args.host}:{args.port}", flush=True)
    print(f"YARA engine: {backend} - {detail}", flush=True)
    print("Flow: Analyze Sample | Family Rule | yarGen Monitor | Validate/Test. Static analysis only; samples are never executed.", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
