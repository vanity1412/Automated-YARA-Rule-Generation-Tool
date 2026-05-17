# -*- coding: utf-8 -*-
"""YARA / YARA-X engine integration layer.

This module intentionally prefers the *official classic YARA CLI* when a local
``yara.exe`` / ``yara64.exe`` is bundled with the app.  That is the direct
command-line tool built from VirusTotal/yara.  Python bindings remain as a
fallback so the app still works on machines without the CLI binary.

Detection order by default:
1) local classic YARA CLI: yara64.exe, yara.exe, yara, plus yarac64.exe/yarac.exe
2) YARA CLI on PATH
3) yara-python
4) yara-x Python module or yr CLI
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterable


class YaraEngine:
    def __init__(
        self,
        root_dir: str | Path | None = None,
        prefer_yara_x: bool = False,
        prefer_cli: bool = True,
    ):
        self.root_dir = Path(root_dir) if root_dir else Path.cwd()
        self.prefer_yara_x = prefer_yara_x
        self.prefer_cli = prefer_cli
        self._yara_mod = None
        self._yara_x_mod = None
        self.cli: Path | None = None
        self.compiler_cli: Path | None = None
        self.backend = "missing"
        self.detail = "No usable YARA backend found. Put yara64.exe/yara.exe in the app folder, add YARA to PATH, or install yara-python."
        self.last_command: list[str] = []
        self.version_output = ""

        if prefer_cli and not prefer_yara_x and self._try_yara_cli(local_only=True):
            return
        if prefer_cli and not prefer_yara_x and self._try_yara_cli(local_only=False):
            return
        if prefer_yara_x and self._try_yara_x_python():
            return
        if prefer_yara_x and self._try_yara_x_cli():
            return
        if self._try_yara_python():
            return
        if not prefer_cli and self._try_yara_cli(local_only=False):
            return
        if not prefer_yara_x and self._try_yara_x_python():
            return
        if not prefer_yara_x and self._try_yara_x_cli():
            return

    # ------------------------------------------------------------------
    # Backend detection
    # ------------------------------------------------------------------
    def _try_yara_cli(self, local_only: bool = False) -> bool:
        cli = self.find_yara_cli(local_only=local_only)
        if not cli:
            return False
        ok, version = self._probe_cli(cli, ["--version"])
        if not ok:
            self.detail = f"Found YARA CLI but cannot run it: {cli}\n{version}"
            return False
        self.cli = cli
        self.compiler_cli = self.find_yarac_cli(local_only=False)
        self.backend = "yara-cli"
        self.version_output = version.strip()
        compiler = f"; compiler: {self.compiler_cli}" if self.compiler_cli else "; compiler: not found, syntax check uses yara scan fallback"
        self.detail = f"VirusTotal/YARA CLI: {cli} ({self.version_output or 'version unknown'}){compiler}"
        return True

    def _try_yara_python(self) -> bool:
        try:
            import yara  # type: ignore
            self._yara_mod = yara
            version = getattr(yara, "__version__", "unknown")
            self.backend = "yara-python"
            self.detail = f"yara-python {version} (Python binding for classic YARA engine)"
            self.version_output = str(version)
            return True
        except Exception as exc:
            self.detail = f"yara-python unavailable: {exc}"
            return False

    def _try_yara_x_python(self) -> bool:
        try:
            import yara_x  # type: ignore
            self._yara_x_mod = yara_x
            version = getattr(yara_x, "__version__", "installed")
            self.backend = "yara-x-python"
            self.detail = f"yara-x Python module {version}"
            self.version_output = str(version)
            return True
        except Exception as exc:
            self.detail = f"yara-x Python unavailable: {exc}"
            return False

    def _try_yara_x_cli(self) -> bool:
        cli = self.find_cli("yr", local_only=False)
        if not cli:
            return False
        ok, version = self._probe_cli(cli, ["--version"])
        if not ok:
            self.detail = f"Found yr CLI but cannot run it: {cli}\n{version}"
            return False
        self.backend = "yara-x-cli"
        self.detail = f"YARA-X yr CLI: {cli} ({version.strip() or 'version unknown'})"
        self.version_output = version.strip()
        self.cli = cli
        return True

    def _probe_cli(self, cli: Path, args: list[str]) -> tuple[bool, str]:
        try:
            proc = subprocess.run(
                [str(cli), *args],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=10,
                cwd=str(self.root_dir),
            )
            return proc.returncode == 0, proc.stdout.strip()
        except Exception as exc:
            return False, str(exc)

    def _candidate_paths(self, names: Iterable[str], local_only: bool = False) -> list[Path]:
        bases = [
            self.root_dir,
            self.root_dir / "bin",
            self.root_dir / "tools",
            self.root_dir / "tools" / "yara",
            self.root_dir / "yara",
            self.root_dir / "yara-master",
            self.root_dir / "yara-master" / "cli",
            self.root_dir / "yara-master" / "build" / "bin",
        ]
        candidates: list[Path] = []
        for base in bases:
            for name in names:
                candidates.append(base / name)
        if not local_only:
            for name in names:
                found = shutil.which(name)
                if found:
                    candidates.append(Path(found))
        # Preserve order but remove duplicates.
        seen: set[str] = set()
        unique: list[Path] = []
        for p in candidates:
            key = str(p).lower() if os.name == "nt" else str(p)
            if key not in seen:
                seen.add(key)
                unique.append(p)
        return unique

    def find_yara_cli(self, local_only: bool = False) -> Path | None:
        # The user's bundled files are commonly named yara64.exe and yarac64.exe.
        return self._first_existing(self._candidate_paths(["yara64.exe", "yara.exe", "yara"], local_only=local_only))

    def find_yarac_cli(self, local_only: bool = False) -> Path | None:
        return self._first_existing(self._candidate_paths(["yarac64.exe", "yarac.exe", "yarac"], local_only=local_only))

    def find_cli(self, name: str, local_only: bool = False) -> Path | None:
        if name == "yara":
            return self.find_yara_cli(local_only=local_only)
        if name == "yarac":
            return self.find_yarac_cli(local_only=local_only)
        names = [name]
        if not name.endswith(".exe"):
            names.append(f"{name}.exe")
        return self._first_existing(self._candidate_paths(names, local_only=local_only))

    def _first_existing(self, paths: Iterable[Path]) -> Path | None:
        for p in paths:
            try:
                if p.exists() and p.is_file():
                    return p
            except OSError:
                continue
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def available(self) -> bool:
        return self.backend in {"yara-cli", "yara-python", "yara-x-python", "yara-x-cli"}

    @property
    def is_yara_x(self) -> bool:
        return self.backend.startswith("yara-x")

    @property
    def is_official_yara_cli(self) -> bool:
        return self.backend == "yara-cli"

    def compile_rule(self, rule_path: str | Path):
        """Compile or syntax-check a rule file. Raises on invalid syntax."""
        rule_path = Path(rule_path)
        if self.backend == "yara-cli":
            # Prefer yarac when bundled; this is the proper classic YARA compiler.
            if self.compiler_cli:
                with tempfile.TemporaryDirectory() as td:
                    out = Path(td) / "rules.compiled"
                    cmd = [str(self.compiler_cli), str(rule_path), str(out)]
                    self.last_command = cmd
                    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
                    if proc.returncode == 0:
                        return True
                    raise RuntimeError(proc.stdout.strip() or "yarac failed to compile the rule")
            # Fallback: yara exits 0 when matched and 1 when no match; both mean syntax OK.
            cmd = [str(self.cli), str(rule_path), str(rule_path)]
            self.last_command = cmd
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
            if proc.returncode in (0, 1):
                return True
            raise RuntimeError(proc.stdout.strip() or "YARA CLI syntax check failed")

        if self.backend == "yara-python":
            return self._yara_mod.compile(filepath=str(rule_path))

        if self.backend == "yara-x-python":
            source = rule_path.read_text(encoding="utf-8", errors="replace")
            return self._yara_x_mod.compile(source)

        if self.backend == "yara-x-cli":
            with tempfile.TemporaryDirectory() as td:
                out = Path(td) / "rules.yarc"
                cmd = [str(self.cli), "compile", "--output", str(out), str(rule_path)]
                self.last_command = cmd
                proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
                if proc.returncode == 0:
                    return True
                raise RuntimeError(proc.stdout.strip() or "YARA-X compile failed")

        raise RuntimeError(self.detail)

    def scan_file(self, rule_path: str | Path, target: str | Path, timeout: int = 60) -> list[str]:
        """Scan one file and return matched rule identifiers."""
        rule_path = Path(rule_path)
        target = Path(target)
        if self.backend == "yara-cli":
            # Official classic CLI usage: yara[64].exe RULE_FILE TARGET_FILE
            cmd = [str(self.cli), str(rule_path), str(target)]
            self.last_command = cmd
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout + 5,
            )
            if proc.returncode not in (0, 1):
                raise RuntimeError(proc.stdout.strip() or "YARA CLI scan failed")
            return self._parse_text_rule_names(proc.stdout)

        if self.backend == "yara-python":
            rules = self._yara_mod.compile(filepath=str(rule_path))
            matches = rules.match(str(target), timeout=timeout)
            return [getattr(m, "rule", str(m)) for m in matches]

        if self.backend == "yara-x-python":
            source = rule_path.read_text(encoding="utf-8", errors="replace")
            rules = self._yara_x_mod.compile(source)
            data = target.read_bytes()
            try:
                scanner = self._yara_x_mod.Scanner(rules)
                if hasattr(scanner, "set_timeout"):
                    scanner.set_timeout(timeout)
                results = scanner.scan(data)
            except Exception:
                results = rules.scan(data)
            return self._extract_yara_x_rule_names(results)

        if self.backend == "yara-x-cli":
            cmd = [str(self.cli), "scan", "--output-format", "json", str(rule_path), str(target)]
            self.last_command = cmd
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout + 5,
            )
            if proc.returncode not in (0, 1):
                raise RuntimeError(proc.stdout.strip() or "YARA-X scan failed")
            return self._parse_yara_x_cli_output(proc.stdout)

        raise RuntimeError(self.detail)

    # ------------------------------------------------------------------
    # Output parsers
    # ------------------------------------------------------------------
    def _extract_yara_x_rule_names(self, results: Any) -> list[str]:
        names: list[str] = []
        matching_rules = getattr(results, "matching_rules", None)
        if matching_rules is None and isinstance(results, dict):
            matching_rules = results.get("matching_rules") or results.get("rules")
        for rule in matching_rules or []:
            if isinstance(rule, str):
                names.append(rule)
            elif isinstance(rule, dict):
                names.append(str(rule.get("identifier") or rule.get("rule") or rule.get("name")))
            else:
                names.append(str(getattr(rule, "identifier", getattr(rule, "rule", rule))))
        return [n for n in names if n and n != "None"]

    def _parse_yara_x_cli_output(self, output: str) -> list[str]:
        output = output.strip()
        if not output:
            return []
        try:
            payload = json.loads(output)
            return self._rule_names_from_json(payload)
        except Exception:
            return self._parse_text_rule_names(output)

    def _rule_names_from_json(self, payload: Any) -> list[str]:
        names: list[str] = []
        if isinstance(payload, list):
            for item in payload:
                names.extend(self._rule_names_from_json(item))
        elif isinstance(payload, dict):
            for rule in payload.get("rules", []) or []:
                if isinstance(rule, dict):
                    name = rule.get("identifier") or rule.get("rule") or rule.get("name")
                    if name:
                        names.append(str(name))
                elif rule:
                    names.append(str(rule))
            for key in ("matching_rules", "matches"):
                for rule in payload.get(key, []) or []:
                    if isinstance(rule, dict):
                        name = rule.get("identifier") or rule.get("rule") or rule.get("name")
                        if name:
                            names.append(str(name))
                    elif rule:
                        names.append(str(rule))
        return names

    def _parse_text_rule_names(self, output: str) -> list[str]:
        rules: list[str] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            low = line.lower()
            if low.startswith("warning") or low.startswith("error"):
                continue
            # Classic YARA output is: RULE_NAME FILE_PATH
            first = line.split()[0]
            if first and first not in rules:
                rules.append(first)
        return rules

    def cli_command_preview(self, rule_path: str | Path, target: str | Path) -> str:
        if self.backend == "yara-cli" and self.cli:
            return f'"{self.cli}" "{rule_path}" "{target}"'
        if self.backend == "yara-x-cli" and self.cli:
            return f'"{self.cli}" scan "{rule_path}" "{target}"'
        return "Python API backend; no external CLI command is used."

    def as_row(self) -> tuple[str, str, str]:
        status = "OK" if self.available() else "Warning"
        if self.backend == "yara-cli":
            family = "VirusTotal/YARA CLI"
        elif self.is_yara_x:
            family = "YARA-X engine"
        else:
            family = "YARA engine"
        return (family, status, f"{self.backend}: {self.detail}")


def describe_local_yara_source(root_dir: str | Path) -> tuple[str, str, str]:
    root = Path(root_dir)
    src = root / "yara-master"
    if not src.exists():
        return ("VirusTotal/yara source", "Missing", str(src))
    markers = [src / "libyara", src / "cli", src / "configure.ac"]
    ok = all(p.exists() for p in markers)
    return ("VirusTotal/yara source", "OK" if ok else "Warning", str(src))


def describe_local_yara_cli(root_dir: str | Path) -> tuple[str, str, str]:
    engine = YaraEngine(root_dir, prefer_yara_x=False, prefer_cli=True)
    if engine.backend == "yara-cli":
        return ("VirusTotal/yara executable", "OK", engine.detail)
    root = Path(root_dir)
    return ("VirusTotal/yara executable", "Missing", f"Put yara64.exe/yara.exe and yarac64.exe/yarac.exe in {root}")


def describe_local_yara_x_source(root_dir: str | Path) -> tuple[str, str, str]:
    root = Path(root_dir)
    candidates = [root / "yara-x", root / "yara-x-master"]
    for src in candidates:
        if src.exists():
            markers = [src / "cli", src / "Cargo.toml"]
            ok = all(p.exists() for p in markers)
            return ("VirusTotal/yara-x source", "OK" if ok else "Warning", str(src))
    return ("VirusTotal/yara-x source", "Optional", "Install yara-x Python module or yr CLI to use YARA-X")
