# -*- coding: utf-8 -*-
"""
Local goodware DB knowledge helpers for yarGen GUI.

The DBs are intentionally NOT shipped to GitHub because they are large.
This module works with a local dbs/ folder at runtime. It loads only one
DB part at a time to avoid keeping all 44 large DB files in memory.
"""
from __future__ import annotations

import gzip
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

DB_GROUPS = ("strings", "opcodes", "exports", "imphashes")


@dataclass
class DBFileInfo:
    path: Path
    group: str
    part: Optional[int]
    size_bytes: int
    exists: bool
    entries: Optional[int] = None
    error: str = ""

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def size_mb(self) -> float:
        return self.size_bytes / (1024 * 1024)


def detect_group_and_part(name: str) -> Tuple[str, Optional[int]]:
    lowered = name.lower()
    group = "custom"
    for g in DB_GROUPS:
        if f"good-{g}-part" in lowered or f"good-{g}-demo" in lowered:
            group = g
            break
    m = re.search(r"part(\d+)\.db$", lowered)
    return group, int(m.group(1)) if m else None


class GoodwareDBKnowledge:
    """Small, deterministic knowledge layer over yarGen goodware DB files."""

    def __init__(self, db_dir: Path) -> None:
        self.db_dir = Path(db_dir)
        self._summary_cache: List[DBFileInfo] = []
        self._summary_valid = False

    def set_db_dir(self, db_dir: Path) -> None:
        self.db_dir = Path(db_dir)
        self._summary_valid = False
        self._summary_cache = []

    def list_db_files(self) -> List[DBFileInfo]:
        if self._summary_valid:
            return list(self._summary_cache)
        rows: List[DBFileInfo] = []
        if not self.db_dir.exists():
            self._summary_cache = []
            self._summary_valid = True
            return []
        for p in sorted(self.db_dir.glob("*.db"), key=lambda x: x.name.lower()):
            group, part = detect_group_and_part(p.name)
            try:
                size = p.stat().st_size
            except OSError:
                size = 0
            rows.append(DBFileInfo(path=p, group=group, part=part, size_bytes=size, exists=True))
        self._summary_cache = rows
        self._summary_valid = True
        return list(rows)

    def group_summary(self) -> Dict[str, Dict[str, object]]:
        summary: Dict[str, Dict[str, object]] = {}
        for info in self.list_db_files():
            g = info.group
            row = summary.setdefault(g, {"files": 0, "bytes": 0, "parts": []})
            row["files"] = int(row["files"]) + 1
            row["bytes"] = int(row["bytes"]) + info.size_bytes
            if info.part is not None:
                row["parts"].append(info.part)
        for row in summary.values():
            row["mb"] = int(row["bytes"]) / (1024 * 1024)
            row["parts"] = sorted(set(row["parts"]))
        return summary

    def explain_db_coverage(self) -> str:
        rows = self.list_db_files()
        if not rows:
            return f"Không tìm thấy file .db trong: {self.db_dir}"
        summary = self.group_summary()
        lines = [f"DB folder: {self.db_dir}", f"Tổng số DB files: {len(rows)}", ""]
        for g in ["strings", "opcodes", "exports", "imphashes", "custom"]:
            if g not in summary:
                continue
            r = summary[g]
            parts = ", ".join(str(x) for x in r.get("parts", [])) or "custom/demo"
            lines.append(f"- {g}: {r['files']} file, {r['mb']:.2f} MB, parts: {parts}")
        heavy = [x for x in rows if x.size_mb > 50]
        if heavy:
            lines.append("")
            lines.append("DB nặng nhất:")
            for x in sorted(heavy, key=lambda i: i.size_bytes, reverse=True)[:8]:
                lines.append(f"- {x.name}: {x.size_mb:.2f} MB")
        lines.append("")
        lines.append("Ghi chú: app không cần upload DB lên GitHub. DB sẽ được đọc từ máy local khi chạy.")
        return "\n".join(lines)

    def _read_db_object(self, path: Path) -> object:
        with gzip.GzipFile(path, "rb") as fh:
            raw = fh.read()
        return json.loads(raw)

    def count_entries_for_file(self, info: DBFileInfo) -> DBFileInfo:
        try:
            obj = self._read_db_object(info.path)
            info.entries = len(obj) if hasattr(obj, "__len__") else None
        except Exception as exc:
            info.error = str(exc)
        return info

    def iter_files_for_groups(self, groups: Iterable[str], max_part: Optional[int] = None) -> List[DBFileInfo]:
        wanted = set(groups)
        rows = []
        for info in self.list_db_files():
            if info.group not in wanted:
                continue
            if max_part is not None and info.part is not None and info.part > max_part:
                continue
            rows.append(info)
        return rows

    def lookup_values(
        self,
        values: Iterable[str],
        groups: Iterable[str] = ("strings", "exports", "imphashes"),
        max_part: Optional[int] = None,
        case_sensitive: bool = False,
        progress_callback=None,
    ) -> Dict[str, List[str]]:
        """Return mapping value -> DB files that contain it.

        Loads only one DB file at a time. For big DBs this can still take time,
        but it avoids permanently storing the full 44-file DB in memory.
        """
        original_values: List[str] = []
        lookup_values: List[str] = []
        for v in values:
            raw = str(v).strip().strip('"').strip("'")
            if not raw:
                continue
            original_values.append(raw)
            lookup_values.append(raw if case_sensitive else raw.lower())
        result: Dict[str, List[str]] = {v: [] for v in original_values}
        if not lookup_values:
            return result

        files = self.iter_files_for_groups(groups, max_part=max_part)
        for idx, info in enumerate(files, start=1):
            if progress_callback:
                progress_callback(f"Đang quét {idx}/{len(files)}: {info.name}")
            try:
                obj = self._read_db_object(info.path)
                if isinstance(obj, dict):
                    # Most yarGen DBs are JSON dictionaries. Avoid creating a huge
                    # set of 10M+ keys because that can freeze or exhaust RAM.
                    keys = obj
                    direct_found = set()
                    for original, needle in zip(original_values, lookup_values):
                        candidates = [original] if case_sensitive else [original, needle, original.lower(), original.upper()]
                        if any(c in keys for c in candidates):
                            result[original].append(info.name)
                            direct_found.add(needle)

                    # Accurate case-insensitive fallback without building a giant
                    # key_set. This scans keys only for values not found by direct
                    # membership, which is slower but safe for 44 large DB parts.
                    if not case_sensitive:
                        remaining = {needle for needle in lookup_values if needle not in direct_found}
                        if remaining:
                            found_lower = set()
                            for key in keys:
                                lk = str(key).lower()
                                if lk in remaining:
                                    found_lower.add(lk)
                                    if len(found_lower) == len(remaining):
                                        break
                            for original, needle in zip(original_values, lookup_values):
                                if needle in found_lower and info.name not in result[original]:
                                    result[original].append(info.name)
                    del obj
                    continue

                if isinstance(obj, list):
                    # Lists are uncommon and usually smaller. Still scan streaming-style
                    # instead of keeping extra copies where possible.
                    wanted = set(lookup_values)
                    found = set()
                    for item in obj:
                        key = str(item) if case_sensitive else str(item).lower()
                        if key in wanted:
                            found.add(key)
                    for original, needle in zip(original_values, lookup_values):
                        if needle in found:
                            result[original].append(info.name)
                    del obj, wanted, found
            except Exception as exc:
                if progress_callback:
                    progress_callback(f"[WARN] Không đọc được {info.name}: {exc}")
        return result

    def estimate_value_risk(self, value: str, hits: List[str]) -> str:
        if not hits:
            return "Ít thấy trong goodware DB local hoặc chưa scan đủ DB. Có thể là candidate tốt hơn."
        groups = {detect_group_and_part(x)[0] for x in hits}
        if "strings" in groups and len(hits) >= 3:
            return "Rủi ro false positive cao: xuất hiện trong nhiều goodware strings DB."
        if "strings" in groups:
            return "Cần review: xuất hiện trong goodware strings DB."
        return "Có xuất hiện trong goodware DB, nên xem lại trước khi dùng làm IOC mạnh."
