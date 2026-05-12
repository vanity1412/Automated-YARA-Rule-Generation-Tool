# -*- coding: utf-8 -*-
import json
from pathlib import Path

DEFAULT_SETTINGS = {
    "language": "vi",
    "language_selected": False,
    "theme": "light",
    "mode": "basic",
    "default_db_mode": "Full quality DB",
    "log_retention_lines": 8000,
}

class SettingsManager:
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir
        self.path = root_dir / "settings.json"
        self.data = DEFAULT_SETTINGS.copy()
        self.load()

    def load(self):
        if self.path.exists():
            try:
                obj = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(obj, dict):
                    self.data.update(obj)
            except Exception:
                pass

    def save(self):
        self.path.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), encoding="utf-8")

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, key, value):
        self.data[key] = value

    def reset(self):
        self.data = DEFAULT_SETTINGS.copy()
        self.save()
