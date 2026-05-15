# -*- coding: utf-8 -*-
APP_TITLE = "yarGen GUI - Wuxia YARA Forge"
APP_VERSION = "3.1.1-wuxia-web"

MIN_DB_PARTS = 9
EXPECTED_DB_PREFIXES = [
    "good-strings-part",
    "good-opcodes-part",
    "good-exports-part",
    "good-imphashes-part",
]

RELEVANT_EXTENSIONS = {
    ".asp", ".aspx", ".bas", ".bat", ".cmd", ".com", ".cpl", ".crt", ".dll",
    ".exe", ".input", ".jsp", ".msc", ".php", ".ps", ".ps1", ".psd1", ".psm1",
    ".py", ".scr", ".sys", ".tmp", ".vb", ".vbe", ".vbs", ".war", ".wsc",
    ".wsf", ".wsh",
}

ARCHIVE_EXTENSIONS = {
    ".7z", ".zip", ".rar", ".gz", ".tgz", ".tar", ".bz2", ".xz", ".cab", ".iso"
}

NAV_ITEMS = [
    ("home", "nav.home"),
    ("setup", "nav.setup"),
    ("samples", "nav.samples"),
    ("family", "nav.family"),
    ("generate", "nav.generate"),
    ("monitor", "nav.monitor"),
    ("validate", "nav.validate"),
    ("database", "nav.database"),
    ("reports", "nav.reports"),
    ("analysis", "nav.analysis"),
    ("web", "nav.web"),
    ("settings", "nav.settings"),
]

PRESET_DESCRIPTIONS = {
    "Beginner": {
        "vi": "Cấu hình cân bằng cho lần chạy đầu tiên. Dễ sinh rule và phù hợp người mới.",
        "en": "Balanced first-run configuration for beginners.",
    },
    "PE Deep": {
        "vi": "Phân tích PE sâu hơn, có thể bật opcode. Chạy chậm và tốn RAM hơn.",
        "en": "Deeper PE analysis, may use opcodes. Slower and more memory-heavy.",
    },
    "Script Malware": {
        "vi": "Dành cho PowerShell, JavaScript, VBS, BAT/CMD.",
        "en": "For PowerShell, JavaScript, VBS, BAT/CMD samples.",
    },
    "Webshell": {
        "vi": "Dành cho PHP/ASP/ASPX/JSP webshell.",
        "en": "For PHP/ASP/ASPX/JSP webshells.",
    },
    "Fast Scan": {
        "vi": "Chạy nhanh để demo/triage. Dùng DB runtime nhẹ và không sửa DB gốc.",
        "en": "Fast triage/demo mode. Uses lightweight runtime DB without modifying original DBs.",
    },
    "TrickBot Demo": {
        "vi": "Cấu hình cân bằng cho mẫu PE TrickBot đã giải nén.",
        "en": "Balanced preset for extracted TrickBot PE samples.",
    },
    "Loose Debug": {
        "vi": "Chỉ dùng để kiểm tra vì sao yarGen ra 0 rule. Không dùng làm rule cuối.",
        "en": "Troubleshooting only when yarGen produces 0 rules. Do not use as final rules.",
    },
}
