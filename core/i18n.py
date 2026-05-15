# -*- coding: utf-8 -*-
TRANSLATIONS = {
    "vi": {
        "nav.home": "Home", "nav.setup": "Setup", "nav.samples": "Samples", "nav.family": "Family",
        "nav.generate": "Generate", "nav.monitor": "Monitor", "nav.validate": "Validate/Test",
        "nav.database": "Database", "nav.reports": "Reports", "nav.analysis": "Analysis Suite", "nav.web": "Web Mode", "nav.settings": "Settings",
        "home.title": "Bảng điều khiển", "home.subtitle": "Workflow tạo chữ ký YARA từ nhiều mẫu malware cùng family.",
        "setup.title": "Kiểm tra môi trường", "setup.validate": "Kiểm tra môi trường",
        "setup.install": "Cài requirements", "setup.update_db": "Tải / cập nhật DB", "setup.open": "Mở thư mục project",
        "samples.title": "Phân tích sample", "samples.scan": "Scan folder",
        "samples.cluster": "Gom cụm mẫu giống nhau", "samples.gen_cluster": "Generate rule per cluster",
        "family.title": "Malware family", "family.apply": "Áp preset Family Rule",
        "family.analyze": "Phân tích folder family", "family.identifier": "Tạo identifier.txt",
        "generate.title": "Tạo YARA rule", "generate.generate": "Tạo YARA rule",
        "generate.preview": "Xem command", "generate.stop": "Dừng", "generate.basic": "Basic options", "generate.advanced": "Advanced options",
        "monitor.title": "Giám sát quá trình generate", "monitor.clear": "Xóa log",
        "monitor.open_rule": "Mở rule", "monitor.open_folder": "Mở folder rules",
        "validate.title": "Validate & Test", "validate.syntax": "Kiểm tra cú pháp",
        "validate.test_malware": "Test malware", "validate.test_goodware": "Test goodware",
        "validate.export_csv": "Xuất CSV", "validate.export_html": "Xuất HTML",
        "database.title": "Database", "database.refresh": "Refresh DB",
        "database.open": "Mở dbs folder", "database.evaluate": "Evaluate selected DB",
        "reports.title": "Báo cáo & chấm điểm rule", "reports.analyze_scores": "Phân tích điểm rule",
        "reports.export_md": "Xuất Markdown", "reports.export_csv": "Xuất CSV",
        "settings.title": "Cài đặt", "settings.save": "Lưu cài đặt", "settings.reset": "Reset",
        "status.env": "Environment", "status.project": "Project", "status.preset": "Preset",
        "status.output": "Output", "status.running": "Status",
    },
    "en": {
        "nav.home": "Home", "nav.setup": "Setup", "nav.samples": "Samples", "nav.family": "Family",
        "nav.generate": "Generate", "nav.monitor": "Monitor", "nav.validate": "Validate/Test",
        "nav.database": "Database", "nav.reports": "Reports", "nav.analysis": "Analysis Suite", "nav.web": "Web Mode", "nav.settings": "Settings",
        "home.title": "Dashboard", "home.subtitle": "Workflow to build YARA signatures from malware family samples.",
        "setup.title": "Environment Check", "setup.validate": "Validate environment",
        "setup.install": "Install requirements", "setup.update_db": "Download / update DBs", "setup.open": "Open project folder",
        "samples.title": "Sample Analyzer", "samples.scan": "Scan folder",
        "samples.cluster": "Cluster similar samples", "samples.gen_cluster": "Generate rule per cluster",
        "family.title": "Malware Family", "family.apply": "Apply Family Rule preset",
        "family.analyze": "Analyze family folder", "family.identifier": "Create identifier.txt",
        "generate.title": "Generate YARA Rules", "generate.generate": "Generate YARA rule",
        "generate.preview": "Preview command", "generate.stop": "Stop", "generate.basic": "Basic options", "generate.advanced": "Advanced options",
        "monitor.title": "Generation Monitor", "monitor.clear": "Clear log",
        "monitor.open_rule": "Open rule", "monitor.open_folder": "Open rules folder",
        "validate.title": "Validate & Test", "validate.syntax": "Validate syntax",
        "validate.test_malware": "Test malware", "validate.test_goodware": "Test goodware",
        "validate.export_csv": "Export CSV", "validate.export_html": "Export HTML",
        "database.title": "Database", "database.refresh": "Refresh DB",
        "database.open": "Open dbs folder", "database.evaluate": "Evaluate selected DB",
        "reports.title": "Reports & Rule Scoring", "reports.analyze_scores": "Analyze rule scores",
        "reports.export_md": "Export Markdown", "reports.export_csv": "Export CSV",
        "settings.title": "Settings", "settings.save": "Save settings", "settings.reset": "Reset",
        "status.env": "Environment", "status.project": "Project", "status.preset": "Preset",
        "status.output": "Output", "status.running": "Status",
    },
}

class I18n:
    def __init__(self, language="vi"):
        self.language = language if language in TRANSLATIONS else "vi"
    def set_language(self, language):
        self.language = language if language in TRANSLATIONS else "vi"
    def t(self, key):
        return TRANSLATIONS.get(self.language, TRANSLATIONS["vi"]).get(key, key)
