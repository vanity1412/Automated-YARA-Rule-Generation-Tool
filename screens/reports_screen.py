# -*- coding: utf-8 -*-
import csv
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText

from core.utils import path_row, normalize_path, open_path
from core.yara_score import parse_rule_score_report, build_markdown
from core.scrollable_screen import ScrollableScreen


class ReportsScreen(ScrollableScreen):
    """
    Clean, full-width, scrollable YARA report screen.

    Design goal:
    - Remove the introductory step cards and unnecessary layout controls.
    - Make the screen scrollable from top to bottom.
    - Use full-width sections so there is no unused blank column on the right.
    - Keep the text simple enough for beginners while preserving analyst detail.
    """

    CARD_COLORS = {
        "Production Candidate": "#16a34a",
        "Hunting Candidate": "#2563eb",
        "Hunting / Super Rule": "#7c3aed",
        "Risky / Needs Review": "#f59e0b",
        "Sample-specific / Weak": "#ef4444",
    }

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        self.summary_vars = {
            "total": tk.StringVar(value="0"),
            "best": tk.StringVar(value="Chưa phân tích"),
            "prod": tk.StringVar(value="0"),
            "hunting": tk.StringVar(value="0"),
            "risky": tk.StringVar(value="0"),
            "weak": tk.StringVar(value="0"),
            "review_weak": tk.StringVar(value="0"),
            "risk": tk.StringVar(value="Chưa có dữ liệu"),
        }
        self.status_var = tk.StringVar(value="Chọn file YARA có score rồi bấm Phân tích rule.")
        self.build()

    def refresh_text(self): pass
    def on_mode_changed(self): pass
    def on_show(self): pass

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------
    def build(self):
        content = self.create_scrollable_content("YARA Rule Report")
        self.content = content

        content.columnconfigure(0, weight=1)
        # Đặt weight cho các row - row cuối cùng (report) có thể mở rộng
        content.rowconfigure(0, weight=0)  # input card
        content.rowconfigure(1, weight=0)  # summary cards  
        content.rowconfigure(2, weight=0)  # chart card
        content.rowconfigure(3, weight=1)  # report card - có thể mở rộng

        # Some ScrollableScreen implementations keep the inner frame at its
        # requested width. This binding gently forces the inner content to use
        # the full visible width when the parent canvas supports it.
        content.bind("<Configure>", lambda _e: self._sync_scroll_width())
        self.after_idle(self._sync_scroll_width)

        self._build_input_card(content, row=0)
        self._build_summary_cards(content, row=1)
        self._build_chart_card(content, row=2)
        self._build_report_card(content, row=3)

        self._set_welcome_report()
        self.draw_chart([])

    def _sync_scroll_width(self):
        """Try to make the scrollable content fill the available canvas width."""
        content = getattr(self, "content", None)
        if not content:
            return
        parent = content.master
        if isinstance(parent, tk.Canvas):
            try:
                canvas_width = parent.winfo_width()
                if canvas_width > 1:
                    # Tìm window item trong canvas
                    for item in parent.find_all():
                        if parent.type(item) == "window":
                            parent.itemconfigure(item, width=canvas_width)
                            break
            except Exception:
                # Fallback - không làm gì nếu không thể sync width
                pass

    def _build_input_card(self, parent, row):
        card = ttk.Frame(parent, style="Card.TFrame", padding=14)
        card.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        card.columnconfigure(1, weight=1)

        ttk.Label(card, text="Phân tích YARA Rule", style="Title.TLabel").grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Label(
            card,
            text="Chọn file .yar/.yara đã tạo với --score. App sẽ phân loại rule, vẽ biểu đồ và tạo báo cáo dễ đọc.",
            style="Card.TLabel",
            wraplength=1100,
            justify="left",
        ).grid(row=1, column=0, columnspan=2, sticky="ew", pady=(4, 10))

        path_row(card, 2, "YARA file", self.app.state.var_rule_score_file, self.app.root_dir, "file_open")

        actions = ttk.Frame(card, style="Card.TFrame")
        actions.grid(row=3, column=1, sticky="ew", pady=(10, 0))
        actions.columnconfigure(4, weight=1)

        ttk.Button(actions, text="Phân tích rule", command=self.analyze_rule_scores).grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Button(actions, text="Xuất Markdown", command=self.export_markdown, style="Secondary.TButton").grid(row=0, column=1, sticky="w", padx=(0, 8))
        ttk.Button(actions, text="Xuất CSV", command=self.export_csv, style="Secondary.TButton").grid(row=0, column=2, sticky="w", padx=(0, 8))
        ttk.Button(actions, text="Xóa kết quả", command=self._clear_report, style="Secondary.TButton").grid(row=0, column=3, sticky="w")

        ttk.Label(card, textvariable=self.status_var, style="Card.TLabel", wraplength=1100).grid(row=4, column=1, sticky="ew", pady=(8, 0))

    def _build_summary_cards(self, parent, row):
        card = ttk.Frame(parent, style="Card.TFrame", padding=14)
        card.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        card.columnconfigure(0, weight=1)

        ttk.Label(card, text="Kết quả nhanh", style="H1.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            card,
            text="Đọc phần này trước: nó cho biết rule nào ổn, rule nào chỉ nên hunting và mức rủi ro báo nhầm.",
            style="Card.TLabel",
            wraplength=1100,
            justify="left",
        ).grid(row=1, column=0, sticky="ew", pady=(3, 10))

        grid = ttk.Frame(card, style="Card.TFrame")
        grid.grid(row=2, column=0, sticky="ew")
        for col in range(3):
            grid.columnconfigure(col, weight=1, uniform="summary")

        self._metric_card(grid, 0, 0, "Tổng rule", self.summary_vars["total"], "Số rule đọc được từ file.", "#111827")
        self._metric_card(grid, 0, 1, "Rule mạnh nhất", self.summary_vars["best"], "Rule có max score cao nhất.", "#111827")
        self._metric_card(grid, 0, 2, "Rủi ro", self.summary_vars["risk"], "Khả năng báo nhầm hoặc bỏ sót.", "#f59e0b")
        self._metric_card(grid, 1, 0, "Có thể dùng", self.summary_vars["prod"], "Candidate sau khi test sạch.", "#16a34a")
        self._metric_card(grid, 1, 1, "Hunting", self.summary_vars["hunting"], "Dùng để rà soát nghi vấn.", "#2563eb")
        self._metric_card(grid, 1, 2, "Cần xem lại / yếu", self.summary_vars["review_weak"], "Risky + weak, cần analyst xem kỹ.", "#ef4444")

    def _metric_card(self, parent, row, col, title, value_var, hint, color):
        box = ttk.Frame(parent, style="Surface.TFrame", padding=12)
        box.grid(row=row, column=col, sticky="nsew", padx=(0 if col == 0 else 6, 0 if col == 2 else 6), pady=(0 if row == 0 else 8, 0))
        box.columnconfigure(0, weight=1)

        dot = tk.Canvas(box, width=12, height=12, highlightthickness=0, background="#ffffff")
        dot.grid(row=0, column=0, sticky="w")
        dot.create_oval(2, 2, 10, 10, fill=color, outline=color)

        ttk.Label(box, text=title, style="Card.TLabel").grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Label(box, textvariable=value_var, style="Title.TLabel", wraplength=320).grid(row=2, column=0, sticky="w", pady=(2, 0))
        ttk.Label(box, text=hint, style="Card.TLabel", wraplength=320, justify="left").grid(row=3, column=0, sticky="ew", pady=(4, 0))

    def _build_chart_card(self, parent, row):
        card = ttk.Frame(parent, style="Card.TFrame", padding=14)
        card.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        card.columnconfigure(0, weight=1)

        ttk.Label(card, text="Biểu đồ rule đáng chú ý", style="H1.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            card,
            text="Thanh càng dài nghĩa là indicator càng mạnh. Màu xanh lá là tốt, xanh dương là hunting, vàng là cần xem lại, đỏ là yếu.",
            style="Card.TLabel",
            wraplength=1100,
            justify="left",
        ).grid(row=1, column=0, sticky="ew", pady=(3, 8))

        self.canvas = tk.Canvas(card, height=340, background="#ffffff", highlightthickness=1, highlightbackground="#d1d5db")
        self.canvas.grid(row=2, column=0, sticky="ew")
        self.canvas.bind("<Configure>", lambda _e: self._redraw_chart_if_ready())

    def _build_report_card(self, parent, row):
        card = ttk.Frame(parent, style="Card.TFrame", padding=14)
        card.grid(row=row, column=0, sticky="nsew")
        card.columnconfigure(0, weight=1)
        card.rowconfigure(2, weight=1)

        ttk.Label(card, text="Báo cáo chi tiết", style="H1.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            card,
            text="Kết luận nằm ở đầu báo cáo. Các bảng kỹ thuật, rủi ro và khuyến nghị nằm phía dưới.",
            style="Card.TLabel",
            wraplength=1100,
            justify="left",
        ).grid(row=1, column=0, sticky="ew", pady=(3, 8))

        # Loại bỏ height cố định để ScrolledText có thể mở rộng theo nội dung
        # và sử dụng scroll của ScrollableScreen
        self.report = ScrolledText(card, wrap="word", font=("Consolas", 10), padx=10, pady=10)
        self.report.grid(row=2, column=0, sticky="nsew")

    def _redraw_chart_if_ready(self):
        rows = getattr(self.app.state, "last_rule_score_rows", None)
        if rows:
            self.draw_chart(rows)

    # ------------------------------------------------------------------
    # Language helpers
    # ------------------------------------------------------------------
    def _language_code(self):
        """Return a best-effort UI/report language code: 'vi' or 'en'."""
        candidates = []

        for attr in ("language", "lang", "locale", "current_language", "current_locale"):
            if hasattr(self.app, attr):
                try:
                    candidates.append(getattr(self.app, attr))
                except Exception:
                    pass

        state = getattr(self.app, "state", None)
        if state is not None:
            for attr in ("var_language", "var_lang", "language", "lang", "locale"):
                if hasattr(state, attr):
                    try:
                        value = getattr(state, attr)
                        if hasattr(value, "get"):
                            value = value.get()
                        candidates.append(value)
                    except Exception:
                        pass

        joined = " ".join(str(v).lower() for v in candidates if v not in ("", None))
        if any(k in joined for k in ("vi", "vietnam", "tiếng việt", "tieng viet", "vie")):
            return "vi"
        if any(k in joined for k in ("en", "english", "us", "uk")):
            return "en"

        # User's current report requirement is Vietnamese by default.
        return "vi"

    def _is_vietnamese(self):
        return self._language_code() == "vi"

    def _verdict_label(self, verdict):
        if not self._is_vietnamese():
            return verdict

        mapping = {
            "Production Candidate": "Ứng viên triển khai",
            "Hunting Candidate": "Nên dùng để hunting",
            "Hunting / Super Rule": "Hunting / rule tổng hợp",
            "Risky / Needs Review": "Cần rà soát",
            "Sample-specific / Weak": "Yếu / chỉ bám sample",
        }
        return mapping.get(str(verdict), str(verdict))

    def _risk_level_label(self, level):
        if not self._is_vietnamese():
            return level
        return {
            "Low": "Thấp",
            "Medium": "Trung bình",
            "Medium/High": "Trung bình/Cao",
            "High": "Cao",
        }.get(level, level)

    def _set_welcome_report(self):
        self.report.delete("1.0", tk.END)
        self.report.insert(
            "end",
            (
                "Hướng dẫn nhanh\n"
                "==============\n\n"
                "1. Chọn file YARA đã được tạo kèm --score.\n"
                "2. Bấm 'Phân tích rule'.\n"
                "3. Đọc phần 'Kết quả nhanh' và biểu đồ trước.\n\n"
                "Cách hiểu đơn giản:\n"
                "- Rule tốt: có dấu hiệu đặc trưng, ít trùng phần mềm sạch.\n"
                "- Rule hunting: dùng để tìm nghi vấn, sau đó kiểm tra lại.\n"
                "- Rule risky/weak: có thể báo nhầm hoặc chỉ bắt đúng sample ban đầu.\n\n"
                "Lưu ý: YARA rule giúp nhận diện file giống mẫu đã phân tích, không thay thế phân tích sandbox/reverse engineering.\n"
            ),
        )

    def _clear_report(self):
        self.app.state.last_rule_score_rows = []
        self.app.state.last_rule_score_markdown = ""
        self._reset_summary()
        self.canvas.delete("all")
        self.draw_chart([])
        self.status_var.set("Đã xóa kết quả. Chọn file rồi phân tích lại.")
        self._set_welcome_report()

    # ------------------------------------------------------------------
    # Analysis flow
    # ------------------------------------------------------------------
    def analyze_rule_scores(self):
        path = normalize_path(self.app.state.var_rule_score_file.get() or self.app.state.var_output.get(), self.app.root_dir)
        try:
            rows = parse_rule_score_report(path)
            yara_text = self._read_text_safely(path)
            enriched_rows = self._enrich_rows(rows)
            base_markdown = build_markdown(enriched_rows, path)
            friendly_markdown = self._build_beginner_markdown(enriched_rows, path, yara_text)
            detailed_markdown = self._build_detailed_markdown(enriched_rows, path, yara_text)
            markdown = friendly_markdown.rstrip() + "\n\n---\n\n" + base_markdown.rstrip() + "\n\n" + detailed_markdown

            self.app.state.last_rule_score_rows = enriched_rows
            self.app.state.last_rule_score_markdown = markdown

            self._update_summary(enriched_rows, yara_text)
            self.report.delete("1.0", "end")
            self.report.insert("end", markdown)
            self.draw_chart(enriched_rows)

            self.status_var.set(f"Đã phân tích {len(enriched_rows)} rule từ: {path}")
            if "monitor" in self.app.screens:
                self.app.screens["monitor"].log(f"[SCORE REPORT] Parsed {len(enriched_rows)} rules from {path}\n")
        except Exception as e:
            messagebox.showerror("Rule Score Report", str(e))
            self.status_var.set("Không phân tích được file. Kiểm tra lại đường dẫn hoặc định dạng YARA.")

    # ------------------------------------------------------------------
    # Summary helpers
    # ------------------------------------------------------------------
    def _reset_summary(self):
        self.summary_vars["total"].set("0")
        self.summary_vars["best"].set("Chưa phân tích")
        self.summary_vars["prod"].set("0")
        self.summary_vars["hunting"].set("0")
        self.summary_vars["risky"].set("0")
        self.summary_vars["weak"].set("0")
        self.summary_vars["review_weak"].set("0")
        self.summary_vars["risk"].set("Chưa có dữ liệu")

    def _update_summary(self, rows, yara_text):
        total = len(rows)
        prod = sum(1 for r in rows if r.get("rule_classification") == "Production Candidate")
        hunting = sum(1 for r in rows if "Hunting" in str(r.get("rule_classification", "")))
        risky = sum(1 for r in rows if r.get("rule_classification") == "Risky / Needs Review")
        weak = sum(1 for r in rows if r.get("rule_classification") == "Sample-specific / Weak")

        best = self._best_rule(rows)
        risk_label = self._overall_risk_label(rows, yara_text)

        self.summary_vars["total"].set(str(total))
        self.summary_vars["best"].set(best or "Không có score")
        self.summary_vars["prod"].set(str(prod))
        self.summary_vars["hunting"].set(str(hunting))
        self.summary_vars["risky"].set(str(risky))
        self.summary_vars["weak"].set(str(weak))
        self.summary_vars["review_weak"].set(f"{risky + weak}")
        self.summary_vars["risk"].set(risk_label)

    def _best_rule(self, rows):
        scored = [r for r in rows if self._to_float(r.get("max_score")) is not None]
        if not scored:
            return None
        best = max(scored, key=lambda r: self._to_float(r.get("max_score"), 0.0))
        name = str(best.get("short_name") or best.get("name") or "N/A")
        score = self._to_float(best.get("max_score"), 0.0)
        if len(name) > 28:
            name = name[:25] + "..."
        return f"{name} ({score:.0f})"

    def _overall_risk_label(self, rows, yara_text):
        goodware_rules = sum(1 for r in rows if self._to_int(r.get("goodware_count")) > 0)
        negative_rules = sum(1 for r in rows if self._to_int(r.get("negative_score_count")) > 0)
        weak_rules = sum(1 for r in rows if r.get("rule_classification") == "Sample-specific / Weak")
        has_random = self._looks_like_random_string_heavy(yara_text)

        if goodware_rules or negative_rules:
            return "Cao - có Goodware/negative"
        if weak_rules >= max(1, len(rows) // 2) or has_random:
            return "Trung bình - nhiều rule yếu"
        return "Thấp/Trung bình"

    # ------------------------------------------------------------------
    # Rule scoring helpers
    # ------------------------------------------------------------------
    def _read_text_safely(self, path):
        try:
            return Path(path).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ""

    def _to_float(self, value, default=None):
        try:
            if value in ("", None):
                return default
            return float(value)
        except (TypeError, ValueError):
            return default

    def _to_int(self, value, default=0):
        try:
            if value in ("", None):
                return default
            return int(float(value))
        except (TypeError, ValueError):
            return default

    def _enrich_rows(self, rows):
        enriched = []
        for row in rows:
            r = dict(row)
            classification, reason, action = self._classify_rule(r)
            r["rule_classification"] = classification
            r["classification_reason"] = reason
            r["recommended_action"] = action
            enriched.append(r)
        return enriched

    def _classify_rule(self, r):
        confidence = str(r.get("confidence", "")).strip()
        high_score_count = self._to_int(r.get("high_score_count"))
        goodware_count = self._to_int(r.get("goodware_count"))
        negative_score_count = self._to_int(r.get("negative_score_count"))
        is_super = str(r.get("is_super", "")).lower() in ("1", "true", "yes", "y")
        avg_score = self._to_float(r.get("avg_score"), 0.0)
        max_score = self._to_float(r.get("max_score"), 0.0)
        vi = self._is_vietnamese()

        if is_super:
            if vi:
                return (
                    "Hunting / Super Rule",
                    "Rule tổng hợp nhiều mẫu nên hữu ích để rà soát nhanh, nhưng độ chính xác phụ thuộc vào chất lượng string bên trong. Loại rule này thường phù hợp cho hunting hơn là cảnh báo production.",
                    "Giữ ở chế độ hunting/lab. Chỉ triển khai cảnh báo thật sau khi tách lại indicator mạnh và kiểm thử false positive trên cleanware."
                )
            return (
                "Hunting / Super Rule",
                "The rule combines indicators from multiple samples. It is useful for broad triage, but accuracy depends on the quality of the included strings.",
                "Keep it for hunting/lab use. Deploy to production only after splitting strong indicators and validating false positives."
            )

        if goodware_count > 0 or negative_score_count > 0:
            if vi:
                return (
                    "Risky / Needs Review",
                    "Rule có Goodware String hoặc negative score, nghĩa là một số dấu hiệu có thể xuất hiện trong phần mềm hợp lệ hoặc không đủ đặc trưng cho mã độc.",
                    "Rà soát lại từng string, loại bỏ indicator yếu, rồi test trên cleanware corpus trước khi dùng."
                )
            return (
                "Risky / Needs Review",
                "The rule contains Goodware Strings or negative-score indicators, which means some strings may also appear in legitimate software.",
                "Review each string, remove weak indicators, and test against a cleanware corpus before use."
            )

        if confidence in ("Rất cao", "Cao") and high_score_count >= 2 and avg_score >= 10:
            if vi:
                return (
                    "Production Candidate",
                    "Rule có nhiều indicator điểm cao, confidence tốt và chưa thấy dấu hiệu goodware trong score report. Đây là nhóm đáng tin nhất trong bộ rule.",
                    "Có thể xem là ứng viên triển khai, nhưng vẫn phải test với malware corpus và cleanware corpus trước khi đưa vào SIEM/EDR."
                )
            return (
                "Production Candidate",
                "The rule has multiple high-score indicators, good confidence, and no obvious goodware signals in the score report.",
                "Treat as a deployment candidate, but validate against malware and cleanware corpora before SIEM/EDR use."
            )

        if max_score >= 20 and high_score_count >= 1:
            if vi:
                return (
                    "Hunting Candidate",
                    "Rule có ít nhất một indicator mạnh nhưng tổng thể chưa đủ chắc để xem là rule triển khai. Nó phù hợp để tìm mẫu nghi vấn và hỗ trợ điều tra.",
                    "Dùng cho hunting, retro-hunt hoặc triage. Nên bổ sung điều kiện hành vi, PE metadata hoặc string đặc trưng hơn."
                )
            return (
                "Hunting Candidate",
                "The rule has at least one strong indicator, but the overall rule is not strong enough for production deployment.",
                "Use for hunting, retro-hunting, or triage. Add behavior conditions, PE metadata, or stronger strings."
            )

        if vi:
            return (
                "Sample-specific / Weak",
                "Rule chủ yếu dựa vào string yếu, ngắn, ngẫu nhiên hoặc điểm trung bình thấp. Nó có thể chỉ bắt đúng sample ban đầu hoặc biến thể rất gần.",
                "Chỉ dùng như fingerprint cho sample. Không nên dùng để kết luận family ransomware hoặc triển khai production."
            )
        return (
            "Sample-specific / Weak",
            "The rule mostly relies on weak, short, random-looking, or low-average-score strings. It may only match the original sample or very close variants.",
            "Use only as a sample fingerprint. Do not treat it as family-level ransomware detection."
        )

    # ------------------------------------------------------------------
    # Markdown report
    # ------------------------------------------------------------------
    def _build_beginner_markdown(self, rows, path, yara_text):
        total = len(rows)
        prod = sum(1 for r in rows if r.get("rule_classification") == "Production Candidate")
        hunting = sum(1 for r in rows if "Hunting" in str(r.get("rule_classification", "")))
        risky = sum(1 for r in rows if r.get("rule_classification") == "Risky / Needs Review")
        weak = sum(1 for r in rows if r.get("rule_classification") == "Sample-specific / Weak")
        best = self._best_rule(rows) or ("Không có rule đủ score" if self._is_vietnamese() else "No scored rule")
        risk = self._overall_risk_label(rows, yara_text)

        if not self._is_vietnamese():
            meaning = "This rule set is best used for hunting/lab review first, not direct production deployment."
            if prod > 0 and risky == 0:
                meaning = "Some rules are promising, but false-positive testing is still required before production use."
            elif risky > 0:
                meaning = "Some rules need review because they may alert on legitimate software."

            return "\n".join([
                "# Beginner-Friendly YARA Report",
                "",
                f"**Analyzed file:** `{path}`",
                "",
                "## Quick conclusion",
                "",
                f"- Total rules parsed: **{total}**",
                f"- Strongest rule: **{best}**",
                f"- Deployment candidates: **{prod}**",
                f"- Hunting / triage rules: **{hunting}**",
                f"- Rules needing review: **{risky}**",
                f"- Weak or sample-specific rules: **{weak}**",
                f"- Overall risk: **{risk}**",
                "",
                f"**Interpretation:** {meaning}",
                "",
                "## Plain-language explanation",
                "",
                "- **Good rule:** uses meaningful indicators, avoids common goodware strings, and has enough conditions to reduce noise.",
                "- **Hunting rule:** useful for finding suspicious files, but the result still needs analyst review.",
                "- **Risky rule:** may alert on legitimate software because it contains weak or goodware-associated indicators.",
                "- **Weak rule:** usually matches only the original sample or very close variants.",
            ])

        meaning = "Bộ rule này phù hợp để hunting/lab trước, chưa nên đưa thẳng vào production."
        if prod > 0 and risky == 0:
            meaning = "Bộ rule có một số rule khá tốt, nhưng vẫn cần kiểm thử false positive trước khi dùng trong môi trường thật."
        elif risky > 0:
            meaning = "Bộ rule có rule cần rà soát vì tồn tại nguy cơ báo nhầm phần mềm sạch."

        lines = [
            "# Báo cáo YARA dễ hiểu cho người mới",
            "",
            f"**File phân tích:** `{path}`",
            "",
            "## Kết luận nhanh",
            "",
            f"- Tổng số rule đọc được: **{total}**",
            f"- Rule mạnh nhất: **{best}**",
            f"- Rule có thể xem là ứng viên triển khai: **{prod}**",
            f"- Rule phù hợp để hunting/sàng lọc: **{hunting}**",
            f"- Rule cần rà soát lại: **{risky}**",
            f"- Rule yếu hoặc chỉ bám sample: **{weak}**",
            f"- Rủi ro tổng quan: **{risk}**",
            "",
            f"**Diễn giải trọng tâm:** {meaning}",
            "",
            "## Hiểu nhanh các nhóm rule",
            "",
            "- **Rule tốt:** có dấu hiệu đặc trưng, ít trùng phần mềm sạch, điều kiện match đủ chặt để giảm báo nhầm.",
            "- **Rule hunting:** dùng để tìm file nghi vấn trong lab/SOC, sau đó analyst phải kiểm tra tiếp.",
            "- **Rule cần rà soát:** có Goodware String, negative score hoặc indicator yếu nên có nguy cơ báo nhầm.",
            "- **Rule yếu/chỉ bám sample:** thường chỉ bắt đúng mẫu ban đầu hoặc biến thể rất gần, chưa đại diện tốt cho cả malware family.",
        ]
        return "\n".join(lines)

    def _build_detailed_markdown(self, rows, path, yara_text):
        return "\n\n".join([
            self._build_executive_summary(rows),
            self._build_rule_classification_table(rows),
            self._build_behavior_inference(yara_text),
            self._build_risk_assessment(rows, yara_text),
            self._build_recommendations(rows),
        ])

    def _build_executive_summary(self, rows):
        total = len(rows)
        prod = sum(1 for r in rows if r.get("rule_classification") == "Production Candidate")
        hunting = sum(1 for r in rows if "Hunting" in str(r.get("rule_classification", "")))
        risky = sum(1 for r in rows if r.get("rule_classification") == "Risky / Needs Review")
        weak = sum(1 for r in rows if r.get("rule_classification") == "Sample-specific / Weak")
        best = self._best_rule(rows) or "N/A"

        if not self._is_vietnamese():
            return "\n".join([
                "# Detailed YARA Rule Assessment",
                "",
                "## 1. Executive Summary",
                "",
                f"- **Total rules analyzed:** {total}",
                f"- **Deployment candidates:** {prod}",
                f"- **Hunting / super rules:** {hunting}",
                f"- **Rules needing review:** {risky}",
                f"- **Weak or sample-specific rules:** {weak}",
                f"- **Highest scoring rule:** {best}",
                "",
                "**Assessment:** This report measures rule quality, not full malware behavior. "
                "A high-quality YARA rule is useful for detection and hunting, but the final conclusion still requires validation with cleanware testing, PE analysis, sandboxing, or reverse engineering.",
                "",
                "**Priority:** Review production candidates first, then hunting rules. Treat risky and weak rules as supporting evidence only.",
            ])

        return "\n".join([
            "# Đánh giá chi tiết YARA Rule",
            "",
            "## 1. Tóm tắt điều hành",
            "",
            f"- **Tổng số rule đã phân tích:** {total}",
            f"- **Rule có thể xem là ứng viên triển khai:** {prod}",
            f"- **Rule phù hợp để hunting / rule tổng hợp:** {hunting}",
            f"- **Rule cần rà soát lại:** {risky}",
            f"- **Rule yếu hoặc chỉ bám sample:** {weak}",
            f"- **Rule có điểm cao nhất:** {best}",
            "",
            "**Nhận định chính:** Báo cáo này đánh giá chất lượng rule YARA, không thay thế phân tích mã độc đầy đủ. "
            "Rule tốt giúp phát hiện và hunting hiệu quả hơn, nhưng kết luận cuối cùng vẫn cần kiểm chứng bằng cleanware testing, phân tích PE, sandbox hoặc reverse engineering.",
            "",
            "**Trọng tâm xử lý:** Ưu tiên xem nhóm ứng viên triển khai trước, sau đó đến nhóm hunting. Nhóm risky/weak chỉ nên dùng làm bằng chứng phụ, không nên dùng để kết luận độc lập.",
        ])

    def _build_rule_classification_table(self, rows):
        if not self._is_vietnamese():
            lines = [
                "## 2. Rule Classification",
                "",
                "| # | Rule | Max | Avg | Confidence | Goodware | Negative | Verdict | What it means | Recommended action |",
                "|---:|---|---:|---:|---|---:|---:|---|---|---|",
            ]
            for i, r in enumerate(rows, start=1):
                name = str(r.get("short_name") or r.get("name") or f"rule_{i}")[:48]
                max_score = self._to_float(r.get("max_score"), 0.0)
                avg_score = self._to_float(r.get("avg_score"), 0.0)
                goodware = self._to_int(r.get("goodware_count"))
                negative = self._to_int(r.get("negative_score_count"))
                verdict = r.get("rule_classification", "")
                reason = r.get("classification_reason", "")
                action = r.get("recommended_action", "")
                lines.append(
                    f"| {i} | `{name}` | {max_score:.2f} | {avg_score:.2f} | "
                    f"{r.get('confidence', '')} | {goodware} | {negative} | {verdict} | {reason} | {action} |"
                )
            lines.extend([
                "",
                "**Reading guide:**",
                "",
                "- **Production Candidate:** strongest group, but still requires false-positive testing.",
                "- **Hunting Candidate:** useful for triage and retro-hunting; analyst validation is required.",
                "- **Risky / Needs Review:** contains weak, negative, or goodware-associated indicators.",
                "- **Sample-specific / Weak:** useful only as a fingerprint for the original sample or near variants.",
            ])
            return "\n".join(lines)

        lines = [
            "## 2. Phân loại chất lượng rule",
            "",
            "| # | Rule | Max | Avg | Confidence | Goodware | Negative | Kết luận | Ý nghĩa | Khuyến nghị |",
            "|---:|---|---:|---:|---|---:|---:|---|---|---|",
        ]

        for i, r in enumerate(rows, start=1):
            name = str(r.get("short_name") or r.get("name") or f"rule_{i}")[:48]
            max_score = self._to_float(r.get("max_score"), 0.0)
            avg_score = self._to_float(r.get("avg_score"), 0.0)
            goodware = self._to_int(r.get("goodware_count"))
            negative = self._to_int(r.get("negative_score_count"))
            verdict = self._verdict_label(r.get("rule_classification", ""))
            reason = r.get("classification_reason", "")
            action = r.get("recommended_action", "")
            lines.append(
                f"| {i} | `{name}` | {max_score:.2f} | {avg_score:.2f} | "
                f"{r.get('confidence', '')} | {goodware} | {negative} | {verdict} | {reason} | {action} |"
            )

        lines.extend([
            "",
            "**Cách đọc bảng:**",
            "",
            "- **Ứng viên triển khai:** nhóm tốt nhất, có thể đưa vào danh sách rule candidate nhưng vẫn phải test false positive.",
            "- **Nên dùng để hunting:** phù hợp để tìm mẫu nghi vấn, retro-hunt hoặc hỗ trợ triage.",
            "- **Cần rà soát:** có dấu hiệu dễ báo nhầm, cần kiểm tra từng string trước khi dùng.",
            "- **Yếu / chỉ bám sample:** chỉ nên xem như fingerprint cho sample ban đầu, không đại diện tốt cho cả family.",
        ])
        return "\n".join(lines)

    def _build_behavior_inference(self, yara_text):
        indicators = self._extract_behavior_indicators(yara_text)

        if not self._is_vietnamese():
            lines = [
                "## 3. Behavior Inference From YARA Artifacts",
                "",
                "| Evidence in rule | Possible behavior | Analyst note |",
                "|---|---|---|",
            ]
            if indicators:
                for evidence, behavior, note in indicators:
                    lines.append(f"| `{evidence}` | {behavior} | {note} |")
            else:
                lines.append("| No strong behavior artifact found | Unknown | The rule set may be mostly sample-fingerprint based. |")
            lines.extend([
                "",
                "**Important:** These are hypotheses derived from strings and YARA conditions. Confirm them with PE analysis, sandbox execution, or reverse engineering before writing a final malware-behavior conclusion.",
            ])
            return "\n".join(lines)

        lines = [
            "## 3. Nhận định hành vi từ dấu hiệu trong rule",
            "",
            "| Dấu hiệu tìm thấy | Hành vi có thể suy luận | Ghi chú phân tích |",
            "|---|---|---|",
        ]

        if indicators:
            for evidence, behavior, note in indicators:
                lines.append(f"| `{evidence}` | {behavior} | {note} |")
        else:
            lines.append("| Không thấy artifact hành vi rõ ràng | Chưa đủ cơ sở suy luận | Bộ rule có thể chủ yếu là fingerprint theo sample. |")

        lines.extend([
            "",
            "**Lưu ý quan trọng:** Phần này chỉ là suy luận từ string và condition trong YARA. "
            "Không nên viết là hành vi chắc chắn nếu chưa xác nhận bằng phân tích PE, sandbox hoặc reverse engineering.",
        ])
        return "\n".join(lines)

    def _extract_behavior_indicators(self, text):
        vi = self._is_vietnamese()
        if vi:
            checks = [
                ("encryptor3dll.dll", "Có thể có thành phần encryptor dạng DLL", "Đây là artifact mạnh vì nhắc trực tiếp tới module mã hóa."),
                ("LBB_pass.exe", "Có cơ chế chạy EXE bằng mật khẩu/tham số", "Payload hoặc builder có thể cần tham số để kích hoạt đầy đủ."),
                ("-pass %s", "Thực thi phụ thuộc tham số", "Nếu thiếu tham số, sandbox tự động có thể không kích hoạt đúng hành vi."),
                ("Password_dll.txt", "Có artifact lưu/đọc mật khẩu cho DLL", "Gợi ý workflow vận hành hoặc builder dùng password cho payload DLL."),
                ("Password_exe.txt", "Có artifact lưu/đọc mật khẩu cho EXE", "Gợi ý workflow vận hành hoặc builder dùng password cho payload EXE."),
                ("rundll32", "Có khả năng chạy payload DLL qua tiện ích Windows hợp lệ", "Đáng chú ý cho detection theo process command line."),
                ("Get-ADComputer", "Có dấu hiệu liệt kê máy trong Active Directory", "Gợi ý khả năng chuẩn bị triển khai trên môi trường domain."),
                ("Invoke-GPUpdate", "Có dấu hiệu lạm dụng/cưỡng ép Group Policy Update", "Có thể liên quan đến triển khai hoặc lan rộng trong doanh nghiệp."),
                ("self-spread", "Có nhắc đến khả năng tự lan truyền", "Cần kiểm chứng động, nhưng đây là dấu hiệu đáng chú ý về lateral movement."),
                ("impersonation", "Có nhắc đến impersonation/quyền chạy", "Có thể cần quyền admin cục bộ hoặc ngữ cảnh thông tin xác thực."),
                ("Encryptor Creation Error", "Có logic tạo/build encryptor", "Nghiêng về builder hoặc tool tạo payload hơn là payload đơn lẻ."),
                ("Resource Compression Error", "Có workflow nén/nhúng resource", "Có thể builder nén hoặc nhúng payload vào tài nguyên."),
                ("powershell", "Có dấu hiệu dùng PowerShell", "Nên bổ sung detection theo command line/script nếu triển khai SOC."),
                ("pe.imphash()", "Rule dùng import hash", "Hữu ích để gom cụm sample giống nhau, nhưng dễ mất tác dụng nếu import thay đổi."),
                ("filesize <", "Rule giới hạn kích thước file", "Giúp giảm nhiễu nhưng có thể bỏ sót biến thể rebuild/packed lớn hơn."),
            ]
        else:
            checks = [
                ("encryptor3dll.dll", "Possible encryptor DLL component", "Strong ransomware/builder artifact because it directly references an encryptor module."),
                ("LBB_pass.exe", "Password-protected EXE execution", "The sample may require a runtime password or argument before fully executing."),
                ("-pass %s", "Argument-gated execution", "Can reduce automated sandbox visibility if the required argument is missing."),
                ("Password_dll.txt", "DLL password artifact", "Suggests the builder or operator workflow stores/uses a DLL execution password."),
                ("Password_exe.txt", "EXE password artifact", "Suggests the builder or operator workflow stores/uses an EXE execution password."),
                ("rundll32", "DLL payload execution through Windows utility", "May indicate execution of malicious DLL exports through a legitimate Windows binary."),
                ("Get-ADComputer", "Active Directory computer enumeration", "Potential domain-wide targeting or deployment preparation."),
                ("Invoke-GPUpdate", "Group Policy update abuse or deployment support", "May indicate enterprise/domain propagation or remote execution workflow."),
                ("self-spread", "Self-spreading capability mentioned", "Needs dynamic validation, but the string suggests lateral movement capability."),
                ("impersonation", "Privilege or identity impersonation mentioned", "May require local administrator privileges or credential context."),
                ("Encryptor Creation Error", "Builder/encryptor generation logic", "Points to builder functionality rather than a simple standalone payload."),
                ("Resource Compression Error", "Resource packing/compression workflow", "May indicate the builder embeds or compresses payload resources."),
                ("powershell", "PowerShell-based execution or administration", "Useful for detection engineering across process command lines and scripts."),
                ("pe.imphash()", "Import-hash based detection", "Good for clustering similar builds, but can break when imports change."),
                ("filesize <", "File size constrained detection", "Helps reduce noise, but may miss rebuilt or packed variants."),
            ]

        found = []
        low_text = text.lower()
        for needle, behavior, note in checks:
            if needle.lower() in low_text:
                found.append((needle, behavior, note))
        return found

    def _build_risk_assessment(self, rows, yara_text):
        goodware_rules = sum(1 for r in rows if self._to_int(r.get("goodware_count")) > 0)
        negative_rules = sum(1 for r in rows if self._to_int(r.get("negative_score_count")) > 0)
        super_rules = sum(1 for r in rows if str(r.get("is_super", "")).lower() in ("1", "true", "yes", "y"))
        has_imphash = "pe.imphash()" in yara_text
        has_filesize = "filesize <" in yara_text
        has_random_short_strings = self._looks_like_random_string_heavy(yara_text)

        fp_level = "Low"
        if goodware_rules or negative_rules:
            fp_level = "Medium/High"
        elif super_rules or has_random_short_strings:
            fp_level = "Medium"

        fn_level = "Medium"
        if has_imphash and has_filesize:
            fn_level = "Medium/High"

        if not self._is_vietnamese():
            return "\n".join([
                "## 4. False Positive / False Negative Risk",
                "",
                f"- **False-positive risk:** **{fp_level}**",
                f"  - Rules containing Goodware Strings: **{goodware_rules}**",
                f"  - Rules containing negative-score indicators: **{negative_rules}**",
                f"  - Super rules: **{super_rules}**",
                f"  - Random/short-string heavy pattern detected: **{'Yes' if has_random_short_strings else 'No'}**",
                "",
                f"- **False-negative risk:** **{fn_level}**",
                f"  - Uses `pe.imphash()`: **{'Yes' if has_imphash else 'No'}**",
                f"  - Uses file size constraints: **{'Yes' if has_filesize else 'No'}**",
                "",
                "**Analyst interpretation:**",
                "",
                "- False positives increase when the rule relies on goodware-associated strings, short random strings, or broad super-rule logic.",
                "- False negatives increase when the rule depends on exact strings, exact import hash, exact paths, or tight file-size limits.",
                "- Rebuilt, packed, or reconfigured ransomware variants may bypass sample-specific rules.",
            ])

        return "\n".join([
            "## 4. Đánh giá rủi ro FP/FN",
            "",
            f"- **Rủi ro false positive / báo nhầm:** **{self._risk_level_label(fp_level)}**",
            f"  - Số rule có Goodware String: **{goodware_rules}**",
            f"  - Số rule có negative score: **{negative_rules}**",
            f"  - Số super rule: **{super_rules}**",
            f"  - Có nhiều string ngắn/ngẫu nhiên: **{'Có' if has_random_short_strings else 'Không'}**",
            "",
            f"- **Rủi ro false negative / bỏ sót:** **{self._risk_level_label(fn_level)}**",
            f"  - Có dùng `pe.imphash()`: **{'Có' if has_imphash else 'Không'}**",
            f"  - Có giới hạn `filesize`: **{'Có' if has_filesize else 'Không'}**",
            "",
            "**Diễn giải trọng tâm:**",
            "",
            "- Rủi ro báo nhầm tăng khi rule dùng Goodware String, string quá ngắn/ngẫu nhiên hoặc super rule quá rộng.",
            "- Rủi ro bỏ sót tăng khi rule phụ thuộc vào string chính xác, import hash, đường dẫn tuyệt đối hoặc giới hạn kích thước quá chặt.",
            "- Nếu ransomware bị rebuild, pack lại, đổi import, đổi path hoặc xóa string, rule bám sample có thể không còn match.",
        ])

    def _looks_like_random_string_heavy(self, text):
        fullword_ascii_count = text.count("fullword ascii")
        goodware_count = text.count("Goodware String")
        return fullword_ascii_count >= 30 or goodware_count >= 3

    def _build_recommendations(self, rows):
        if not self._is_vietnamese():
            return "\n".join([
                "## 5. Deployment Recommendations",
                "",
                "### Deployment decision",
                "",
                "- Deploy **Production Candidate** rules only after cleanware and malware corpus validation.",
                "- Keep **Hunting Candidate** and **Super Rule** detections for triage, retro-hunting, and analyst review.",
                "- Do not deploy **Risky / Needs Review** rules until weak and goodware-associated indicators are removed.",
                "- Treat **Sample-specific / Weak** rules as sample fingerprints, not family-level ransomware detections.",
                "",
                "### Improvement checklist",
                "",
                "- Prefer meaningful artifacts: command lines, unique file names, builder messages, mutexes, config markers, exports, protocol strings, and ransom-note markers.",
                "- Avoid short random strings unless they are combined with stronger behavioral or PE conditions.",
                "- Reduce dependency on `imphash`; imports can change when malware is rebuilt or packed.",
                "- Keep `filesize` constraints loose enough to avoid missing rebuilt variants.",
                "- Split rules by purpose: `builder`, `encryptor`, `dll_loader`, `powershell_ad_activity`, and `sample_fingerprint`.",
                "",
                "### Validation commands",
                "",
                "```bash",
                "yarac rule.yar",
                "yara -w rule.yar malware_samples/",
                "yara -w rule.yar cleanware_corpus/",
                "```",
                "",
                "### Final wording",
                "",
                "> The rule set is useful for hunting and initial triage. Some rules contain strong ransomware builder/encryptor artifacts, while others are sample-specific or risky. Validate against cleanware before production deployment.",
            ])

        return "\n".join([
            "## 5. Khuyến nghị triển khai",
            "",
            "### Quyết định sử dụng",
            "",
            "- Chỉ đưa **Ứng viên triển khai** vào SIEM/EDR sau khi đã test trên cả malware corpus và cleanware corpus.",
            "- Giữ nhóm **Hunting Candidate** và **Super Rule** cho lab, retro-hunt, triage hoặc điều tra thủ công.",
            "- Không triển khai nhóm **Cần rà soát** nếu chưa loại bỏ Goodware String, negative score hoặc indicator yếu.",
            "- Xem nhóm **Yếu / chỉ bám sample** như fingerprint của mẫu ban đầu, không dùng để kết luận cả ransomware family.",
            "",
            "### Checklist cải thiện rule",
            "",
            "- Ưu tiên artifact có ý nghĩa: command line, tên file đặc thù, thông báo builder, mutex, marker config, export DLL, chuỗi giao thức hoặc ransom-note marker.",
            "- Tránh dùng string ngắn/ngẫu nhiên nếu không kết hợp với điều kiện mạnh hơn.",
            "- Giảm phụ thuộc vào `imphash` vì import table có thể thay đổi khi malware bị rebuild hoặc pack lại.",
            "- Không đặt `filesize` quá chặt vì dễ bỏ sót biến thể có kích thước khác.",
            "- Nên tách rule theo mục đích: `builder`, `encryptor`, `dll_loader`, `powershell_ad_activity`, `sample_fingerprint`.",
            "",
            "### Lệnh kiểm thử nên chạy",
            "",
            "```bash",
            "yarac rule.yar",
            "yara -w rule.yar malware_samples/",
            "yara -w rule.yar cleanware_corpus/",
            "```",
            "",
            "### Câu kết luận gợi ý cho report",
            "",
            "> Bộ rule hiện phù hợp cho hunting và triage ban đầu. Một số rule có artifact mạnh liên quan ransomware builder/encryptor, nhưng vẫn có rule bám sample hoặc có nguy cơ báo nhầm. Cần kiểm thử với cleanware trước khi triển khai production.",
        ])

    # ------------------------------------------------------------------
    # Chart and export
    # ------------------------------------------------------------------
    def draw_chart(self, rows):
        c = self.canvas
        c.delete("all")
        width = max(900, c.winfo_width() or 1000)

        c.create_text(18, 16, anchor="nw", text="Top rule theo max score", font=("Segoe UI", 13, "bold"))
        c.create_text(
            18,
            40,
            anchor="nw",
            text="Màu cho biết verdict. Điểm cao là dấu hiệu mạnh hơn, không phải kết luận tuyệt đối.",
            font=("Segoe UI", 9),
            fill="#4b5563",
        )

        scored = [r for r in rows if self._to_float(r.get("max_score")) is not None]
        if not scored:
            c.create_text(18, 82, anchor="nw", text="Không thấy score. Hãy tạo rule với --score trước.", fill="#ef4444")
            return

        top_rules = sorted(scored, key=lambda r: self._to_float(r.get("max_score"), 0.0), reverse=True)[:8]
        max_score = max(self._to_float(r.get("max_score"), 0.0) for r in top_rules) or 1.0

        left = 260
        top_y = 82
        bar_h = 24
        gap = 12
        usable_width = max(300, width - left - 130)

        for i, r in enumerate(top_rules):
            y = top_y + i * (bar_h + gap)
            val = self._to_float(r.get("max_score"), 0.0)
            verdict = r.get("rule_classification", "")
            color = self.CARD_COLORS.get(verdict, "#6b7280")
            name = str(r.get("short_name") or r.get("name") or f"rule_{i+1}")
            if len(name) > 34:
                name = name[:31] + "..."

            c.create_text(18, y + bar_h / 2, anchor="w", text=name, font=("Segoe UI", 9))
            c.create_rectangle(left, y, left + usable_width, y + bar_h, fill="#f3f4f6", outline="")
            bw = int(usable_width * val / max_score)
            c.create_rectangle(left, y, left + bw, y + bar_h, fill=color, outline="")
            c.create_text(left + bw + 8, y + bar_h / 2, anchor="w", text=f"{val:.2f}", font=("Segoe UI", 9, "bold"))
            c.create_text(width - 18, y + bar_h / 2, anchor="e", text=verdict, font=("Segoe UI", 8), fill="#374151")

    def export_markdown(self):
        if not self.app.state.last_rule_score_markdown:
            self.analyze_rule_scores()
        out = normalize_path(self.app.state.var_report_dir.get(), self.app.root_dir)
        out.mkdir(parents=True, exist_ok=True)
        path = out / "yara_rule_score_report.md"
        path.write_text(self.app.state.last_rule_score_markdown, encoding="utf-8")
        open_path(path.parent)

    def export_csv(self):
        rows = self.app.state.last_rule_score_rows
        if not rows:
            self.analyze_rule_scores()
            rows = self.app.state.last_rule_score_rows
        if not rows:
            return

        out = normalize_path(self.app.state.var_report_dir.get(), self.app.root_dir)
        out.mkdir(parents=True, exist_ok=True)
        path = out / "yara_rule_score_report.csv"
        fields = [
            "stt",
            "name",
            "string_count",
            "score_count",
            "max_score",
            "avg_score",
            "min_score",
            "confidence",
            "high_score_count",
            "negative_score_count",
            "goodware_count",
            "is_super",
            "rule_classification",
            "classification_reason",
            "recommended_action",
        ]
        with path.open("w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields)
            writer.writeheader()
            for r in rows:
                writer.writerow({k: r.get(k, "") for k in fields})
        open_path(path.parent)
