from __future__ import annotations

import json
import os
import shutil
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, font as tkfont, messagebox, ttk

from modules.ad_connector import connect_to_ad, test_ad_connection
from modules.config_loader import ConfigLoadError, load_config
from modules.disabled_account_checker import check_disabled_accounts
from modules.event_log_reader import get_event_log_status
from modules.log_validation import check_event_logs
from modules.privileged_group_analyzer import check_privileged_groups
from modules.report_generator import generate_report
from modules.scoring_engine import calculate_score, get_control_weights
from modules.stale_account_detector import check_stale_accounts


APP_BG = "#09131E"
PANEL_BG = "#112436"
CARD_BG = "#173149"
CARD_ALT = "#1D405E"
SURFACE_BG = "#214761"
SURFACE_ALT = "#2B5978"
TEXT = "#E8F4FF"
MUTED = "#93ACC2"
ACCENT = "#28C7FF"
SUCCESS = "#53D48E"
WARNING = "#F2B94B"
FAIL = "#FF6A7F"
BORDER = "#2A4D68"

CONTROL_ORDER = [
    ("privileged_groups", "Privileged group analysis"),
    ("stale_accounts", "Stale account detection"),
    ("disabled_accounts", "Disabled privileged accounts"),
    ("log_validation", "Windows Security Log analysis"),
]

TIER_MAPPING = [
    ("80-100", "High"),
    ("60-79", "Moderate"),
    ("40-59", "Low"),
    ("Below 40", "Poor"),
]

PROGRESS_STEPS = [
    "Loading configuration",
    "Validating environment",
    "Connecting to Active Directory",
    "Validating Windows Security Log access",
    "Enumerating privileged groups",
    "Checking stale accounts",
    "Checking disabled privileged accounts",
    "Reading recent security events",
    "Calculating weighted readiness score",
    "Generating JSON report",
    "Generating PDF report",
    "Finalizing assessment",
]


def score_color(score: float) -> str:
    if score >= 80:
        return SUCCESS
    if score >= 60:
        return ACCENT
    if score >= 40:
        return WARNING
    return FAIL


class SOCProbeDesktopApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SOCProbe")
        self.root.geometry("1280x900")
        self.root.minsize(1120, 800)
        self.root.configure(bg=APP_BG)

        self.config = load_config()
        self.report_json_path = Path(self.config["output"]["report_path"])
        self.report_pdf_path = Path(self.config["output"]["pdf_report_path"])
        self.current_report = None
        self.scanning = False
        self.last_scan_summary = "No scan run yet"

        self.font_title = tkfont.Font(family="Segoe UI Semibold", size=26)
        self.font_h2 = tkfont.Font(family="Segoe UI Semibold", size=15)
        self.font_h3 = tkfont.Font(family="Segoe UI Semibold", size=11)
        self.font_body = tkfont.Font(family="Segoe UI", size=10)
        self.font_small = tkfont.Font(family="Segoe UI", size=9)
        self.font_score = tkfont.Font(family="Segoe UI Semibold", size=48)
        self.font_mono = tkfont.Font(family="Consolas", size=10)
        self.font_mono_small = tkfont.Font(family="Consolas", size=9)

        self.control_widgets = {}
        self.scoring_rows = {}

        self._build_ui()
        self._update_scoring_tab()
        self._log("SOCProbe desktop client loaded.", "info")
        self._log("Running startup checks for Active Directory and Windows Security Log.", "muted")
        self.root.after(100, self._run_startup_checks)

    def _build_ui(self):
        shell = tk.Frame(self.root, bg=APP_BG)
        shell.pack(fill="both", expand=True, padx=18, pady=18)

        self._build_header(shell)

        content = tk.Frame(shell, bg=APP_BG)
        content.pack(fill="both", expand=True, pady=(16, 0))

        left = tk.Frame(content, bg=APP_BG)
        left.pack(side="left", fill="both", expand=True, padx=(0, 10))
        right = tk.Frame(content, bg=APP_BG, width=360)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)

        self._build_main_notebook(left)
        self._build_side_panel(right)

    def _build_header(self, parent):
        frame = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        frame.pack(fill="x")
        tk.Frame(frame, bg=ACCENT, height=3).pack(fill="x")

        inner = tk.Frame(frame, bg=PANEL_BG)
        inner.pack(fill="x", padx=20, pady=18)

        left = tk.Frame(inner, bg=PANEL_BG)
        left.pack(side="left", fill="x", expand=True)
        tk.Label(left, text="SOCProbe", bg=PANEL_BG, fg=TEXT, font=self.font_title).pack(anchor="w")
        tk.Label(
            left,
            text="Single-company local SOC assessment for Active Directory and Windows Security Logs",
            bg=PANEL_BG,
            fg=MUTED,
            font=self.font_body,
        ).pack(anchor="w", pady=(4, 0))
        domain = self.config["domain"]
        org = self.config["organization"]
        tk.Label(
            left,
            text=f"{org['name']} | {domain.get('fqdn', '')} | {domain.get('server', '')}:{domain.get('port', 389)}",
            bg=PANEL_BG,
            fg=MUTED,
            font=self.font_small,
        ).pack(anchor="w", pady=(8, 0))

        self.status_frame = tk.Frame(inner, bg=SURFACE_BG, highlightbackground=ACCENT, highlightthickness=1)
        self.status_frame.pack(side="right")
        self.status_dot = tk.Label(self.status_frame, text="●", bg=SURFACE_BG, fg=ACCENT, font=self.font_body)
        self.status_dot.pack(side="left", padx=(10, 4), pady=8)
        self.status_label = tk.Label(self.status_frame, text="READY", bg=SURFACE_BG, fg=TEXT, font=self.font_h3)
        self.status_label.pack(side="left", padx=(0, 12), pady=8)

    def _build_main_notebook(self, parent):
        self.main_notebook = ttk.Notebook(parent)
        self.main_notebook.pack(fill="both", expand=True)

        overview_tab = tk.Frame(self.main_notebook, bg=APP_BG)
        reports_tab = tk.Frame(self.main_notebook, bg=APP_BG)
        scoring_tab = tk.Frame(self.main_notebook, bg=APP_BG)

        self.main_notebook.add(overview_tab, text="Overview")
        self.main_notebook.add(reports_tab, text="Reports")
        self.main_notebook.add(scoring_tab, text="Scoring Methodology")

        self._build_overview_tab(overview_tab)
        self._build_reports_tab(reports_tab)
        self._build_scoring_tab(scoring_tab)

    def _build_overview_tab(self, parent):
        self._build_summary(parent)
        self._build_controls(parent)
        self._build_detail_sections(parent)

    def _build_summary(self, parent):
        frame = tk.Frame(parent, bg=APP_BG)
        frame.pack(fill="x")

        score_card = tk.Frame(frame, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        score_card.pack(side="left", fill="both", expand=True, padx=(0, 8))
        score_inner = tk.Frame(score_card, bg=PANEL_BG)
        score_inner.pack(fill="both", expand=True, padx=18, pady=18)
        tk.Label(score_inner, text="SOC READINESS SCORE", bg=PANEL_BG, fg=MUTED, font=self.font_small).pack(anchor="w")
        self.score_label = tk.Label(score_inner, text="--", bg=PANEL_BG, fg=TEXT, font=self.font_score)
        self.score_label.pack(anchor="w", pady=(6, 0))
        self.tier_label = tk.Label(score_inner, text="Awaiting assessment", bg=SURFACE_BG, fg=MUTED, font=self.font_h3, padx=12, pady=6)
        self.tier_label.pack(anchor="w", pady=(6, 0))
        self.summary_label = tk.Label(
            score_inner,
            text="Run the assessment to generate findings, event telemetry, remediation guidance, JSON, and PDF reports.",
            bg=PANEL_BG,
            fg=MUTED,
            font=self.font_body,
            wraplength=520,
            justify="left",
        )
        self.summary_label.pack(anchor="w", pady=(12, 0))

        status_card = tk.Frame(frame, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1, width=340)
        status_card.pack(side="right", fill="y")
        status_card.pack_propagate(False)
        status_inner = tk.Frame(status_card, bg=PANEL_BG)
        status_inner.pack(fill="both", expand=True, padx=18, pady=18)
        tk.Label(status_inner, text="STARTUP STATUS", bg=PANEL_BG, fg=MUTED, font=self.font_small).pack(anchor="w")
        self.ad_status = self._build_status_row(status_inner, "Active Directory")
        self.event_status = self._build_status_row(status_inner, "MS Event Log")

    def _build_status_row(self, parent, label: str):
        row = tk.Frame(parent, bg=PANEL_BG)
        row.pack(fill="x", pady=(10, 0))
        tk.Label(row, text=label, bg=PANEL_BG, fg=TEXT, font=self.font_body).pack(side="left")
        badge = tk.Label(row, text="Checking", bg=SURFACE_BG, fg=WARNING, font=self.font_small, padx=10, pady=4)
        badge.pack(side="right")
        detail = tk.Label(parent, text="", bg=PANEL_BG, fg=MUTED, font=self.font_small, wraplength=280, justify="left")
        detail.pack(anchor="w", pady=(2, 0))
        return {"badge": badge, "detail": detail}

    def _build_controls(self, parent):
        frame = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        frame.pack(fill="x", pady=(12, 0))
        tk.Label(frame, text="Assessment Controls", bg=PANEL_BG, fg=TEXT, font=self.font_h2).pack(anchor="w", padx=18, pady=(16, 6))
        weights = get_control_weights(self.config)
        for key, label in CONTROL_ORDER:
            card = tk.Frame(frame, bg=CARD_BG, highlightbackground=BORDER, highlightthickness=1)
            card.pack(fill="x", padx=18, pady=6)
            inner = tk.Frame(card, bg=CARD_BG)
            inner.pack(fill="x", padx=14, pady=12)
            left = tk.Frame(inner, bg=CARD_BG)
            left.pack(side="left", fill="x", expand=True)
            tk.Label(left, text=label, bg=CARD_BG, fg=TEXT, font=self.font_h3).pack(anchor="w")
            detail = tk.Label(left, text="Waiting for scan", bg=CARD_BG, fg=MUTED, font=self.font_body, wraplength=600, justify="left")
            detail.pack(anchor="w", pady=(4, 0))
            right = tk.Frame(inner, bg=CARD_BG)
            right.pack(side="right")
            tk.Label(right, text=f"Weight {weights.get(key, 0)}", bg=SURFACE_BG, fg=ACCENT, font=self.font_small, padx=10, pady=4).pack(side="right", padx=(8, 0))
            badge = tk.Label(right, text="PENDING", bg=SURFACE_BG, fg=MUTED, font=self.font_small, padx=10, pady=4)
            badge.pack(side="right")
            self.control_widgets[key] = {"badge": badge, "detail": detail}

    def _build_detail_sections(self, parent):
        grid = tk.Frame(parent, bg=APP_BG)
        grid.pack(fill="both", expand=True, pady=(12, 0))

        top = tk.Frame(grid, bg=APP_BG)
        top.pack(fill="both", expand=True)
        bottom = tk.Frame(grid, bg=APP_BG)
        bottom.pack(fill="both", expand=True)

        left = tk.Frame(top, bg=APP_BG)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))
        right = tk.Frame(top, bg=APP_BG)
        right.pack(side="right", fill="both", expand=True, padx=(8, 0))

        self.findings_text = self._build_text_card(left, "Findings Summary", 12)
        self.event_log_text = self._build_text_card(right, "Event Log Summary", 12)
        self.remediation_text = self._build_text_card(bottom, "Recommended Actions", 10)

    def _build_reports_tab(self, parent):
        frame = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        frame.pack(fill="both", expand=True)
        tk.Label(frame, text="In-App Report View", bg=PANEL_BG, fg=TEXT, font=self.font_h2).pack(anchor="w", padx=18, pady=(16, 8))
        self.report_notebook = ttk.Notebook(frame)
        self.report_notebook.pack(fill="both", expand=True, padx=18, pady=(0, 18))

        summary_tab = tk.Frame(self.report_notebook, bg=CARD_BG)
        json_tab = tk.Frame(self.report_notebook, bg=CARD_BG)
        self.report_notebook.add(summary_tab, text="Summary")
        self.report_notebook.add(json_tab, text="JSON")

        self.summary_text = tk.Text(summary_tab, bg=CARD_BG, fg=TEXT, font=self.font_mono, relief="flat", wrap="word", state="disabled", padx=12, pady=12)
        self.summary_text.pack(fill="both", expand=True)
        self.json_text = tk.Text(json_tab, bg=CARD_BG, fg=TEXT, font=self.font_mono_small, relief="flat", wrap="none", state="disabled", padx=12, pady=12)
        self.json_text.pack(fill="both", expand=True)

    def _build_scoring_tab(self, parent):
        shell = tk.Frame(parent, bg=APP_BG)
        shell.pack(fill="both", expand=True)

        top = tk.Frame(shell, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        top.pack(fill="x")
        top_inner = tk.Frame(top, bg=PANEL_BG)
        top_inner.pack(fill="x", padx=18, pady=18)

        tk.Label(top_inner, text="Scoring Methodology", bg=PANEL_BG, fg=TEXT, font=self.font_h2).pack(anchor="w")
        tk.Label(
            top_inner,
            text="Readiness Score = (Passed Control Weight / Total Control Weight) × 100",
            bg=PANEL_BG,
            fg=ACCENT,
            font=self.font_mono,
        ).pack(anchor="w", pady=(8, 0))
        tk.Label(
            top_inner,
            text=(
                "These checks are framework-informed, while the numerical score is a custom weighted rule-based "
                "academic scoring model designed for transparent and defendable local SOC readiness assessment."
            ),
            bg=PANEL_BG,
            fg=MUTED,
            font=self.font_body,
            wraplength=860,
            justify="left",
        ).pack(anchor="w", pady=(10, 0))

        metrics_row = tk.Frame(shell, bg=APP_BG)
        metrics_row.pack(fill="x", pady=(12, 0))
        self.scoring_metrics = {}
        for idx, (key, title, default_value) in enumerate(
            [
                ("passed_weight", "Passed Control Weight", "0"),
                ("total_weight", "Total Control Weight", str(sum(get_control_weights(self.config).values()))),
                ("score", "Current Score", "--"),
                ("tier", "Current Tier", "Awaiting assessment"),
            ]
        ):
            card = tk.Frame(metrics_row, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
            card.pack(side="left", fill="both", expand=True, padx=(0, 8) if idx < 3 else 0)
            inner = tk.Frame(card, bg=PANEL_BG)
            inner.pack(fill="both", expand=True, padx=14, pady=14)
            tk.Label(inner, text=title.upper(), bg=PANEL_BG, fg=MUTED, font=self.font_small).pack(anchor="w")
            value = tk.Label(inner, text=default_value, bg=PANEL_BG, fg=TEXT, font=self.font_h2)
            value.pack(anchor="w", pady=(8, 0))
            self.scoring_metrics[key] = value

        lower = tk.Frame(shell, bg=APP_BG)
        lower.pack(fill="both", expand=True, pady=(12, 0))

        controls_card = tk.Frame(lower, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        controls_card.pack(side="left", fill="both", expand=True, padx=(0, 8))
        tk.Label(controls_card, text="Control Weights And Status", bg=PANEL_BG, fg=TEXT, font=self.font_h2).pack(anchor="w", padx=18, pady=(16, 10))

        table = tk.Frame(controls_card, bg=CARD_BG)
        table.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        headers = [("Control", 0), ("Weight", 1), ("Status", 2)]
        for text, column in headers:
            tk.Label(table, text=text, bg=CARD_ALT, fg=TEXT, font=self.font_small, padx=10, pady=8).grid(row=0, column=column, sticky="ew", padx=1, pady=1)
            table.grid_columnconfigure(column, weight=1)

        weights = get_control_weights(self.config)
        for row_index, (key, label) in enumerate(CONTROL_ORDER, start=1):
            tk.Label(table, text=label, bg=CARD_BG, fg=TEXT, font=self.font_body, anchor="w", padx=10, pady=8).grid(row=row_index, column=0, sticky="ew", padx=1, pady=1)
            tk.Label(table, text=str(weights.get(key, 0)), bg=CARD_BG, fg=ACCENT, font=self.font_body, padx=10, pady=8).grid(row=row_index, column=1, sticky="ew", padx=1, pady=1)
            status_label = tk.Label(table, text="Pending", bg=CARD_BG, fg=MUTED, font=self.font_body, padx=10, pady=8)
            status_label.grid(row=row_index, column=2, sticky="ew", padx=1, pady=1)
            self.scoring_rows[key] = status_label

        tiers_card = tk.Frame(lower, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1, width=320)
        tiers_card.pack(side="right", fill="y")
        tiers_card.pack_propagate(False)
        tk.Label(tiers_card, text="Readiness Tier Mapping", bg=PANEL_BG, fg=TEXT, font=self.font_h2).pack(anchor="w", padx=18, pady=(16, 10))
        for threshold, label in TIER_MAPPING:
            row = tk.Frame(tiers_card, bg=PANEL_BG)
            row.pack(fill="x", padx=18, pady=4)
            tk.Label(row, text=threshold, bg=PANEL_BG, fg=ACCENT, font=self.font_mono).pack(side="left")
            tk.Label(row, text=label, bg=PANEL_BG, fg=TEXT, font=self.font_body).pack(side="right")

    def _build_text_card(self, parent, title: str, height: int) -> tk.Text:
        frame = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        frame.pack(fill="both", expand=True, pady=(0, 12))
        tk.Label(frame, text=title, bg=PANEL_BG, fg=TEXT, font=self.font_h2).pack(anchor="w", padx=18, pady=(16, 8))
        text = tk.Text(frame, bg=CARD_BG, fg=TEXT, font=self.font_mono, relief="flat", wrap="word", state="disabled", height=height, padx=12, pady=12)
        text.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        return text

    def _build_side_panel(self, parent):
        ops = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        ops.pack(fill="x")
        inner = tk.Frame(ops, bg=PANEL_BG)
        inner.pack(fill="x", padx=18, pady=18)
        tk.Label(inner, text="Operations", bg=PANEL_BG, fg=TEXT, font=self.font_h2).pack(anchor="w")
        self.state_label = tk.Label(inner, text="Ready", bg=PANEL_BG, fg=MUTED, font=self.font_body)
        self.state_label.pack(anchor="w", pady=(4, 12))
        self.run_button = tk.Button(inner, text="Run Assessment", command=self._start_assessment, bg=ACCENT, fg=APP_BG, activebackground="#5FD9FF", activeforeground=APP_BG, relief="flat", padx=12, pady=12, cursor="hand2")
        self.run_button.pack(fill="x")
        self.open_json_button = tk.Button(inner, text="Open JSON Report", command=lambda: self._open_path(self.report_json_path), state="disabled", bg=SURFACE_BG, fg=MUTED, activebackground=SURFACE_ALT, activeforeground=TEXT, relief="flat", padx=12, pady=10, cursor="hand2")
        self.open_json_button.pack(fill="x", pady=(10, 0))
        self.open_pdf_button = tk.Button(inner, text="Open PDF Report", command=lambda: self._open_path(self.report_pdf_path), state="disabled", bg=SURFACE_BG, fg=MUTED, activebackground=SURFACE_ALT, activeforeground=TEXT, relief="flat", padx=12, pady=10, cursor="hand2")
        self.open_pdf_button.pack(fill="x", pady=(10, 0))

        report_help = tk.Label(
            inner,
            text="Use the report actions after a completed scan to open the generated local JSON and PDF deliverables.",
            bg=PANEL_BG,
            fg=MUTED,
            font=self.font_small,
            wraplength=300,
            justify="left",
        )
        report_help.pack(anchor="w", pady=(10, 0))

        log_frame = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        log_frame.pack(fill="both", expand=True, pady=(12, 0))
        tk.Label(log_frame, text="Activity Log", bg=PANEL_BG, fg=TEXT, font=self.font_h3).pack(anchor="w", padx=18, pady=(16, 8))
        self.log_text = tk.Text(log_frame, bg=CARD_BG, fg=TEXT, font=self.font_mono, relief="flat", wrap="word", state="disabled", padx=12, pady=12)
        self.log_text.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        self.log_text.tag_config("info", foreground=ACCENT)
        self.log_text.tag_config("success", foreground=SUCCESS)
        self.log_text.tag_config("warn", foreground=WARNING)
        self.log_text.tag_config("fail", foreground=FAIL)
        self.log_text.tag_config("muted", foreground=MUTED)

    def _set_status(self, label: str, color: str):
        self.status_label.configure(text=label)
        self.status_dot.configure(fg=color)
        self.status_frame.configure(highlightbackground=color)

    def _set_connection_status(self, widget: dict, label: str, color: str, detail: str):
        widget["badge"].configure(text=label, fg=color)
        widget["detail"].configure(text=detail)

    def _set_control_state(self, key: str, label: str, color: str, detail: str):
        widget = self.control_widgets[key]
        widget["badge"].configure(text=label, fg=color)
        widget["detail"].configure(text=detail)
        if key in self.scoring_rows:
            self.scoring_rows[key].configure(text=label, fg=color)

    def _write_text(self, widget: tk.Text, value: str):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", value)
        widget.configure(state="disabled")

    def _update_scoring_tab(self, report: dict | None = None):
        score_breakdown = (report or {}).get("score_breakdown", {})
        controls = score_breakdown.get("controls", {})
        weights = get_control_weights(self.config)

        passed_weight = score_breakdown.get("passed_control_weight", 0)
        total_weight = score_breakdown.get("total_control_weight", sum(weights.values()))
        current_score = score_breakdown.get("score", "--")
        current_tier = score_breakdown.get("tier", "Awaiting assessment")

        self.scoring_metrics["passed_weight"].configure(text=str(passed_weight))
        self.scoring_metrics["total_weight"].configure(text=str(total_weight))
        self.scoring_metrics["score"].configure(text=str(current_score))
        tier_fg = score_color(float(current_score)) if isinstance(current_score, (int, float)) else TEXT
        self.scoring_metrics["tier"].configure(text=str(current_tier), fg=tier_fg)

        for key, _label in CONTROL_ORDER:
            control_data = controls.get(key)
            if control_data:
                passed = control_data.get("passed", False)
                self.scoring_rows[key].configure(text="PASS" if passed else "FAIL", fg=SUCCESS if passed else FAIL)
            else:
                self.scoring_rows[key].configure(text="Pending", fg=MUTED)

    def _log(self, message: str, tag: str = "info"):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"{message}\n", tag)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _run_startup_checks(self):
        threading.Thread(target=self._startup_checks_worker, daemon=True).start()

    def _startup_checks_worker(self):
        ad_result = test_ad_connection(self.config)
        event_result = get_event_log_status("Security")
        self.root.after(0, lambda: self._apply_startup_checks(ad_result, event_result))

    def _apply_startup_checks(self, ad_result: dict, event_result: dict):
        if ad_result["connected"]:
            self._set_connection_status(self.ad_status, "Connected", SUCCESS, ad_result["message"])
            self._log("Active Directory connection verified.", "success")
        else:
            self._set_connection_status(self.ad_status, "Failed", FAIL, ad_result["message"])
            self._log("Active Directory connection check failed.", "fail")

        if event_result["accessible"]:
            detail = f"Security log accessible with {event_result['record_count']} records."
            self._set_connection_status(self.event_status, "Connected", SUCCESS, detail)
            self._log("Windows Security Log access verified.", "success")
        else:
            self._set_connection_status(self.event_status, "Failed", FAIL, event_result.get("error", "Unavailable"))
            self._log("Windows Security Log access check failed.", "fail")

        self._update_scoring_tab()

    def _start_assessment(self):
        if self.scanning:
            return
        self.scanning = True
        self._set_status("RUNNING", WARNING)
        self.state_label.configure(text="Assessment in progress")
        self.run_button.configure(state="disabled")
        for key, _ in CONTROL_ORDER:
            self._set_control_state(key, "RUNNING", WARNING, "Assessment in progress")
        self._log("Starting SOC assessment.", "info")
        threading.Thread(target=self._assessment_worker, daemon=True).start()

    def _assessment_worker(self):
        conn = None
        try:
            conn = connect_to_ad(self.config)
            findings = run_assessment(conn, self.config)
            score, tier = calculate_score(findings, self.config)
            result = generate_report(findings, score, tier, self.config)
            self.root.after(0, lambda: self._apply_results(findings, score, tier, result))
        except Exception as exc:
            self.root.after(0, lambda: self._apply_error(exc))
        finally:
            if conn is not None and conn.bound:
                conn.unbind()

    def _apply_results(self, findings: dict, score: float, tier: str, result: dict):
        self.scanning = False
        self.current_report = result
        self._set_status("COMPLETE", SUCCESS)
        self.state_label.configure(text="Assessment complete")
        self.run_button.configure(state="normal")
        self.open_json_button.configure(state="normal", fg=TEXT)
        self.open_pdf_button.configure(state="normal", fg=TEXT)
        self.score_label.configure(text=f"{score:.1f}", fg=score_color(score))
        self.tier_label.configure(text=tier, fg=score_color(score))
        self.summary_label.configure(
            text=(
                f"Assessment complete for {self.config['organization']['name']}. "
                f"JSON and PDF reports were generated in {self.report_json_path.parent}."
            )
        )

        for key, _label in CONTROL_ORDER:
            finding = findings[key]["finding"]
            passed = findings[key]["passed"]
            self._set_control_state(key, "PASS" if passed else "FAIL", SUCCESS if passed else FAIL, finding)

        event_categories = result["event_log_overview"].get("categories", {})
        remediation_actions = result.get("remediation_summary", {}).get("recommended_actions", [])
        activity_breakdown = result["event_log_overview"].get("activity_breakdown", {})

        summary_lines = [
            f"Organization: {result['organization']['name']}",
            f"Readiness score: {result['soc_readiness_score']}/100",
            f"Risk tier: {result['risk_level']}",
            "",
            "Findings:",
        ]
        for key, _label in CONTROL_ORDER:
            summary_lines.append(f"- {findings[key]['finding']}")
        summary_lines.append("")
        summary_lines.append(
            f"Relevant security events in last {result['event_log_overview'].get('lookback_days', 0)} day(s): "
            f"{result['event_log_overview'].get('total_relevant_events', 0)}"
        )
        for category_name, meta in event_categories.items():
            summary_lines.append(f"- {meta.get('label', category_name)}: {meta.get('count', 0)}")

        findings_lines = ["Assessment Findings", ""]
        for key, label in CONTROL_ORDER:
            findings_lines.append(f"{label}:")
            findings_lines.append(findings[key]["finding"])
            findings_lines.append("")

        event_lines = [
            "Windows Security Log Summary",
            "",
            f"Telemetry quality: {result['event_log_overview'].get('telemetry_quality', 'unavailable')}",
            f"Lookback window: {result['event_log_overview'].get('lookback_days', 0)} day(s)",
            f"Relevant monitored events: {result['event_log_overview'].get('total_relevant_events', 0)}",
            f"Human successful logons: {activity_breakdown.get('human_successful_logons', 0)}",
            f"Service/machine successful logons: {activity_breakdown.get('service_or_machine_successful_logons', 0)}",
            "",
            "Category counts:",
        ]
        for category_name, meta in event_categories.items():
            event_lines.append(f"- {meta.get('label', category_name)}: {meta.get('count', 0)}")

        remediation_lines = ["Recommended Next Actions", ""]
        if remediation_actions:
            for action in remediation_actions:
                remediation_lines.append(f"[{action.get('priority', '').upper()}] {action.get('recommendation', '')}")
                remediation_lines.append(f"Issue: {action.get('issue', '')}")
                remediation_lines.append("")
        else:
            remediation_lines.append("No immediate remediation items were added for this run.")

        self._write_text(self.summary_text, "\n".join(summary_lines))
        self._write_text(self.json_text, json.dumps(result, indent=4))
        self._write_text(self.findings_text, "\n".join(findings_lines))
        self._write_text(self.event_log_text, "\n".join(event_lines))
        self._write_text(self.remediation_text, "\n".join(remediation_lines))
        self._update_scoring_tab(result)
        self._log(f"Assessment complete with score {score:.1f}/100 ({tier}).", "success")
        self._log(findings["log_validation"]["finding"], "info" if findings["log_validation"]["passed"] else "warn")

    def _apply_error(self, exc: Exception):
        self.scanning = False
        self._set_status("ERROR", FAIL)
        self.state_label.configure(text="Assessment failed")
        self.run_button.configure(state="normal")
        for key, _ in CONTROL_ORDER:
            self._set_control_state(key, "ERROR", FAIL, "Assessment aborted before completion")
        self._log(f"Assessment failed: {exc}", "fail")

    def _open_path(self, path: Path):
        if not path.exists():
            self._log(f"Report not found: {path}", "fail")
            return
        os.startfile(str(path))

def _export_report(self, source: Path, label: str, pattern: str):
        if not source.exists():
            self._log(f"{label} not found: {source}", "fail")
            return
        target = filedialog.asksaveasfilename(
            title=f"Export {label}",
            defaultextension=pattern.split(".")[-1],
            filetypes=[(label, pattern)],
            initialfile=source.name,
        )
        if not target:
            return
        shutil.copyfile(source, target)
        self._log(f"Exported {label} to {target}", "success")


def _final_build_header(self, parent):
    frame = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
    frame.pack(fill="x")
    tk.Frame(frame, bg=ACCENT, height=3).pack(fill="x")

    inner = tk.Frame(frame, bg=PANEL_BG)
    inner.pack(fill="x", padx=20, pady=18)

    left = tk.Frame(inner, bg=PANEL_BG)
    left.pack(side="left", fill="x", expand=True)
    tk.Label(left, text="SOCProbe", bg=PANEL_BG, fg=TEXT, font=self.font_title).pack(anchor="w")
    tk.Label(
        left,
        text="Single-company local SOC assessment for Active Directory and Windows Security Logs",
        bg=PANEL_BG,
        fg=MUTED,
        font=self.font_body,
    ).pack(anchor="w", pady=(4, 0))
    domain = self.config["domain"]
    org = self.config["organization"]
    tk.Label(
        left,
        text=f"{org['name']} | {domain.get('fqdn', '')} | {domain.get('server', '')}:{domain.get('port', 389)}",
        bg=PANEL_BG,
        fg=MUTED,
        font=self.font_small,
    ).pack(anchor="w", pady=(8, 0))

    right = tk.Frame(inner, bg=PANEL_BG)
    right.pack(side="right")
    self.status_frame = tk.Frame(right, bg=SURFACE_BG, highlightbackground=ACCENT, highlightthickness=1)
    self.status_frame.pack(anchor="e")
    self.status_dot = tk.Label(self.status_frame, text="●", bg=SURFACE_BG, fg=ACCENT, font=self.font_body)
    self.status_dot.pack(side="left", padx=(10, 4), pady=8)
    self.status_label = tk.Label(self.status_frame, text="READY", bg=SURFACE_BG, fg=TEXT, font=self.font_h3)
    self.status_label.pack(side="left", padx=(0, 12), pady=8)
    self.last_scan_label = tk.Label(right, text=self.last_scan_summary, bg=PANEL_BG, fg=MUTED, font=self.font_small)
    self.last_scan_label.pack(anchor="e", pady=(8, 0))


def _final_build_detail_sections(self, parent):
    grid = tk.Frame(parent, bg=APP_BG)
    grid.pack(fill="both", expand=True, pady=(12, 0))

    row1 = tk.Frame(grid, bg=APP_BG)
    row1.pack(fill="both", expand=True)
    row2 = tk.Frame(grid, bg=APP_BG)
    row2.pack(fill="both", expand=True)
    row3 = tk.Frame(grid, bg=APP_BG)
    row3.pack(fill="both", expand=True)

    row1_left = tk.Frame(row1, bg=APP_BG)
    row1_left.pack(side="left", fill="both", expand=True, padx=(0, 8))
    row1_right = tk.Frame(row1, bg=APP_BG)
    row1_right.pack(side="right", fill="both", expand=True, padx=(8, 0))

    row2_left = tk.Frame(row2, bg=APP_BG)
    row2_left.pack(side="left", fill="both", expand=True, padx=(0, 8))
    row2_right = tk.Frame(row2, bg=APP_BG)
    row2_right.pack(side="right", fill="both", expand=True, padx=(8, 0))

    self.metadata_text = self._build_text_card(row1_left, "Assessment Metadata", 8)
    self.findings_text = self._build_text_card(row1_right, "Findings Summary", 10)
    self.event_log_text = self._build_text_card(row2_left, "Event Log Summary", 10)
    self.top_risks_text = self._build_text_card(row2_right, "Top Risks", 8)
    self.remediation_text = self._build_text_card(row3, "Recommended Actions", 8)
    self.scan_progress_text = self._build_text_card(row3, "Scan Progress", 8)

    self._write_text(
        self.metadata_text,
        "\n".join(
            [
                f"Organization: {self.config['organization']['name']}",
                f"Domain: {self.config['domain'].get('fqdn', '')}",
                "Scope: single-company local Windows Server capstone deployment",
                f"Last scan: {self.last_scan_summary}",
            ]
        ),
    )


def _final_build_side_panel(self, parent):
    ops = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
    ops.pack(fill="x")
    inner = tk.Frame(ops, bg=PANEL_BG)
    inner.pack(fill="x", padx=18, pady=18)
    tk.Label(inner, text="Operations", bg=PANEL_BG, fg=TEXT, font=self.font_h2).pack(anchor="w")
    self.state_label = tk.Label(inner, text="Ready", bg=PANEL_BG, fg=MUTED, font=self.font_body)
    self.state_label.pack(anchor="w", pady=(4, 12))
    self.run_button = tk.Button(inner, text="Run Assessment", command=self._start_assessment, bg=ACCENT, fg=APP_BG, activebackground="#5FD9FF", activeforeground=APP_BG, relief="flat", padx=12, pady=12, cursor="hand2")
    self.run_button.pack(fill="x")
    self.open_json_button = tk.Button(inner, text="Open JSON Report", command=lambda: self._open_path(self.report_json_path), state="disabled", bg=SURFACE_BG, fg=MUTED, activebackground=SURFACE_ALT, activeforeground=TEXT, relief="flat", padx=12, pady=10, cursor="hand2")
    self.open_json_button.pack(fill="x", pady=(10, 0))
    self.open_pdf_button = tk.Button(inner, text="Open PDF Report", command=lambda: self._open_path(self.report_pdf_path), state="disabled", bg=SURFACE_BG, fg=MUTED, activebackground=SURFACE_ALT, activeforeground=TEXT, relief="flat", padx=12, pady=10, cursor="hand2")
    self.open_pdf_button.pack(fill="x", pady=(10, 0))
    self.open_folder_button = tk.Button(inner, text="Open Reports Folder", command=self._open_reports_folder, bg=SURFACE_BG, fg=TEXT, activebackground=SURFACE_ALT, activeforeground=TEXT, relief="flat", padx=12, pady=10, cursor="hand2")
    self.open_folder_button.pack(fill="x", pady=(10, 0))
    self.export_json_button = tk.Button(inner, text="Export JSON As", command=lambda: self._export_report(self.report_json_path, "JSON report", "*.json"), state="disabled", bg=SURFACE_BG, fg=MUTED, activebackground=SURFACE_ALT, activeforeground=TEXT, relief="flat", padx=12, pady=10, cursor="hand2")
    self.export_json_button.pack(fill="x", pady=(10, 0))
    self.export_pdf_button = tk.Button(inner, text="Export PDF As", command=lambda: self._export_report(self.report_pdf_path, "PDF report", "*.pdf"), state="disabled", bg=SURFACE_BG, fg=MUTED, activebackground=SURFACE_ALT, activeforeground=TEXT, relief="flat", padx=12, pady=10, cursor="hand2")
    self.export_pdf_button.pack(fill="x", pady=(10, 0))

    report_help = tk.Label(
        inner,
        text="Open the generated JSON, PDF, or the reports folder after a completed scan.",
        bg=PANEL_BG,
        fg=MUTED,
        font=self.font_small,
        wraplength=300,
        justify="left",
    )
    report_help.pack(anchor="w", pady=(10, 0))

    log_frame = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
    log_frame.pack(fill="both", expand=True, pady=(12, 0))
    tk.Label(log_frame, text="Activity Log", bg=PANEL_BG, fg=TEXT, font=self.font_h3).pack(anchor="w", padx=18, pady=(16, 8))
    self.log_text = tk.Text(log_frame, bg=CARD_BG, fg=TEXT, font=self.font_mono, relief="flat", wrap="word", state="disabled", padx=12, pady=12)
    self.log_text.pack(fill="both", expand=True, padx=18, pady=(0, 18))
    self.log_text.tag_config("info", foreground=ACCENT)
    self.log_text.tag_config("success", foreground=SUCCESS)
    self.log_text.tag_config("warn", foreground=WARNING)
    self.log_text.tag_config("fail", foreground=FAIL)
    self.log_text.tag_config("muted", foreground=MUTED)


def _append_scan_progress(self, message: str):
    self.scan_progress_text.configure(state="normal")
    self.scan_progress_text.insert("end", f"{message}\n")
    self.scan_progress_text.see("end")
    self.scan_progress_text.configure(state="disabled")


def _reset_scan_progress(self):
    self._write_text(self.scan_progress_text, "")


def _progress(self, message: str):
    self.root.after(0, lambda: self._append_scan_progress(message))
    self.root.after(0, lambda: self._log(message, "muted"))


def _apply_live_control(self, key: str, control_result: dict):
    passed = control_result.get("passed", False)
    self._set_control_state(key, "PASS" if passed else "FAIL", SUCCESS if passed else FAIL, control_result.get("finding", ""))


def _open_reports_folder(self):
    self.report_json_path.parent.mkdir(parents=True, exist_ok=True)
    os.startfile(str(self.report_json_path.parent))


def _final_start_assessment(self):
    if self.scanning:
        return
    self.scanning = True
    self._set_status("RUNNING", WARNING)
    self.state_label.configure(text="Assessment in progress")
    self.run_button.configure(state="disabled")
    self._reset_scan_progress()
    for key, _ in CONTROL_ORDER:
        self._set_control_state(key, "RUNNING", WARNING, "Assessment in progress")
    self._progress("Starting assessment workflow")
    threading.Thread(target=self._final_assessment_worker, daemon=True).start()


def _final_assessment_worker(self):
    conn = None
    try:
        self._progress("1. Loading configuration")
        config = self.config
        time.sleep(0.08)

        self._progress("2. Validating environment")
        ad_status = test_ad_connection(config)
        event_status = get_event_log_status("Security")
        if not ad_status.get("connected", False):
            raise RuntimeError(ad_status.get("message", "Active Directory validation failed."))
        time.sleep(0.08)

        self._progress("3. Connecting to Active Directory")
        conn = connect_to_ad(config)
        time.sleep(0.08)

        self._progress("4. Validating Windows Security Log access")
        self.root.after(
            0,
            lambda: self._set_connection_status(
                self.event_status,
                "Connected" if event_status.get("accessible", False) else "Failed",
                SUCCESS if event_status.get("accessible", False) else FAIL,
                (
                    f"Security log accessible with {event_status.get('record_count', 0)} records."
                    if event_status.get("accessible", False)
                    else event_status.get("error", "Unavailable")
                ),
            ),
        )
        time.sleep(0.08)

        findings = {}

        self._progress("5. Enumerating privileged groups")
        findings["privileged_groups"] = check_privileged_groups(conn, config)
        self.root.after(0, lambda: self._apply_live_control("privileged_groups", findings["privileged_groups"]))

        self._progress("6. Checking stale accounts")
        findings["stale_accounts"] = check_stale_accounts(conn, config)
        self.root.after(0, lambda: self._apply_live_control("stale_accounts", findings["stale_accounts"]))

        self._progress("7. Checking disabled privileged accounts")
        findings["disabled_accounts"] = check_disabled_accounts(conn, config)
        self.root.after(0, lambda: self._apply_live_control("disabled_accounts", findings["disabled_accounts"]))

        self._progress("8. Reading recent security events")
        findings["log_validation"] = check_event_logs(config)
        self.root.after(0, lambda: self._apply_live_control("log_validation", findings["log_validation"]))

        self._progress("9. Calculating weighted readiness score")
        score, tier = calculate_score(findings, config)
        time.sleep(0.08)

        self._progress("10. Generating JSON report")
        result = generate_report(findings, score, tier, config)
        time.sleep(0.08)

        self._progress("11. Generating PDF report")
        time.sleep(0.08)

        self._progress("12. Finalizing assessment")
        self.root.after(0, lambda: self._final_apply_results(findings, score, tier, result))
    except Exception as exc:
        self.root.after(0, lambda: self._final_apply_error(exc))
    finally:
        if conn is not None and conn.bound:
            conn.unbind()


def _final_apply_results(self, findings: dict, score: float, tier: str, result: dict):
    self.scanning = False
    self.current_report = result
    self._set_status("COMPLETE", SUCCESS)
    self.state_label.configure(text="Assessment complete")
    self.run_button.configure(state="normal")
    self.open_json_button.configure(state="normal", fg=TEXT)
    self.open_pdf_button.configure(state="normal", fg=TEXT)
    self.export_json_button.configure(state="normal", fg=TEXT)
    self.export_pdf_button.configure(state="normal", fg=TEXT)
    self.score_label.configure(text=f"{score:.1f}", fg=score_color(score))
    self.tier_label.configure(text=tier, fg=score_color(score))
    timestamp = result.get("assessment_timestamp", "")
    self.last_scan_summary = f"Last scan: {timestamp}"
    self.last_scan_label.configure(text=self.last_scan_summary)
    self.summary_label.configure(
        text=(
            f"Assessment complete for {self.config['organization']['name']}. "
            f"JSON and PDF reports were generated in {self.report_json_path.parent}."
        )
    )

    for key, _label in CONTROL_ORDER:
        finding = findings[key]["finding"]
        passed = findings[key]["passed"]
        self._set_control_state(key, "PASS" if passed else "FAIL", SUCCESS if passed else FAIL, finding)

    event_categories = result["event_log_overview"].get("categories", {})
    remediation_actions = result.get("remediation_summary", {}).get("recommended_actions", [])
    activity_breakdown = result["event_log_overview"].get("activity_breakdown", {})
    top_risks = result.get("top_risks", [])

    summary_lines = [
        f"Organization: {result['organization']['name']}",
        f"Readiness score: {result['soc_readiness_score']}/100",
        f"Risk tier: {result['risk_level']}",
        "",
        "Findings:",
    ]
    for key, _label in CONTROL_ORDER:
        summary_lines.append(f"- {findings[key]['finding']}")
    summary_lines.append("")
    summary_lines.append(
        f"Relevant security events in last {result['event_log_overview'].get('lookback_days', 0)} day(s): "
        f"{result['event_log_overview'].get('total_relevant_events', 0)}"
    )
    for category_name, meta in event_categories.items():
        summary_lines.append(f"- {meta.get('label', category_name)}: {meta.get('count', 0)}")

    findings_lines = ["Assessment Findings", ""]
    for key, label in CONTROL_ORDER:
        findings_lines.append(f"{label}:")
        findings_lines.append(findings[key]["finding"])
        findings_lines.append("")

    event_lines = [
        "Windows Security Log Summary",
        "",
        f"Telemetry quality: {result['event_log_overview'].get('telemetry_quality', 'unavailable')}",
        f"Lookback window: {result['event_log_overview'].get('lookback_days', 0)} day(s)",
        f"Relevant monitored events: {result['event_log_overview'].get('total_relevant_events', 0)}",
        f"Human successful logons: {activity_breakdown.get('human_successful_logons', 0)}",
        f"Service/machine successful logons: {activity_breakdown.get('service_or_machine_successful_logons', 0)}",
        "",
        "Category counts:",
    ]
    for category_name, meta in event_categories.items():
        event_lines.append(f"- {meta.get('label', category_name)}: {meta.get('count', 0)}")

    risk_lines = ["Top Risks", ""]
    if top_risks:
        for risk in top_risks:
            risk_lines.append(f"[{risk.get('severity', '').upper()}] {risk.get('summary', '')}")
            risk_lines.append("")
    else:
        risk_lines.append("No top risks were added for this run.")

    remediation_lines = ["Recommended Next Actions", ""]
    if remediation_actions:
        for action in remediation_actions:
            remediation_lines.append(f"[{action.get('priority', '').upper()}] {action.get('recommendation', '')}")
            remediation_lines.append(f"Issue: {action.get('issue', '')}")
            remediation_lines.append("")
    else:
        remediation_lines.append("No immediate remediation items were added for this run.")

    metadata_lines = [
        f"Organization: {result['organization']['name']}",
        f"Domain: {result['domain'].get('fqdn', '')}",
        f"Timestamp: {result.get('assessment_timestamp', '')}",
        f"Scope: {result.get('assessment_scope', '')}",
        f"Last scan: {result.get('assessment_timestamp', '')}",
    ]

    self._write_text(self.summary_text, "\n".join(summary_lines))
    self._write_text(self.json_text, json.dumps(result, indent=4))
    self._write_text(self.findings_text, "\n".join(findings_lines))
    self._write_text(self.event_log_text, "\n".join(event_lines))
    self._write_text(self.top_risks_text, "\n".join(risk_lines))
    self._write_text(self.remediation_text, "\n".join(remediation_lines))
    self._write_text(self.metadata_text, "\n".join(metadata_lines))
    self._update_scoring_tab(result)
    self._log(f"Assessment complete with score {score:.1f}/100 ({tier}).", "success")
    self._log(findings["log_validation"]["finding"], "info" if findings["log_validation"]["passed"] else "warn")


def _final_apply_error(self, exc: Exception):
    self.scanning = False
    self._set_status("ERROR", FAIL)
    self.state_label.configure(text="Assessment failed")
    self.run_button.configure(state="normal")
    for key, _ in CONTROL_ORDER:
        self._set_control_state(key, "ERROR", FAIL, "Assessment aborted before completion")
    self._progress(f"Assessment failed: {exc}")
    self._log(f"Assessment failed: {exc}", "fail")


SOCProbeDesktopApp._build_header = _final_build_header
SOCProbeDesktopApp._build_detail_sections = _final_build_detail_sections
SOCProbeDesktopApp._build_side_panel = _final_build_side_panel
SOCProbeDesktopApp._append_scan_progress = _append_scan_progress
SOCProbeDesktopApp._reset_scan_progress = _reset_scan_progress
SOCProbeDesktopApp._progress = _progress
SOCProbeDesktopApp._apply_live_control = _apply_live_control
SOCProbeDesktopApp._open_reports_folder = _open_reports_folder
SOCProbeDesktopApp._start_assessment = _final_start_assessment
SOCProbeDesktopApp._final_assessment_worker = _final_assessment_worker
SOCProbeDesktopApp._final_apply_results = _final_apply_results
SOCProbeDesktopApp._final_apply_error = _final_apply_error


def launch_app():
    root = tk.Tk()
    try:
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background=APP_BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=SURFACE_BG, foreground=TEXT, padding=(14, 8), borderwidth=0)
        style.map("TNotebook.Tab", background=[("selected", CARD_ALT)], foreground=[("selected", TEXT)])
        SOCProbeDesktopApp(root)
        root.mainloop()
    except ConfigLoadError as exc:
        root.withdraw()
        messagebox.showerror(
            "SOCProbe Configuration Missing",
            (
                "Configuration missing.\n\n"
                "config.json could not be found.\n\n"
                "For the packaged executable, place config.json next to SOCProbe.exe in dist.\n\n"
                f"Expected location:\n{exc.expected_path}\n\n"
                f"Reports folder:\n{exc.report_directory}\n"
                "The reports folder will be created automatically when needed."
            ),
            parent=root,
        )
        root.destroy()


if __name__ == "__main__":
    launch_app()
