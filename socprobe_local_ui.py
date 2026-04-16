from __future__ import annotations

import json
import os
import shutil
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, font as tkfont, ttk

from modules.ad_connector import test_ad_connection
from modules.analysis_engine import run_assessment
from modules.config_loader import load_config
from modules.event_log_reader import get_event_log_status
from modules.report_generator import generate_report
from modules.scoring_engine import calculate_score, get_control_weights
from modules.ad_connector import connect_to_ad


APP_BG = "#0A1420"
PANEL_BG = "#122334"
CARD_BG = "#173149"
SURFACE_BG = "#21435F"
TEXT = "#E8F4FF"
MUTED = "#91A9BF"
ACCENT = "#24C8FF"
SUCCESS = "#4FD38B"
WARNING = "#F7BB43"
FAIL = "#FF6377"
BORDER = "#2B4F6B"

CONTROL_ORDER = [
    ("privileged_groups", "Privileged group analysis"),
    ("stale_accounts", "Stale account detection"),
    ("disabled_accounts", "Disabled privileged accounts"),
    ("log_validation", "Windows Security Log analysis"),
]


def score_color(score: float) -> str:
    if score >= 80:
        return SUCCESS
    if score >= 60:
        return ACCENT
    if score >= 40:
        return WARNING
    return FAIL


class SOCProbeLocalApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SOCProbe")
        self.root.geometry("1220x860")
        self.root.minsize(1080, 780)
        self.root.configure(bg=APP_BG)

        self.config = load_config()
        self.report_json_path = Path(self.config["output"]["report_path"])
        self.report_pdf_path = Path(self.config["output"]["pdf_report_path"])
        self.current_report = None
        self.scanning = False

        self.font_title = tkfont.Font(family="Segoe UI Semibold", size=24)
        self.font_h2 = tkfont.Font(family="Segoe UI Semibold", size=14)
        self.font_h3 = tkfont.Font(family="Segoe UI Semibold", size=11)
        self.font_body = tkfont.Font(family="Segoe UI", size=10)
        self.font_small = tkfont.Font(family="Segoe UI", size=9)
        self.font_score = tkfont.Font(family="Segoe UI Semibold", size=46)
        self.font_mono = tkfont.Font(family="Consolas", size=10)

        self.control_widgets = {}
        self._build_ui()
        self._log("SOCProbe local client loaded.", "info")
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
        right = tk.Frame(content, bg=APP_BG, width=380)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)

        self._build_summary(left)
        self._build_controls(left)
        self._build_report_panel(left)
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
        self.summary_label = tk.Label(score_inner, text="Run the assessment to generate findings, JSON, and PDF reports.", bg=PANEL_BG, fg=MUTED, font=self.font_body, wraplength=520, justify="left")
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
            detail = tk.Label(left, text="Waiting for scan", bg=CARD_BG, fg=MUTED, font=self.font_body, wraplength=620, justify="left")
            detail.pack(anchor="w", pady=(4, 0))
            right = tk.Frame(inner, bg=CARD_BG)
            right.pack(side="right")
            tk.Label(right, text=f"Weight {weights.get(key, 0)}", bg=SURFACE_BG, fg=ACCENT, font=self.font_small, padx=10, pady=4).pack(side="right", padx=(8, 0))
            badge = tk.Label(right, text="PENDING", bg=SURFACE_BG, fg=MUTED, font=self.font_small, padx=10, pady=4)
            badge.pack(side="right")
            self.control_widgets[key] = {"badge": badge, "detail": detail}

    def _build_report_panel(self, parent):
        frame = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        frame.pack(fill="both", expand=True, pady=(12, 0))
        tk.Label(frame, text="In-App Report View", bg=PANEL_BG, fg=TEXT, font=self.font_h2).pack(anchor="w", padx=18, pady=(16, 8))
        self.report_notebook = ttk.Notebook(frame)
        self.report_notebook.pack(fill="both", expand=True, padx=18, pady=(0, 18))

        summary_tab = tk.Frame(self.report_notebook, bg=CARD_BG)
        json_tab = tk.Frame(self.report_notebook, bg=CARD_BG)
        self.report_notebook.add(summary_tab, text="Summary")
        self.report_notebook.add(json_tab, text="JSON")

        self.summary_text = tk.Text(summary_tab, bg=CARD_BG, fg=TEXT, font=self.font_mono, relief="flat", wrap="word", state="disabled", padx=12, pady=12)
        self.summary_text.pack(fill="both", expand=True)
        self.json_text = tk.Text(json_tab, bg=CARD_BG, fg=TEXT, font=self.font_mono, relief="flat", wrap="none", state="disabled", padx=12, pady=12)
        self.json_text.pack(fill="both", expand=True)

    def _build_side_panel(self, parent):
        ops = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        ops.pack(fill="x")
        inner = tk.Frame(ops, bg=PANEL_BG)
        inner.pack(fill="x", padx=18, pady=18)
        tk.Label(inner, text="Operations", bg=PANEL_BG, fg=TEXT, font=self.font_h2).pack(anchor="w")
        self.state_label = tk.Label(inner, text="Ready", bg=PANEL_BG, fg=MUTED, font=self.font_body)
        self.state_label.pack(anchor="w", pady=(4, 12))
        self.run_button = tk.Button(inner, text="Run Assessment", command=self._start_assessment, bg=ACCENT, fg=APP_BG, relief="flat", padx=12, pady=12)
        self.run_button.pack(fill="x")
        self.open_json_button = tk.Button(inner, text="Open JSON Report", command=lambda: self._open_path(self.report_json_path), state="disabled", bg=SURFACE_BG, fg=MUTED, relief="flat", padx=12, pady=10)
        self.open_json_button.pack(fill="x", pady=(10, 0))
        self.open_pdf_button = tk.Button(inner, text="Open PDF Report", command=lambda: self._open_path(self.report_pdf_path), state="disabled", bg=SURFACE_BG, fg=MUTED, relief="flat", padx=12, pady=10)
        self.open_pdf_button.pack(fill="x", pady=(10, 0))
        self.export_json_button = tk.Button(inner, text="Export JSON As", command=lambda: self._export_report(self.report_json_path, "JSON report", "*.json"), state="disabled", bg=SURFACE_BG, fg=MUTED, relief="flat", padx=12, pady=10)
        self.export_json_button.pack(fill="x", pady=(10, 0))
        self.export_pdf_button = tk.Button(inner, text="Export PDF As", command=lambda: self._export_report(self.report_pdf_path, "PDF report", "*.pdf"), state="disabled", bg=SURFACE_BG, fg=MUTED, relief="flat", padx=12, pady=10)
        self.export_pdf_button.pack(fill="x", pady=(10, 0))

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

    def _write_text(self, widget: tk.Text, value: str):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", value)
        widget.configure(state="disabled")

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
        self.export_json_button.configure(state="normal", fg=TEXT)
        self.export_pdf_button.configure(state="normal", fg=TEXT)
        self.score_label.configure(text=f"{score:.1f}", fg=score_color(score))
        self.tier_label.configure(text=tier, fg=score_color(score))
        self.summary_label.configure(
            text=(
                f"Assessment complete for {self.config['organization']['name']}. "
                f"JSON and PDF reports were generated in {self.report_json_path.parent}."
            )
        )

        for key, label in CONTROL_ORDER:
            finding = findings[key]["finding"]
            passed = findings[key]["passed"]
            self._set_control_state(key, "PASS" if passed else "FAIL", SUCCESS if passed else FAIL, finding)

        event_categories = result["event_log_overview"].get("categories", {})
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

        self._write_text(self.summary_text, "\n".join(summary_lines))
        self._write_text(self.json_text, json.dumps(result, indent=4))
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


def launch_app():
    root = tk.Tk()
    style = ttk.Style()
    style.theme_use("default")
    style.configure("TNotebook", background=APP_BG)
    style.configure("TNotebook.Tab", background=SURFACE_BG, foreground=TEXT, padding=(12, 6))
    SOCProbeLocalApp(root)
    root.mainloop()


if __name__ == "__main__":
    launch_app()
