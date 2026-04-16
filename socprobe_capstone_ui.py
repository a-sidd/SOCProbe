import datetime
import json
import threading
import tkinter as tk
from pathlib import Path
from tkinter import font as tkfont
from tkinter import ttk

from modules.ad_connector import connect_to_ad
from modules.analysis_engine import run_assessment
from modules.company_directory import discover_companies_in_ad, fetch_company_directory
from modules.config_loader import build_company_config, load_config
from modules.report_generator import generate_report
from modules.scoring_engine import CONTROL_WEIGHTS, calculate_score

APP_BG = "#050505"
PANEL_BG = "#111111"
CARD_BG = "#181818"
CARD_ALT = "#202020"
SURFACE_BG = "#262626"
ACCENT_RED = "#D7263D"
ACCENT_RED_SOFT = "#7A1B27"
ACCENT_RED_DEEP = "#3A0D13"
TEXT_PRIMARY = "#F4F4F4"
TEXT_SECONDARY = "#C7C7C7"
TEXT_MUTED = "#8B8B8B"
BORDER = "#303030"
WARNING = "#E7B34A"
FAIL = "#FF5C70"
SHADOW = "#0A0A0A"

CONTROL_META = [
    ("privileged_groups", "Privileged Group Review", "Domain Admins, Enterprise Admins, Schema Admins"),
    ("stale_accounts", "Stale Account Detection", "Accounts inactive longer than configured threshold"),
    ("disabled_accounts", "Disabled Privileged Accounts", "Disabled identities still present in privileged groups"),
    ("log_validation", "Security Log Access", "Local Windows event log accessibility and record presence"),
]


def score_color(score: float) -> str:
    if score >= 80:
        return TEXT_PRIMARY
    if score >= 60:
        return "#E6E6E6"
    if score >= 40:
        return WARNING
    return FAIL


def tier_colors(tier: str) -> tuple[str, str]:
    palette = {
        "HIGH": (TEXT_PRIMARY, CARD_ALT),
        "MODERATE": ("#F0D9DD", ACCENT_RED_DEEP),
        "LOW": (WARNING, "#3B2A12"),
        "POOR": (FAIL, ACCENT_RED_DEEP),
        "SCANNING": (TEXT_SECONDARY, CARD_ALT),
    }
    return palette.get(tier, (TEXT_PRIMARY, CARD_BG))


class SOCProbeApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SOCProbe")
        self.root.geometry("1360x860")
        self.root.minsize(1180, 780)
        self.root.configure(bg=APP_BG)

        self.base_config = load_config()
        discovery_conn = connect_to_ad(self.base_config)
        discovered_companies = discover_companies_in_ad(discovery_conn, self.base_config)
        self.base_config["companies"] = discovered_companies
        self.base_config["selected_company_slug"] = discovered_companies[0]["slug"]
        self.company_lookup = {company["name"]: company["slug"] for company in discovered_companies}
        self.selected_company_name = tk.StringVar(value=discovered_companies[0]["name"])
        self.active_config = build_company_config(self.base_config, self.base_config["selected_company_slug"])
        self.report_path = Path(self.active_config["output"]["report_path"])
        self.scanning = False

        self.font_display = tkfont.Font(family="Segoe UI", size=50, weight="bold")
        self.font_h1 = tkfont.Font(family="Segoe UI", size=26, weight="bold")
        self.font_h2 = tkfont.Font(family="Segoe UI", size=16, weight="bold")
        self.font_h3 = tkfont.Font(family="Segoe UI", size=11, weight="bold")
        self.font_body = tkfont.Font(family="Segoe UI", size=10)
        self.font_small = tkfont.Font(family="Segoe UI", size=9)
        self.font_mono = tkfont.Font(family="Consolas", size=10)
        self.font_button = tkfont.Font(family="Segoe UI", size=11, weight="bold")

        self.metric_labels = {}
        self.control_widgets = {}
        self.company_labels = {}

        self._configure_styles()
        self._build_ui()
        self._animate_header()
        self._refresh_company_context()
        self._log("SOCProbe desktop client ready", "info")
        self._log("Company options were discovered from Active Directory.", "muted")

    def _configure_styles(self):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Capstone.TNotebook", background=APP_BG, borderwidth=0)
        style.configure("Capstone.TNotebook.Tab", background=CARD_BG, foreground=TEXT_SECONDARY, padding=(18, 10), borderwidth=0)
        style.map("Capstone.TNotebook.Tab", background=[("selected", ACCENT_RED_DEEP)], foreground=[("selected", TEXT_PRIMARY)])
        style.configure("Company.TCombobox", fieldbackground=CARD_BG, background=CARD_BG, foreground=TEXT_PRIMARY)

    def _build_ui(self):
        outer = tk.Frame(self.root, bg=APP_BG)
        outer.pack(fill="both", expand=True, padx=18, pady=18)
        self._build_header(outer)

        notebook = ttk.Notebook(outer, style="Capstone.TNotebook")
        notebook.pack(fill="both", expand=True, pady=(18, 0))

        assessment_tab = tk.Frame(notebook, bg=APP_BG)
        directory_tab = tk.Frame(notebook, bg=APP_BG)
        notebook.add(assessment_tab, text="Assessment")
        notebook.add(directory_tab, text="Company Directory")

        self._build_assessment_tab(assessment_tab)
        self._build_directory_tab(directory_tab)
        self._build_footer(outer)

    def _build_header(self, parent):
        shell = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        shell.pack(fill="x")
        tk.Frame(shell, bg=ACCENT_RED, height=3).pack(fill="x")

        inner = tk.Frame(shell, bg=PANEL_BG)
        inner.pack(fill="x", padx=22, pady=18)

        left = tk.Frame(inner, bg=PANEL_BG)
        left.pack(side="left", fill="x", expand=True)
        self.title_label = tk.Label(left, text="SOCProbe", bg=PANEL_BG, fg=TEXT_PRIMARY, font=self.font_h1)
        self.title_label.pack(anchor="w")
        tk.Label(left, text="Local SOC Assessment Tool for SMB AD and Windows Security Logs", bg=PANEL_BG, fg=TEXT_MUTED, font=self.font_body).pack(anchor="w", pady=(4, 0))

        selector = tk.Frame(left, bg=PANEL_BG)
        selector.pack(anchor="w", pady=(14, 0))
        tk.Label(selector, text="Company Profile", bg=PANEL_BG, fg=TEXT_MUTED, font=self.font_small).pack(anchor="w")
        self.company_combo = ttk.Combobox(selector, textvariable=self.selected_company_name, values=list(self.company_lookup.keys()), state="readonly", style="Company.TCombobox", width=34)
        self.company_combo.pack(anchor="w", pady=(6, 0))
        self.company_combo.bind("<<ComboboxSelected>>", self._on_company_change)

        right = tk.Frame(inner, bg=PANEL_BG)
        right.pack(side="right")
        self.status_shell = tk.Frame(right, bg=CARD_BG, highlightbackground=ACCENT_RED_SOFT, highlightthickness=1)
        self.status_shell.pack(anchor="e", pady=(0, 8))
        self.status_dot = tk.Canvas(self.status_shell, width=14, height=14, bg=CARD_BG, highlightthickness=0)
        self.status_dot.pack(side="left", padx=(10, 4), pady=9)
        self.status_dot_oval = self.status_dot.create_oval(2, 2, 12, 12, fill=ACCENT_RED, outline="")
        self.status_label = tk.Label(self.status_shell, text="READY", bg=CARD_BG, fg=TEXT_PRIMARY, font=self.font_h3)
        self.status_label.pack(side="left", padx=(0, 12), pady=7)
        self.endpoint_label = tk.Label(right, text="", bg=PANEL_BG, fg=TEXT_MUTED, font=self.font_small)
        self.endpoint_label.pack(anchor="e")

    def _build_assessment_tab(self, parent):
        content = tk.Frame(parent, bg=APP_BG)
        content.pack(fill="both", expand=True)

        left = tk.Frame(content, bg=APP_BG)
        left.pack(side="left", fill="both", expand=True, padx=(0, 10))
        right = tk.Frame(content, bg=APP_BG, width=360)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)

        self._build_hero(left)
        self._build_metrics(left)
        self._build_controls(left)
        self._build_side_panel(right)

    def _build_directory_tab(self, parent):
        shell = tk.Frame(parent, bg=APP_BG)
        shell.pack(fill="both", expand=True)

        top = tk.Frame(shell, bg=APP_BG)
        top.pack(fill="x")

        left = tk.Frame(top, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        left.pack(side="left", fill="both", expand=True, padx=(0, 10))
        left_inner = tk.Frame(left, bg=PANEL_BG)
        left_inner.pack(fill="both", expand=True, padx=20, pady=18)
        tk.Label(left_inner, text="Selected company", bg=PANEL_BG, fg=TEXT_PRIMARY, font=self.font_h2).pack(anchor="w")

        for key in ("name", "industry", "environment", "headquarters", "employees", "departments", "summary"):
            label = tk.Label(left_inner, text="", bg=PANEL_BG, fg=TEXT_SECONDARY, font=self.font_body, justify="left", wraplength=520)
            label.pack(anchor="w", pady=(6, 0))
            self.company_labels[key] = label

        right = tk.Frame(top, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1, width=340)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)
        right_inner = tk.Frame(right, bg=PANEL_BG)
        right_inner.pack(fill="both", expand=True, padx=18, pady=18)
        tk.Label(right_inner, text="Directory summary", bg=PANEL_BG, fg=TEXT_PRIMARY, font=self.font_h2).pack(anchor="w")
        self.directory_summary_label = tk.Label(right_inner, text="Run an assessment to load live directory details for the selected company profile.", bg=PANEL_BG, fg=TEXT_MUTED, font=self.font_body, justify="left", wraplength=280)
        self.directory_summary_label.pack(anchor="w", pady=(8, 0))

        tree_shell = tk.Frame(shell, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        tree_shell.pack(fill="both", expand=True, pady=(12, 0))
        tk.Label(tree_shell, text="Departments and users", bg=PANEL_BG, fg=TEXT_PRIMARY, font=self.font_h2).pack(anchor="w", padx=18, pady=(16, 8))

        body = tk.Frame(tree_shell, bg=CARD_BG)
        body.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        columns = ("type", "value", "detail", "status")
        self.directory_tree = ttk.Treeview(body, columns=columns, show="tree headings", height=20)
        self.directory_tree.heading("#0", text="Name")
        self.directory_tree.heading("type", text="Type")
        self.directory_tree.heading("value", text="Primary")
        self.directory_tree.heading("detail", text="Detail")
        self.directory_tree.heading("status", text="Status")
        self.directory_tree.column("#0", width=260)
        self.directory_tree.column("type", width=110, anchor="center")
        self.directory_tree.column("value", width=180)
        self.directory_tree.column("detail", width=260)
        self.directory_tree.column("status", width=90, anchor="center")
        self.directory_tree.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(body, orient="vertical", command=self.directory_tree.yview)
        scroll.pack(side="right", fill="y")
        self.directory_tree.configure(yscrollcommand=scroll.set)

    def _build_hero(self, parent):
        shell = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        shell.pack(fill="x")
        inner = tk.Frame(shell, bg=PANEL_BG)
        inner.pack(fill="x", padx=24, pady=22)

        left = tk.Frame(inner, bg=PANEL_BG)
        left.pack(side="left", fill="both", expand=True)
        tk.Label(left, text="SOC readiness snapshot", bg=PANEL_BG, fg=TEXT_MUTED, font=self.font_h3).pack(anchor="w")
        self.score_display = tk.Label(left, text="--", bg=PANEL_BG, fg=TEXT_PRIMARY, font=self.font_display)
        self.score_display.pack(anchor="w", pady=(6, 0))
        self.tier_label = tk.Label(left, text="Awaiting scan", bg=CARD_ALT, fg=TEXT_SECONDARY, font=self.font_h3, padx=14, pady=7)
        self.tier_label.pack(anchor="w", pady=(8, 0))
        self.report_target_label = tk.Label(left, text="", bg=PANEL_BG, fg=TEXT_MUTED, font=self.font_body)
        self.report_target_label.pack(anchor="w", pady=(12, 0))

        right = tk.Frame(inner, bg=CARD_BG, highlightbackground=BORDER, highlightthickness=1)
        right.pack(side="right", fill="y", padx=(24, 0))
        self.score_ring = tk.Canvas(right, width=220, height=220, bg=CARD_BG, highlightthickness=0)
        self.score_ring.pack(padx=18, pady=16)
        self.score_ring.create_oval(20, 20, 200, 200, outline=SURFACE_BG, width=18)
        self.ring_arc = self.score_ring.create_arc(20, 20, 200, 200, start=90, extent=0, style="arc", outline=ACCENT_RED, width=18)
        self.ring_text = self.score_ring.create_text(110, 96, text="0%", fill=TEXT_PRIMARY, font=("Segoe UI", 28, "bold"))
        self.ring_subtext = self.score_ring.create_text(110, 132, text="No scan yet", fill=TEXT_MUTED, font=("Segoe UI", 10))

    def _build_metrics(self, parent):
        row = tk.Frame(parent, bg=APP_BG)
        row.pack(fill="x", pady=14)
        items = [
            ("controls_passed", "Controls Passed", "0 / 4"),
            ("directory_state", "Directory Findings", "Pending"),
            ("log_state", "Log Validation", "Pending"),
        ]
        for index, (key, title, default) in enumerate(items):
            card = tk.Frame(row, bg=CARD_BG, highlightbackground=BORDER, highlightthickness=1)
            card.pack(side="left", fill="both", expand=True, padx=(0, 10) if index < len(items) - 1 else 0)
            inner = tk.Frame(card, bg=CARD_BG)
            inner.pack(fill="both", expand=True, padx=18, pady=16)
            tk.Label(inner, text=title.upper(), bg=CARD_BG, fg=TEXT_MUTED, font=self.font_small).pack(anchor="w")
            value = tk.Label(inner, text=default, bg=CARD_BG, fg=TEXT_PRIMARY, font=self.font_h2)
            value.pack(anchor="w", pady=(8, 0))
            self.metric_labels[key] = value

    def _build_controls(self, parent):
        shell = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        shell.pack(fill="both", expand=True)
        head = tk.Frame(shell, bg=PANEL_BG)
        head.pack(fill="x", padx=20, pady=(18, 8))
        tk.Label(head, text="Assessment controls", bg=PANEL_BG, fg=TEXT_PRIMARY, font=self.font_h2).pack(anchor="w")
        tk.Label(head, text="Each control contributes to the final readiness score using fixed academic weights.", bg=PANEL_BG, fg=TEXT_MUTED, font=self.font_body).pack(anchor="w", pady=(4, 0))
        body = tk.Frame(shell, bg=PANEL_BG)
        body.pack(fill="both", expand=True, padx=20, pady=(4, 18))

        for key, title, description in CONTROL_META:
            card = tk.Frame(body, bg=CARD_BG, highlightbackground=BORDER, highlightthickness=1)
            card.pack(fill="x", pady=5)
            bar = tk.Frame(card, bg=SHADOW, width=6)
            bar.pack(side="left", fill="y")
            inner = tk.Frame(card, bg=CARD_BG)
            inner.pack(fill="x", expand=True, padx=16, pady=14)
            copy = tk.Frame(inner, bg=CARD_BG)
            copy.pack(side="left", fill="x", expand=True)
            tk.Label(copy, text=title, bg=CARD_BG, fg=TEXT_PRIMARY, font=self.font_h3).pack(anchor="w")
            tk.Label(copy, text=description, bg=CARD_BG, fg=TEXT_MUTED, font=self.font_body).pack(anchor="w", pady=(4, 0))
            detail = tk.Label(copy, text="Waiting for scan", bg=CARD_BG, fg=TEXT_MUTED, font=self.font_small)
            detail.pack(anchor="w", pady=(8, 0))
            status_area = tk.Frame(inner, bg=CARD_BG)
            status_area.pack(side="right")
            tk.Label(status_area, text=f"Weight {CONTROL_WEIGHTS.get(key, 0)}", bg=ACCENT_RED_DEEP, fg="#F0C3CA", font=self.font_small, padx=10, pady=5).pack(side="right", padx=(10, 0))
            status = tk.Label(status_area, text="PENDING", bg=SURFACE_BG, fg=TEXT_MUTED, font=self.font_small, padx=12, pady=5)
            status.pack(side="right")
            self.control_widgets[key] = {"status": status, "detail": detail, "bar": bar}

    def _build_side_panel(self, parent):
        top = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        top.pack(fill="x")
        inner = tk.Frame(top, bg=PANEL_BG)
        inner.pack(fill="x", padx=18, pady=18)
        tk.Label(inner, text="Operations", bg=PANEL_BG, fg=TEXT_PRIMARY, font=self.font_h2).pack(anchor="w")
        tk.Label(inner, text="Run the selected company profile against the configured local AD environment.", bg=PANEL_BG, fg=TEXT_MUTED, font=self.font_body, wraplength=300, justify="left").pack(anchor="w", pady=(4, 14))
        self.run_btn = tk.Button(inner, text="Start Assessment", command=self._run_scan, bg=ACCENT_RED, fg=TEXT_PRIMARY, activebackground="#B41E32", activeforeground=TEXT_PRIMARY, relief="flat", cursor="hand2", font=self.font_button, padx=16, pady=14)
        self.run_btn.pack(fill="x")
        self.report_btn = tk.Button(inner, text="Open JSON Report", command=self._view_report, state="disabled", bg=CARD_ALT, fg=TEXT_MUTED, activebackground=SURFACE_BG, activeforeground=TEXT_PRIMARY, relief="flat", cursor="hand2", font=self.font_button, padx=16, pady=12)
        self.report_btn.pack(fill="x", pady=(10, 0))

        log_shell = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        log_shell.pack(fill="both", expand=True, pady=(12, 0))
        tk.Label(log_shell, text="Activity log", bg=PANEL_BG, fg=TEXT_PRIMARY, font=self.font_h3).pack(anchor="w", padx=18, pady=(16, 8))
        text_wrap = tk.Frame(log_shell, bg=CARD_BG, highlightbackground=BORDER, highlightthickness=1)
        text_wrap.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        self.log_text = tk.Text(text_wrap, bg=CARD_BG, fg=TEXT_SECONDARY, insertbackground=TEXT_PRIMARY, selectbackground=ACCENT_RED_SOFT, relief="flat", wrap="word", state="disabled", font=self.font_mono, padx=14, pady=14)
        self.log_text.pack(side="left", fill="both", expand=True)
        scroll = tk.Scrollbar(text_wrap, command=self.log_text.yview, width=10, troughcolor=CARD_BG)
        scroll.pack(side="right", fill="y")
        self.log_text.configure(yscrollcommand=scroll.set)
        self.log_text.tag_config("info", foreground="#E6E6E6")
        self.log_text.tag_config("success", foreground=TEXT_PRIMARY)
        self.log_text.tag_config("fail", foreground=FAIL)
        self.log_text.tag_config("warn", foreground=WARNING)
        self.log_text.tag_config("muted", foreground=TEXT_MUTED)

    def _build_footer(self, parent):
        footer = tk.Frame(parent, bg=APP_BG)
        footer.pack(fill="x", pady=(16, 0))
        tk.Label(footer, text="SOCProbe v1.0  |  Sheridan College Capstone  |  Local Windows assessment client", bg=APP_BG, fg=TEXT_MUTED, font=self.font_small).pack(side="left")
        self.timestamp_label = tk.Label(footer, text="No scans run", bg=APP_BG, fg=TEXT_MUTED, font=self.font_small)
        self.timestamp_label.pack(side="right")

    def _animate_header(self):
        colors = [TEXT_PRIMARY, "#F2D8DC", "#FFFFFF", "#E8C0C8"]
        self._header_index = 0

        def cycle():
            self.title_label.configure(fg=colors[self._header_index % len(colors)])
            self._header_index += 1
            self.root.after(900, cycle)

        cycle()

    def _on_company_change(self, _event=None):
        if self.scanning:
            return
        slug = self.company_lookup[self.selected_company_name.get()]
        self.active_config = build_company_config(self.base_config, slug)
        self.report_path = Path(self.active_config["output"]["report_path"])
        self._refresh_company_context()
        self._reset_visuals_for_company()
        self._log(f"Company profile switched to {self.active_config['selected_company']['name']}.", "info")

    def _refresh_company_context(self):
        company = self.active_config["selected_company"]
        profile = company.get("profile", {})
        domain = self.active_config["domain"]
        self.endpoint_label.configure(text=f"{domain.get('fqdn', 'local')}  |  {domain.get('server', '127.0.0.1')}:{domain.get('port', 389)}")
        self.report_target_label.configure(text=f"Report output: {self.report_path}")
        self.company_labels["name"].configure(text=f"Company: {company.get('name', 'Unknown')}")
        self.company_labels["industry"].configure(text=f"Industry: {company.get('industry', 'N/A')}")
        self.company_labels["environment"].configure(text=f"Environment: {company.get('environment', 'N/A')}")
        self.company_labels["headquarters"].configure(text=f"Headquarters: {profile.get('headquarters', 'N/A')}")
        self.company_labels["employees"].configure(text=f"Employee estimate: {profile.get('employees', 'N/A')}")
        self.company_labels["departments"].configure(text=f"Declared departments: {', '.join(profile.get('departments', [])) or 'N/A'}")
        self.company_labels["summary"].configure(text=f"Summary: {profile.get('summary', 'No summary configured.')}")
        self.directory_summary_label.configure(text="Run an assessment to load live directory details for the selected company profile.")
        for item in self.directory_tree.get_children():
            self.directory_tree.delete(item)

    def _reset_visuals_for_company(self):
        self.score_display.configure(text="--", fg=TEXT_PRIMARY)
        self.tier_label.configure(text="Awaiting scan", fg=TEXT_SECONDARY, bg=CARD_ALT)
        self.score_ring.itemconfig(self.ring_arc, outline=ACCENT_RED, extent=0)
        self.score_ring.itemconfig(self.ring_text, text="0%")
        self.score_ring.itemconfig(self.ring_subtext, text="No scan yet")
        self.metric_labels["controls_passed"].configure(text="0 / 4")
        self.metric_labels["directory_state"].configure(text="Pending")
        self.metric_labels["log_state"].configure(text="Pending")
        self.report_btn.configure(state="disabled", fg=TEXT_MUTED)
        for key in self.control_widgets:
            self._set_control_state(key, "PENDING", "Waiting for scan", TEXT_MUTED, SURFACE_BG, SHADOW)

    def _pulse_status(self):
        colors = [ACCENT_RED, FAIL]
        self._pulse_frame = 0

        def pulse():
            if not self.scanning:
                return
            color = colors[self._pulse_frame % len(colors)]
            self.status_dot.itemconfig(self.status_dot_oval, fill=color)
            self._pulse_frame += 1
            self.root.after(450, pulse)

        pulse()

    def _set_status(self, text: str, dot_color: str, border_color: str | None = None):
        self.status_label.configure(text=text, fg=TEXT_PRIMARY)
        self.status_dot.itemconfig(self.status_dot_oval, fill=dot_color)
        self.status_shell.configure(highlightbackground=border_color or dot_color)

    def _log(self, message: str, tag: str = "info"):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{timestamp}] {message}\n", tag)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _update_score_visuals(self, score: float, tier: str):
        color = score_color(score)
        extent = -(max(0, min(score, 100)) / 100) * 360
        tier_fg, tier_bg = tier_colors(tier)
        self.score_display.configure(text=f"{score:.1f}", fg=color)
        self.tier_label.configure(text=tier, fg=tier_fg, bg=tier_bg)
        self.score_ring.itemconfig(self.ring_arc, outline=color, extent=extent)
        self.score_ring.itemconfig(self.ring_text, text=f"{int(round(score))}%")
        self.score_ring.itemconfig(self.ring_subtext, text=tier.title(), fill=TEXT_MUTED)

    def _set_control_state(self, key: str, label: str, detail: str, fg: str, bg: str, bar_color: str):
        widget = self.control_widgets[key]
        widget["status"].configure(text=label, fg=fg, bg=bg)
        widget["detail"].configure(text=detail, fg=TEXT_SECONDARY if label == "PASS" else TEXT_MUTED)
        widget["bar"].configure(bg=bar_color)

    def _run_scan(self):
        if self.scanning:
            return

        self.scanning = True
        self.run_btn.configure(state="disabled", text="Assessment Running", bg=ACCENT_RED_SOFT)
        self.report_btn.configure(state="disabled", fg=TEXT_MUTED)
        self.metric_labels["controls_passed"].configure(text="Scanning")
        self.metric_labels["directory_state"].configure(text="Collecting")
        self.metric_labels["log_state"].configure(text="Collecting")
        self._update_score_visuals(0.0, "SCANNING")
        self._set_status("SCANNING", ACCENT_RED, FAIL)
        for key in self.control_widgets:
            self._set_control_state(key, "RUNNING", "Assessment in progress", WARNING, SURFACE_BG, ACCENT_RED_SOFT)
        self._pulse_status()
        self._log(f"Starting local assessment for {self.active_config['selected_company']['name']}.", "info")
        threading.Thread(target=self._run_assessment, daemon=True).start()

    def _run_assessment(self):
        try:
            config = self.active_config
            self._log("Configuration loaded.", "success")
            self._log("Connecting to Active Directory.", "info")
            conn = connect_to_ad(config)
            self._log("Active Directory connection established.", "success")
            self._log("Executing assessment modules.", "info")

            findings = run_assessment(conn, config)
            directory_data = fetch_company_directory(conn, config)

            for key, _, _ in CONTROL_META:
                control = findings[key]
                self.root.after(
                    0,
                    lambda control_key=key, passed_state=control.get("passed", False), detail=control.get("finding", ""):
                    self._apply_control_result(control_key, passed_state, detail),
                )

            score, tier = calculate_score(findings)
            generate_report(findings, score, tier, config)
            self.root.after(0, lambda: self._show_results(score, tier, findings, directory_data))
        except Exception as exc:
            self.root.after(0, lambda: self._handle_error(exc))

    def _apply_control_result(self, key: str, passed: bool, detail: str):
        if passed:
            self._set_control_state(key, "PASS", detail, TEXT_PRIMARY, CARD_ALT, TEXT_PRIMARY)
            self._log(detail, "success")
        else:
            self._set_control_state(key, "FAIL", detail, FAIL, ACCENT_RED_DEEP, FAIL)
            self._log(detail, "fail")

    def _show_results(self, score: float, tier: str, findings: dict, directory_data: dict):
        self.scanning = False
        passed_controls = sum(1 for value in findings.values() if value.get("passed"))
        directory_failures = sum(1 for key in ("privileged_groups", "stale_accounts", "disabled_accounts") if not findings.get(key, {}).get("passed", False))
        log_state = "Accessible" if findings.get("log_validation", {}).get("passed") else "Restricted"

        self._update_score_visuals(score, tier)
        self._set_status("COMPLETE", TEXT_PRIMARY, TEXT_PRIMARY)
        self.metric_labels["controls_passed"].configure(text=f"{passed_controls} / 4")
        self.metric_labels["directory_state"].configure(text=f"{directory_failures} finding groups")
        self.metric_labels["log_state"].configure(text=log_state)
        self.run_btn.configure(state="normal", text="Run Again", bg=ACCENT_RED)
        self.report_btn.configure(state="normal", fg=TEXT_PRIMARY)
        self.timestamp_label.configure(text=f"Last scan: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        self._populate_directory_tree(directory_data)
        self.directory_summary_label.configure(text=f"Loaded {directory_data['user_count']} users across {directory_data['department_count']} departments for {self.active_config['selected_company']['name']}.")
        self._log(f"Assessment complete. Score {score:.1f}/100, level {tier}.", "success")
        self._log(f"JSON report written to {self.report_path}", "muted")

    def _populate_directory_tree(self, directory_data: dict):
        for item in self.directory_tree.get_children():
            self.directory_tree.delete(item)
        for department in directory_data["departments"]:
            dept_id = self.directory_tree.insert("", "end", text=department["name"], values=("Department", department["user_count"], "Organizational grouping", ""), open=True)
            for user in department["users"]:
                status = "Enabled" if user["enabled"] else "Disabled"
                detail = user["title"] or user["email"] or user["distinguished_name"]
                self.directory_tree.insert(dept_id, "end", text=user["name"], values=("User", user["username"], detail, status))

    def _handle_error(self, exc: Exception):
        self.scanning = False
        self._set_status("ERROR", FAIL, FAIL)
        self.run_btn.configure(state="normal", text="Retry Assessment", bg=ACCENT_RED)
        for key in self.control_widgets:
            self._set_control_state(key, "ERROR", "Assessment aborted before completion", FAIL, ACCENT_RED_DEEP, FAIL)
        self.metric_labels["controls_passed"].configure(text="Error")
        self.metric_labels["directory_state"].configure(text="Error")
        self.metric_labels["log_state"].configure(text="Error")
        self._log(f"ERROR: {exc}", "fail")

    def _view_report(self):
        try:
            with self.report_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)

            win = tk.Toplevel(self.root)
            win.title("SOCProbe Report")
            win.geometry("900x660")
            win.configure(bg=APP_BG)

            shell = tk.Frame(win, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
            shell.pack(fill="both", expand=True, padx=18, pady=18)
            tk.Frame(shell, bg=ACCENT_RED, height=3).pack(fill="x")

            head = tk.Frame(shell, bg=PANEL_BG)
            head.pack(fill="x", padx=18, pady=16)
            tk.Label(head, text=f"Assessment Report | {data.get('organization', '')}", bg=PANEL_BG, fg=TEXT_PRIMARY, font=self.font_h2).pack(side="left")
            tk.Label(head, text=f"{data.get('soc_readiness_score', 0)}/100  |  {data.get('risk_level', '')}", bg=PANEL_BG, fg=score_color(float(data.get('soc_readiness_score', 0))), font=self.font_h3).pack(side="right")

            text_wrap = tk.Frame(shell, bg=CARD_BG, highlightbackground=BORDER, highlightthickness=1)
            text_wrap.pack(fill="both", expand=True, padx=18, pady=(0, 18))
            text = tk.Text(text_wrap, bg=CARD_BG, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY, relief="flat", wrap="none", font=self.font_mono, padx=14, pady=14)
            text.pack(side="left", fill="both", expand=True)
            y_scroll = tk.Scrollbar(text_wrap, command=text.yview)
            y_scroll.pack(side="right", fill="y")
            text.configure(yscrollcommand=y_scroll.set)
            text.insert("end", json.dumps(data, indent=4, default=str))
            text.configure(state="disabled")
        except Exception as exc:
            self._log(f"Could not open report: {exc}", "fail")


def launch_app():
    root = tk.Tk()
    SOCProbeApp(root)
    root.mainloop()


if __name__ == "__main__":
    launch_app()
