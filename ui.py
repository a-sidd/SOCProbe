if __name__ == "__main__":
    from socprobe_local_ui import launch_app
    launch_app()
    raise SystemExit

# ============================================================
# SOCProbe v1.0 — UI
# Dark cybersecurity terminal aesthetic
# Tkinter-based local desktop app
# ============================================================

import tkinter as tk
from tkinter import font as tkfont
import threading
import json
import sys
import os
import datetime

from modules.ad_connector import connect_to_ad
from modules.analysis_engine import run_assessment
from modules.config_loader import load_config
from modules.report_generator import generate_report
from modules.scoring_engine import CONTROL_WEIGHTS, calculate_score

# Add modules path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── COLORS ───────────────────────────────────────────────────
BG_DARK     = "#050D1A"
BG_CARD     = "#0A1628"
BG_SURFACE  = "#0D1F38"
ACCENT      = "#00D4FF"
ACCENT_DIM  = "#0A4A5A"
GREEN       = "#00FF88"
GREEN_DIM   = "#004422"
RED         = "#FF4455"
RED_DIM     = "#3A0A0F"
AMBER       = "#FFB020"
AMBER_DIM   = "#3A2800"
PURPLE      = "#9966FF"
WHITE       = "#E8F4FF"
MUTED       = "#4A6A8A"
BORDER      = "#0D2A44"

# ── SCORE COLORS ─────────────────────────────────────────────
def score_color(score):
    if score >= 80: return GREEN
    if score >= 60: return ACCENT
    if score >= 40: return AMBER
    return RED

def tier_color(tier):
    colors = {"HIGH": GREEN, "MODERATE": ACCENT, "LOW": AMBER, "POOR": RED}
    return colors.get(tier, WHITE)

def tier_bg(tier):
    colors = {"HIGH": GREEN_DIM, "MODERATE": ACCENT_DIM, "LOW": AMBER_DIM, "POOR": RED_DIM}
    return colors.get(tier, BG_CARD)

# ── MAIN APP ──────────────────────────────────────────────────
class SOCProbeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SOCProbe v1.0")
        self.root.geometry("900x700")
        self.root.minsize(860, 660)
        self.root.configure(bg=BG_DARK)
        self.root.resizable(True, True)

        # Fonts
        self.font_title   = tkfont.Font(family="Consolas", size=22, weight="bold")
        self.font_sub     = tkfont.Font(family="Consolas", size=9)
        self.font_label   = tkfont.Font(family="Consolas", size=10)
        self.font_mono    = tkfont.Font(family="Consolas", size=9)
        self.font_score   = tkfont.Font(family="Consolas", size=52, weight="bold")
        self.font_tier    = tkfont.Font(family="Consolas", size=14, weight="bold")
        self.font_btn     = tkfont.Font(family="Consolas", size=11, weight="bold")
        self.font_control = tkfont.Font(family="Consolas", size=9, weight="bold")
        self.font_small   = tkfont.Font(family="Consolas", size=8)

        self.scanning = False
        self.scan_done = False
        self.config_data = load_config()

        self._build_ui()
        self._animate_header()

    # ── BUILD UI ──────────────────────────────────────────────
    def _build_ui(self):
        # ── HEADER ────────────────────────────────────────────
        self.header = tk.Frame(self.root, bg=BG_CARD, height=80)
        self.header.pack(fill="x", padx=0, pady=0)
        self.header.pack_propagate(False)

        # Accent top line
        tk.Frame(self.root, bg=ACCENT, height=2).pack(fill="x")

        header_inner = tk.Frame(self.header, bg=BG_CARD)
        header_inner.pack(fill="both", expand=True, padx=24, pady=12)

        left = tk.Frame(header_inner, bg=BG_CARD)
        left.pack(side="left")

        self.title_label = tk.Label(left, text="SOCProbe", font=self.font_title,
                                    bg=BG_CARD, fg=ACCENT)
        self.title_label.pack(anchor="w")

        tk.Label(left, text="Local SOC Assessment Tool  ·  Sheridan College Capstone",
                 font=self.font_sub, bg=BG_CARD, fg=MUTED).pack(anchor="w")

        right = tk.Frame(header_inner, bg=BG_CARD)
        right.pack(side="right", anchor="e")

        # Status pill
        self.status_frame = tk.Frame(right, bg=ACCENT_DIM,
                                     highlightbackground=ACCENT,
                                     highlightthickness=1)
        self.status_frame.pack(anchor="e", pady=4)

        self.status_dot = tk.Label(self.status_frame, text="●",
                                   font=self.font_small, bg=ACCENT_DIM, fg=ACCENT)
        self.status_dot.pack(side="left", padx=(8,2), pady=4)

        self.status_label = tk.Label(self.status_frame, text="READY",
                                     font=self.font_control, bg=ACCENT_DIM, fg=ACCENT)
        self.status_label.pack(side="left", padx=(0,10), pady=4)

        # Domain info
        tk.Label(right, text="soclab.local  ·  127.0.0.1",
                 font=self.font_small, bg=BG_CARD, fg=MUTED).pack(anchor="e", pady=2)

        # ── MAIN CONTENT ──────────────────────────────────────
        content = tk.Frame(self.root, bg=BG_DARK)
        content.pack(fill="both", expand=True, padx=16, pady=12)

        # LEFT PANEL
        left_panel = tk.Frame(content, bg=BG_DARK)
        left_panel.pack(side="left", fill="both", expand=True, padx=(0,8))

        # Score card
        self.score_card = tk.Frame(left_panel, bg=BG_CARD,
                                   highlightbackground=BORDER,
                                   highlightthickness=1)
        self.score_card.pack(fill="x", pady=(0,8))

        score_inner = tk.Frame(self.score_card, bg=BG_CARD)
        score_inner.pack(padx=20, pady=16)

        tk.Label(score_inner, text="SOC READINESS SCORE",
                 font=self.font_control, bg=BG_CARD, fg=MUTED).pack()

        self.score_display = tk.Label(score_inner, text="--",
                                      font=self.font_score,
                                      bg=BG_CARD, fg=MUTED)
        self.score_display.pack()

        self.score_bar_frame = tk.Frame(score_inner, bg=BG_SURFACE, height=6)
        self.score_bar_frame.pack(fill="x", pady=4)
        self.score_bar_frame.pack_propagate(False)

        self.score_bar = tk.Frame(self.score_bar_frame, bg=MUTED, height=6, width=0)
        self.score_bar.place(x=0, y=0, height=6)

        self.tier_label = tk.Label(score_inner, text="AWAITING SCAN",
                                   font=self.font_tier,
                                   bg=BG_CARD, fg=MUTED)
        self.tier_label.pack(pady=4)

        # Controls grid
        controls_title = tk.Frame(left_panel, bg=BG_DARK)
        controls_title.pack(fill="x", pady=(4,6))
        tk.Label(controls_title, text="SECURITY CONTROLS",
                 font=self.font_control, bg=BG_DARK, fg=MUTED).pack(side="left")

        self.controls_frame = tk.Frame(left_panel, bg=BG_DARK)
        self.controls_frame.pack(fill="x")

        self.control_widgets = {}
        controls = [
            ("privileged_groups",  "Privileged Group Analysis",  "Domain Admins · Schema Admins · Administrators", 25),
            ("stale_accounts",     "Stale Account Detection",     "Inactive accounts > 90 days",                    20),
            ("disabled_accounts",  "Disabled Account Check",      "Disabled users in privileged groups",            10),
            ("log_validation",     "Event Log Validation",        "Security log accessibility",                     20),
        ]

        for key, title, desc, weight in controls:
            card = tk.Frame(self.controls_frame, bg=BG_CARD,
                            highlightbackground=BORDER,
                            highlightthickness=1)
            card.pack(fill="x", pady=3)

            inner = tk.Frame(card, bg=BG_CARD)
            inner.pack(fill="x", padx=14, pady=10)

            left_c = tk.Frame(inner, bg=BG_CARD)
            left_c.pack(side="left", fill="x", expand=True)

            tk.Label(left_c, text=title, font=self.font_label,
                     bg=BG_CARD, fg=WHITE).pack(anchor="w")
            tk.Label(left_c, text=desc, font=self.font_small,
                     bg=BG_CARD, fg=MUTED).pack(anchor="w")

            right_c = tk.Frame(inner, bg=BG_CARD)
            right_c.pack(side="right")

            # Weight badge
            weight_lbl = tk.Label(right_c,
                                  text=f"W:{weight}",
                                  font=self.font_small,
                                  bg=ACCENT_DIM, fg=ACCENT,
                                  padx=6, pady=2)
            weight_lbl.pack(side="right", padx=(6,0))

            # Status badge
            status_lbl = tk.Label(right_c, text="PENDING",
                                  font=self.font_control,
                                  bg=BG_SURFACE, fg=MUTED,
                                  padx=8, pady=3)
            status_lbl.pack(side="right")

            self.control_widgets[key] = status_lbl

        # ── RIGHT PANEL ───────────────────────────────────────
        right_panel = tk.Frame(content, bg=BG_DARK, width=280)
        right_panel.pack(side="right", fill="y", padx=(8,0))
        right_panel.pack_propagate(False)

        # Run button
        self.run_btn = tk.Button(
            right_panel,
            text="▶  RUN ASSESSMENT",
            font=self.font_btn,
            bg=ACCENT, fg=BG_DARK,
            activebackground=GREEN,
            activeforeground=BG_DARK,
            relief="flat", cursor="hand2",
            pady=14,
            command=self._run_scan
        )
        self.run_btn.pack(fill="x", pady=(0,8))

        # View report button
        self.report_btn = tk.Button(
            right_panel,
            text="📄  VIEW REPORT",
            font=self.font_btn,
            bg=BG_CARD, fg=MUTED,
            activebackground=BG_SURFACE,
            activeforeground=WHITE,
            relief="flat", cursor="hand2",
            pady=10,
            state="disabled",
            command=self._view_report
        )
        self.report_btn.pack(fill="x", pady=(0,12))

        # Terminal log
        log_header = tk.Frame(right_panel, bg=BG_DARK)
        log_header.pack(fill="x", pady=(0,4))
        tk.Label(log_header, text="TERMINAL OUTPUT",
                 font=self.font_control, bg=BG_DARK, fg=MUTED).pack(side="left")

        log_frame = tk.Frame(right_panel, bg=BG_CARD,
                             highlightbackground=BORDER,
                             highlightthickness=1)
        log_frame.pack(fill="both", expand=True)

        self.log_text = tk.Text(
            log_frame,
            bg=BG_CARD, fg=ACCENT,
            font=self.font_mono,
            relief="flat",
            padx=10, pady=8,
            wrap="word",
            state="disabled",
            insertbackground=ACCENT,
            selectbackground=ACCENT_DIM
        )
        self.log_text.pack(fill="both", expand=True)

        scrollbar = tk.Scrollbar(log_frame, command=self.log_text.yview,
                                 bg=BG_SURFACE, troughcolor=BG_CARD,
                                 width=8)
        scrollbar.pack(side="right", fill="y")
        self.log_text.config(yscrollcommand=scrollbar.set)

        # Tag colors for log
        self.log_text.tag_config("success", foreground=GREEN)
        self.log_text.tag_config("fail",    foreground=RED)
        self.log_text.tag_config("info",    foreground=ACCENT)
        self.log_text.tag_config("warn",    foreground=AMBER)
        self.log_text.tag_config("muted",   foreground=MUTED)
        self.log_text.tag_config("white",   foreground=WHITE)

        # ── FOOTER ────────────────────────────────────────────
        footer = tk.Frame(self.root, bg=BG_CARD, height=28)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)

        tk.Label(footer,
                 text="SOCProbe v1.0  ·  INFO36206 Capstone  ·  Sheridan College  ·  Syed Ahmed · Ahsan Siddiq · Vaqas Mirza",
                 font=self.font_small, bg=BG_CARD, fg=MUTED).pack(side="left", padx=16, pady=6)

        self.timestamp_label = tk.Label(footer, text="",
                                        font=self.font_small,
                                        bg=BG_CARD, fg=MUTED)
        self.timestamp_label.pack(side="right", padx=16, pady=6)

        # Initial log
        self._log("SOCProbe v1.0 initialized", "info")
        self._log("Domain : soclab.local", "muted")
        self._log("Server : 127.0.0.1:389", "muted")
        self._log("Press RUN ASSESSMENT to begin", "muted")
        self._log("─" * 32, "muted")

    # ── ANIMATION ─────────────────────────────────────────────
    def _animate_header(self):
        colors = [ACCENT, "#00B8E0", "#0099C0", "#00B8E0", ACCENT]
        self._header_frame = 0

        def cycle():
            c = colors[self._header_frame % len(colors)]
            self.title_label.config(fg=c)
            self._header_frame += 1
            self.root.after(800, cycle)

        cycle()

    def _pulse_status(self):
        colors = [ACCENT, AMBER]
        self._pulse_frame = 0

        def pulse():
            if not self.scanning:
                return
            c = colors[self._pulse_frame % 2]
            self.status_dot.config(fg=c)
            self._pulse_frame += 1
            self.root.after(500, pulse)

        pulse()

    # ── LOGGING ───────────────────────────────────────────────
    def _log(self, message, tag="info"):
        self.log_text.config(state="normal")
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{ts}] {message}\n", tag)
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    # ── RUN SCAN ──────────────────────────────────────────────
    def _run_scan(self):
        if self.scanning:
            return
        self.scanning = True
        self.scan_done = False

        # Reset UI
        self.run_btn.config(state="disabled", bg=ACCENT_DIM, fg=MUTED,
                            text="◉  SCANNING...")
        self.report_btn.config(state="disabled")
        self.score_display.config(text="--", fg=MUTED)
        self.tier_label.config(text="SCANNING...", fg=AMBER, bg=BG_CARD)
        self.score_bar.config(width=0, bg=MUTED)

        for key, widget in self.control_widgets.items():
            widget.config(text="RUNNING", bg=AMBER_DIM, fg=AMBER)

        self._set_status("SCANNING", AMBER)
        self._pulse_status()

        self._log("─" * 32, "muted")
        self._log("Starting SOC assessment...", "info")

        # Run in background thread
        thread = threading.Thread(target=self._run_assessment, daemon=True)
        thread.start()

    def _run_assessment(self):
        try:
            config = self.config_data

            self._log("Config loaded", "success")

            self._log("Connecting to Active Directory...", "info")
            conn = connect_to_ad(config)
            self._log("Connected to soclab.local", "success")

            self._log("Running assessment modules...", "info")
            findings = run_assessment(conn, config)

            for key in ("privileged_groups", "stale_accounts", "disabled_accounts", "log_validation"):
                self._update_control(key, findings[key]["passed"], findings[key]["finding"])

            score, tier = calculate_score(findings)

            generate_report(findings, score, tier, config)

            self.root.after(0, lambda: self._show_results(score, tier, findings))

        except Exception as e:
            self._log(f"ERROR: {str(e)}", "fail")
            self.root.after(0, self._reset_after_error)

    def _update_control(self, key, passed, finding):
        def update():
            widget = self.control_widgets[key]
            if passed:
                widget.config(text="PASS", bg=GREEN_DIM, fg=GREEN)
                self._log(f"✓ {finding}", "success")
            else:
                widget.config(text="FAIL", bg=RED_DIM, fg=RED)
                self._log(f"✗ {finding}", "fail")
        self.root.after(0, update)

    def _show_results(self, score, tier, findings):
        self.scanning = False
        self.scan_done = True

        col = score_color(score)
        tc  = tier_color(tier)
        tbg = tier_bg(tier)

        # Score
        self.score_display.config(text=str(int(score)), fg=col)

        # Bar
        bar_width = int((score / 100) * self.score_bar_frame.winfo_width())
        self.score_bar.config(width=bar_width, bg=col)
        self.score_bar.place(x=0, y=0, width=bar_width, height=6)

        # Tier
        self.tier_label.config(text=tier, fg=tc, bg=tbg)

        # Status
        self._set_status("COMPLETE", GREEN)
        self.status_dot.config(fg=GREEN)

        # Timestamp
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.timestamp_label.config(text=f"Last scan: {ts}")

        # Log summary
        passed_count = sum(1 for f in findings.values() if f.get("passed"))
        self._log("─" * 32, "muted")
        self._log(f"Assessment complete", "success")
        self._log(f"Score    : {score}/100", "white")
        self._log(f"Level    : {tier}", "white")
        self._log(f"Passed   : {passed_count}/4 controls", "white")
        self._log("Report saved to reports/", "success")
        self._log("─" * 32, "muted")

        # Re-enable buttons
        self.run_btn.config(state="normal", bg=ACCENT, fg=BG_DARK,
                            text="▶  RUN ASSESSMENT")
        self.report_btn.config(state="normal", bg=BG_SURFACE, fg=WHITE)

    def _reset_after_error(self):
        self.scanning = False
        self._set_status("ERROR", RED)
        self.run_btn.config(state="normal", bg=ACCENT, fg=BG_DARK,
                            text="▶  RUN ASSESSMENT")
        for widget in self.control_widgets.values():
            widget.config(text="ERROR", bg=RED_DIM, fg=RED)

    def _set_status(self, text, color):
        self.status_label.config(text=text, fg=color)
        self.status_frame.config(highlightbackground=color,
                                 bg=BG_CARD if color == GREEN else ACCENT_DIM)
        self.status_dot.config(bg=BG_CARD if color == GREEN else ACCENT_DIM,
                               fg=color)
        self.status_label.config(bg=BG_CARD if color == GREEN else ACCENT_DIM)

    # ── VIEW REPORT ───────────────────────────────────────────
    def _view_report(self):
        try:
            path = self.config_data["output"]["report_path"]
            with open(path) as f:
                data = json.load(f)

            # New window
            win = tk.Toplevel(self.root)
            win.title("SOCProbe — Full Report")
            win.geometry("720x580")
            win.configure(bg=BG_DARK)

            tk.Frame(win, bg=ACCENT, height=2).pack(fill="x")

            header = tk.Frame(win, bg=BG_CARD)
            header.pack(fill="x")
            tk.Label(header, text="FULL ASSESSMENT REPORT",
                     font=self.font_tier, bg=BG_CARD, fg=ACCENT,
                     padx=20, pady=12).pack(side="left")

            score = data.get("soc_readiness_score", 0)
            tier  = data.get("risk_level", "")
            tk.Label(header,
                     text=f"{score}/100  ·  {tier}",
                     font=self.font_tier,
                     bg=BG_CARD, fg=score_color(score),
                     padx=20, pady=12).pack(side="right")

            text = tk.Text(win, bg=BG_CARD, fg=WHITE,
                           font=self.font_mono,
                           relief="flat", padx=16, pady=12)
            text.pack(fill="both", expand=True, padx=8, pady=8)

            text.insert("end", json.dumps(data, indent=4, default=str))
            text.config(state="disabled")

        except Exception as e:
            self._log(f"Could not open report: {e}", "fail")


# ── LAUNCH ────────────────────────────────────────────────────
if __name__ == "__main__":
    root = tk.Tk()
    app = SOCProbeApp(root)
    root.mainloop()
