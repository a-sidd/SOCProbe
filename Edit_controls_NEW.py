
import tkinter as tk
from tkinter import ttk, messagebox
import webbrowser
import os
import math
import shutil
import threading
from datetime import datetime

from assessment.engine import run_real_assessment, run_demo_assessment
from reports.report_generator import save_reports, REPORT_JSON, REPORT_HTML
from database.repository import initialize_database, get_active_profile
from framework.saf_controls import SAF_CONTROLS
from ui.profile_manager import ProfileManager
from ui.control_library import ControlLibraryManager

APP_VERSION = "SOCProbe Enterprise v4.2 - Responsive Assessment Console"

# ---------------- Theme ----------------
BG = "#07111F"
SIDEBAR = "#0B1728"
SURFACE = "#0E1A2B"
SURFACE_2 = "#122238"
SURFACE_3 = "#18283D"
BORDER = "#24364D"
TEXT = "#F8FAFC"
TEXT_2 = "#D5DEEA"
MUTED = "#91A2B8"
CYAN = "#2EC5FF"
BLUE = "#2563EB"
BLUE_2 = "#1D4ED8"
GREEN = "#22C55E"
YELLOW = "#FACC15"
ORANGE = "#F97316"
RED = "#EF4444"
PURPLE = "#7C3AED"
DARK_RED = "#5B1116"
DARK_GREEN = "#07351F"

current_report = None
current_domain_filter = "All"
domain_buttons = {}


def score_color(score):
    if score is None:
        return MUTED
    if score >= 90:
        return GREEN
    if score >= 80:
        return "#A3E635"
    if score >= 70:
        return YELLOW
    if score >= 60:
        return ORANGE
    return RED


def readable_mode(mode):
    labels = {
        "real_assessment": "Real Assessment",
        "real_windows_ad_entra_assessment": "Real Assessment",
        "real_configurable_assessment": "Real Assessment",
        "demo_balanced": "Balanced Demo",
        "demo_excellent": "Excellent Demo",
        "demo_logging_gap": "Logging Gap Demo",
        "demo_identity_risk": "Identity Risk Demo",
        "demo_cloud_gap": "Cloud Gap Demo",
        "demo_critical": "Critical Demo",
    }
    return labels.get(mode, str(mode).replace("_", " ").title())



def draw_badge_icon(canvas, x, y, icon_type, color):
    canvas.create_oval(x-18, y-18, x+18, y+18, fill="#0B2A48", outline=color, width=2)
    if icon_type == "shield":
        canvas.create_polygon(
            x, y-11, x+9, y-6, x+7, y+7, x, y+12, x-7, y+7, x-9, y-6,
            fill="", outline=color, width=2
        )
        canvas.create_line(x-4, y, x-1, y+4, x+6, y-5, fill=color, width=2)
    elif icon_type == "medal":
        canvas.create_oval(x-7, y-10, x+7, y+4, outline=color, width=2)
        canvas.create_polygon(x-5, y+3, x-1, y+13, x+2, y+5, fill=color, outline=color)
        canvas.create_polygon(x+5, y+3, x+1, y+13, x-2, y+5, fill=color, outline=color)
    elif icon_type == "warning":
        canvas.create_polygon(x, y-12, x+12, y+10, x-12, y+10, outline=color, fill="", width=2)
        canvas.create_line(x, y-5, x, y+3, fill=color, width=2)
        canvas.create_oval(x-1, y+6, x+1, y+8, fill=color, outline=color)
    elif icon_type == "check":
        canvas.create_oval(x-10, y-10, x+10, y+10, outline=color, width=2)
        canvas.create_line(x-5, y, x-1, y+4, x+6, y-5, fill=color, width=2)
    elif icon_type == "cross":
        canvas.create_oval(x-10, y-10, x+10, y+10, outline=color, width=2)
        canvas.create_line(x-5, y-5, x+5, y+5, fill=color, width=2)
        canvas.create_line(x+5, y-5, x-5, y+5, fill=color, width=2)


def draw_workflow_icon(canvas, x, y, kind):
    color = TEXT
    if kind == "database":
        canvas.create_oval(x-10, y-8, x+10, y-2, outline=color, width=2)
        canvas.create_line(x-10, y-5, x-10, y+9, fill=color, width=2)
        canvas.create_line(x+10, y-5, x+10, y+9, fill=color, width=2)
        canvas.create_arc(x-10, y+3, x+10, y+10, start=180, extent=180, outline=color, width=2)
        canvas.create_arc(x-10, y-2, x+10, y+5, start=180, extent=180, outline=color, width=2)
    elif kind == "clipboard":
        canvas.create_rectangle(x-9, y-11, x+9, y+12, outline=color, width=2)
        canvas.create_rectangle(x-4, y-14, x+4, y-9, outline=color, width=2)
        canvas.create_line(x-5, y-3, x+5, y-3, fill=color, width=2)
        canvas.create_line(x-5, y+3, x+5, y+3, fill=color, width=2)
        canvas.create_line(x-5, y+9, x+2, y+9, fill=color, width=2)
    elif kind == "bars":
        canvas.create_rectangle(x-10, y+2, x-6, y+12, fill=color, outline=color)
        canvas.create_rectangle(x-2, y-4, x+2, y+12, fill=color, outline=color)
        canvas.create_rectangle(x+6, y-10, x+10, y+12, fill=color, outline=color)
    elif kind == "report":
        canvas.create_rectangle(x-10, y-10, x+10, y+10, outline=color, width=2)
        canvas.create_line(x-5, y+3, x, y+8, x+7, y-5, fill=color, width=2)


def draw_card_icon(canvas, kind, color):
    canvas.delete("all")
    draw_badge_icon(canvas, 24, 24, kind, color)

def draw_gauge(score=0):
    gauge.delete("all")

    width = max(gauge.winfo_width(), 380)
    height = max(gauge.winfo_height(), 220)
    cx = width / 2
    cy = height * 0.72
    radius = min(width * 0.34, height * 0.48)

    gauge.create_text(
        16, 15,
        text="ASSESSMENT SCORE",
        fill=TEXT,
        font=("Segoe UI", 11, "bold"),
        anchor="nw",
    )

    for start, extent, color in [
        (180, -45, RED),
        (135, -45, ORANGE),
        (90, -45, YELLOW),
        (45, -45, GREEN),
    ]:
        gauge.create_arc(
            cx - radius,
            cy - radius,
            cx + radius,
            cy + radius,
            start=start,
            extent=extent,
            width=22,
            style="arc",
            outline=color,
        )

    angle = 180 - (score / 100) * 180
    radians = math.radians(angle)
    needle_length = radius - 28

    x = cx + needle_length * math.cos(radians)
    y = cy - needle_length * math.sin(radians)

    gauge.create_line(cx, cy, x, y, fill=TEXT, width=4)
    gauge.create_oval(cx - 7, cy - 7, cx + 7, cy + 7, fill=TEXT, outline="")

    gauge.create_text(
        cx,
        cy - radius * 0.34,
        text=str(score),
        fill=score_color(score),
        font=("Segoe UI", 30, "bold"),
    )
    gauge.create_text(
        cx,
        cy - radius * 0.08,
        text="/ 100",
        fill=MUTED,
        font=("Segoe UI", 14),
    )

    legend_y = height - 20
    legend = [
        ("0–49 Critical", RED),
        ("50–69 High Risk", ORANGE),
        ("70–89 Needs Improvement", YELLOW),
        ("90–100 Excellent", GREEN),
    ]
    segment = width / 4

    for index, (label, color) in enumerate(legend):
        x_pos = 10 + segment * index
        gauge.create_rectangle(
            x_pos,
            legend_y - 7,
            x_pos + 8,
            legend_y + 1,
            fill=color,
            outline="",
        )
        gauge.create_text(
            x_pos + 13,
            legend_y - 3,
            text=label,
            fill=MUTED,
            font=("Segoe UI", 6),
            anchor="w",
        )


def draw_domain_bars(report):
    domain_canvas.delete("all")

    width = max(domain_canvas.winfo_width(), 420)
    bar_x = int(width * 0.45)
    bar_width = max(120, int(width * 0.36))

    domain_canvas.create_text(
        16,
        15,
        text="DOMAIN ASSESSMENT SCORES",
        fill=TEXT,
        font=("Segoe UI", 11, "bold"),
        anchor="nw",
    )

    y = 55

    for domain, data in report["domain_scores"].items():
        score = data.get("score")
        display_score = 0 if score is None else score

        domain_canvas.create_text(
            16,
            y + 8,
            text=domain,
            fill=TEXT_2,
            font=("Segoe UI", 8, "bold"),
            anchor="w",
            width=bar_x - 28,
        )

        domain_canvas.create_rectangle(
            bar_x,
            y,
            bar_x + bar_width,
            y + 17,
            fill="#15263A",
            outline="",
        )

        domain_canvas.create_rectangle(
            bar_x,
            y,
            bar_x + int(bar_width * display_score / 100),
            y + 17,
            fill=score_color(score),
            outline="",
        )

        domain_canvas.create_text(
            bar_x + bar_width + 12,
            y + 8,
            text="N/A" if score is None else f"{score}%",
            fill=YELLOW if score is None else score_color(score),
            font=("Segoe UI", 8, "bold"),
            anchor="w",
        )
        y += 37

    domain_canvas.create_text(
        16,
        max(y + 6, 205),
        text="Only enabled and assessed controls are included in scoring.",
        fill=MUTED,
        font=("Segoe UI", 7),
        anchor="w",
    )


def draw_methodology(report):
    method_canvas.delete("all")

    width = max(method_canvas.winfo_width(), 420)

    method_canvas.create_text(
        16,
        15,
        text="SAF ASSESSMENT WORKFLOW",
        fill=TEXT,
        font=("Segoe UI", 11, "bold"),
        anchor="nw",
    )

    steps = [
        ("1", "Collect Evidence", "Gather system\nevidence", "database"),
        ("2", "Evaluate Controls", "Apply rules and\nthresholds", "clipboard"),
        ("3", "Assess Risk", "Calculate weighted\nscores", "bars"),
        ("4", "Generate Results", "Create reports and\nrecommendations", "report"),
    ]

    available = width - 34
    spacing = available / 4
    center_y = 95

    for index, (number, title, subtitle, kind) in enumerate(steps):
        center_x = 17 + spacing * index + spacing / 2

        method_canvas.create_oval(
            center_x - 27,
            center_y - 27,
            center_x + 27,
            center_y + 27,
            fill=BLUE_2,
            outline=CYAN,
            width=2,
        )
        method_canvas.create_text(
            center_x,
            center_y - 13,
            text=number,
            fill=TEXT,
            font=("Segoe UI", 7, "bold"),
        )
        draw_workflow_icon(method_canvas, center_x, center_y + 5, kind)

        method_canvas.create_text(
            center_x,
            center_y + 48,
            text=title,
            fill=TEXT_2,
            font=("Segoe UI", 7, "bold"),
            width=max(80, spacing - 8),
        )
        method_canvas.create_text(
            center_x,
            center_y + 72,
            text=subtitle,
            fill=MUTED,
            font=("Segoe UI", 6),
            width=max(80, spacing - 8),
        )

        if index < len(steps) - 1:
            next_x = 17 + spacing * (index + 1) + spacing / 2
            method_canvas.create_line(
                center_x + 32,
                center_y,
                next_x - 32,
                center_y,
                fill=MUTED,
                width=2,
                arrow=tk.LAST,
            )

def result_text(result):
    if result["status"] == "PASS":
        return "Compliant"
    if result["status"] == "NOT ASSESSED":
        return "Not Assessed"

    evidence = result.get("evidence", "")
    if len(evidence) > 44:
        return evidence[:41].rstrip() + "..."
    return evidence or "Requires Attention"


def populate_results(report):
    for item in results_table.get_children():
        results_table.delete(item)

    visible = 0

    for result in report["results"]:
        if (
            current_domain_filter != "All"
            and result["domain"] != current_domain_filter
        ):
            continue

        visible += 1

        tag = (
            "pass"
            if result["status"] == "PASS"
            else "fail"
            if result["status"] == "FAIL"
            else "na"
        )

        results_table.insert(
            "",
            tk.END,
            values=(
                result["id"],
                result["domain"],
                result["name"],
                result["status"],
                result["risk"],
                f"{result['earned']} / {result['weight']}",
                result_text(result),
                "View",
            ),
            tags=(tag,),
        )

    visible_label.config(
        text=f"Showing {visible} of {report['total_controls']} controls"
    )


def filter_domain(domain):
    global current_domain_filter
    current_domain_filter = domain

    for name, button in domain_buttons.items():
        active = name == domain
        button.config(
            bg=BLUE if active else SIDEBAR,
            fg=TEXT if active else TEXT_2,
        )

    if current_report:
        populate_results(current_report)


def update_summary(report):
    summary_text.config(state="normal")
    summary_text.delete("1.0", tk.END)

    content = (
        f"SOCProbe performed an assessment using the "
        f"“{report['active_profile']}” methodology.\n\n"
        f"Assessment coverage: {report['assessed_controls']} of "
        f"{report['total_controls']} controls.\n\n"
        f"● {report['failed_controls']} controls failed and require attention.\n"
        f"● {report['not_assessed_controls']} controls were not assessed.\n"
        f"● {report['passed_controls']} controls passed.\n\n"
        f"Overall posture: {report['readiness'].upper()}."
    )

    summary_text.insert("1.0", content)
    summary_text.config(state="disabled")


def load_report(report):
    global current_report
    current_report = report
    save_reports(report)

    score = report["overall_score"]

    score_label.config(text=f"{score} / 100", fg=score_color(score))
    score_sub.config(
        text=(
            "Critical — Immediate Improvement Required"
            if score < 50
            else "High Risk — Significant Improvement Required"
            if score < 70
            else "Needs Improvement"
            if score < 90
            else "Excellent Security Posture"
        )
    )

    grade_label.config(
        text=f"Grade {report['grade']}",
        fg=score_color(score),
    )
    readiness_label.config(
        text=report["readiness"],
        fg=score_color(score),
    )

    passed_label.config(
        text=f"{report['passed_controls']} / {report['assessed_controls']}",
        fg=GREEN,
    )

    passed_sub.config(
        text=(
            f"{round(report['passed_controls'] / report['assessed_controls'] * 100)}% Controls Passed"
            if report["assessed_controls"]
            else "No controls assessed"
        )
    )

    failed_label.config(
        text=f"{report['failed_controls']} Failed",
        fg=RED,
    )
    failed_sub.config(
        text=f"{report['not_assessed_controls']} Not Assessed"
    )

    mode_label.config(
        text=f"Assessment Mode: {readable_mode(report['assessment_mode'])}"
    )
    profile_label.config(
        text=f"Active Methodology: {report['active_profile']}"
    )
    sidebar_profile_name.config(text=report["active_profile"])

    update_summary(report)
    draw_gauge(score)
    draw_domain_bars(report)
    draw_methodology(report)
    populate_results(report)

    activity_label.config(
        text=(
            "Assessment completed successfully on "
            + datetime.now().strftime("%b %d, %Y %I:%M %p")
        )
    )


def progress_update(current, total, message):
    percentage = int((current / total) * 100) if total else 0
    root.after(0, lambda: progress_var.set(percentage))
    root.after(0, lambda: activity_label.config(text=message))


def assessment_worker(mode, scenario=None):
    try:
        if mode == "real":
            report = run_real_assessment(
                progress_callback=progress_update
            )
        else:
            report = run_demo_assessment(
                scenario,
                progress_callback=progress_update,
            )

        root.after(0, lambda: load_report(report))

    except Exception as exc:
        root.after(
            0,
            lambda: messagebox.showerror(
                "Assessment Error",
                str(exc),
            ),
        )
        root.after(
            0,
            lambda: activity_label.config(
                text="Assessment failed."
            ),
        )

    finally:
        root.after(0, lambda: progress_var.set(0))


def run_real():
    mode_label.config(text="Assessment Mode: Real Assessment")
    threading.Thread(
        target=assessment_worker,
        args=("real",),
        daemon=True,
    ).start()


def run_demo(scenario):
    mode_label.config(
        text=f"Assessment Mode: {readable_mode('demo_' + scenario)}"
    )
    threading.Thread(
        target=assessment_worker,
        args=("demo", scenario),
        daemon=True,
    ).start()


def open_json():
    if os.path.exists(REPORT_JSON):
        os.startfile(REPORT_JSON)
    else:
        messagebox.showinfo(
            "No Report",
            "Run an assessment first.",
        )


def open_html():
    if os.path.exists(REPORT_HTML):
        webbrowser.open(REPORT_HTML)
    else:
        messagebox.showinfo(
            "No Report",
            "Run an assessment first.",
        )


def update_profile_label():
    try:
        profile = get_active_profile()
        profile_label.config(
            text=f"Active Methodology: {profile['profile_name']}"
        )
        sidebar_profile_name.config(
            text=profile["profile_name"]
        )
    except Exception as exc:
        profile_label.config(
            text=f"Methodology Error: {exc}"
        )


def open_methodology_settings():
    ProfileManager(
        root,
        on_change=update_profile_label,
    )


def open_control_library():
    ControlLibraryManager(
        root,
        on_change=update_profile_label,
    )


def open_entra_config():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    target = os.path.join(base_dir, "entra_config.json")
    example = os.path.join(base_dir, "entra_config.example.json")

    if not os.path.exists(target) and os.path.exists(example):
        shutil.copyfile(example, target)

    if os.path.exists(target):
        os.startfile(target)
    else:
        messagebox.showerror(
            "Missing File",
            "entra_config.example.json was not found.",
        )


def on_result_click(event):
    selected = results_table.focus()

    if not selected or not current_report:
        return

    values = results_table.item(selected, "values")
    if not values:
        return

    control = next(
        (
            item
            for item in current_report["results"]
            if item["id"] == values[0]
        ),
        None,
    )

    if not control:
        return

    detail = (
        f"Control ID: {control['id']}\n"
        f"Domain: {control['domain']}\n"
        f"Control: {control['name']}\n"
        f"Status: {control['status']}\n"
        f"Risk: {control['risk']}\n"
        f"Score: {control['earned']} / {control['weight']}\n\n"
        f"Objective:\n{control['objective']}\n\n"
        f"Evidence:\n{control['evidence']}\n\n"
        f"Recommendation:\n{control['recommendation']}"
    )

    messagebox.showinfo(
        "Control Assessment Details",
        detail,
    )


# ---------------- Root and styles ----------------
root = tk.Tk()
root.title(APP_VERSION)
root.geometry("1680x960")
root.minsize(1280, 760)
root.configure(bg=BG)

style = ttk.Style()
style.theme_use("default")

style.configure(
    "Treeview",
    background=SURFACE,
    foreground=TEXT_2,
    fieldbackground=SURFACE,
    rowheight=34,
    borderwidth=0,
    font=("Segoe UI", 8),
)

style.configure(
    "Treeview.Heading",
    background="#102038",
    foreground=TEXT,
    font=("Segoe UI", 8, "bold"),
    padding=8,
)

style.map(
    "Treeview",
    background=[("selected", BLUE_2)],
)

style.configure(
    "Horizontal.TProgressbar",
    troughcolor=SURFACE_3,
    background=GREEN,
    bordercolor=SURFACE_3,
    lightcolor=GREEN,
    darkcolor=GREEN,
)

shell = tk.Frame(root, bg=BG)
shell.pack(fill="both", expand=True)

shell.grid_columnconfigure(1, weight=1)
shell.grid_rowconfigure(0, weight=1)

# ---------------- Sidebar ----------------
sidebar = tk.Frame(
    shell,
    bg=SIDEBAR,
    width=245,
)
sidebar.grid(
    row=0,
    column=0,
    sticky="nsew",
)
sidebar.grid_propagate(False)

brand = tk.Frame(sidebar, bg=SIDEBAR)
brand.pack(
    fill="x",
    padx=16,
    pady=(18, 10),
)

tk.Label(
    brand,
    text="SOCProbe",
    bg=SIDEBAR,
    fg=TEXT,
    font=("Segoe UI", 23, "bold"),
).pack(anchor="w")

tk.Label(
    brand,
    text="SAF ASSESSMENT CONSOLE",
    bg=SIDEBAR,
    fg=CYAN,
    font=("Segoe UI", 8, "bold"),
).pack(anchor="w")

tk.Label(
    brand,
    text="Enterprise v4.2",
    bg=SIDEBAR,
    fg=MUTED,
    font=("Segoe UI", 7),
).pack(anchor="w", pady=(3, 0))

tk.Frame(
    sidebar,
    bg=BORDER,
    height=1,
).pack(
    fill="x",
    padx=14,
    pady=10,
)

tk.Button(
    sidebar,
    text="Dashboard",
    bg=BLUE,
    fg=TEXT,
    bd=0,
    activebackground=BLUE_2,
    activeforeground=TEXT,
    anchor="w",
    padx=17,
    pady=10,
    font=("Segoe UI", 9, "bold"),
).pack(
    fill="x",
    padx=10,
    pady=(0, 10),
)

tk.Label(
    sidebar,
    text="ASSESSMENT DOMAINS",
    bg=SIDEBAR,
    fg=MUTED,
    font=("Segoe UI", 7, "bold"),
).pack(
    anchor="w",
    padx=16,
    pady=(2, 4),
)

domains = [
    "All",
    "Local Windows Security",
    "Active Directory Readiness",
    "Active Directory Security",
    "Microsoft Entra Security",
]

for domain in domains:
    label = "All Controls" if domain == "All" else domain

    button = tk.Button(
        sidebar,
        text=label,
        command=lambda value=domain: filter_domain(value),
        bg=SIDEBAR,
        fg=TEXT_2,
        bd=0,
        activebackground=SURFACE_3,
        activeforeground=TEXT,
        anchor="w",
        padx=17,
        pady=7,
        font=("Segoe UI", 8, "bold"),
    )

    button.pack(
        fill="x",
        padx=7,
        pady=1,
    )

    domain_buttons[domain] = button

tk.Frame(
    sidebar,
    bg=BORDER,
    height=1,
).pack(
    fill="x",
    padx=14,
    pady=12,
)

tk.Label(
    sidebar,
    text="CONFIGURATION",
    bg=SIDEBAR,
    fg=MUTED,
    font=("Segoe UI", 7, "bold"),
).pack(
    anchor="w",
    padx=16,
    pady=(0, 4),
)

tk.Frame(
    sidebar,
    bg=BORDER,
    height=1,
).pack(
    fill="x",
    padx=14,
    pady=12,
)

tk.Label(
    sidebar,
    text="ASSESSMENT MODES",
    bg=SIDEBAR,
    fg=MUTED,
    font=("Segoe UI", 7, "bold"),
).pack(
    anchor="w",
    padx=16,
    pady=(0, 4),
)

for text, command in [
    ("Run Real Assessment", run_real),
    ("Run Balanced Demo", lambda: run_demo("balanced")),
    ("Assessment History", open_json),
]:
    tk.Button(
        sidebar,
        text=text,
        command=command,
        bg=SIDEBAR,
        fg=TEXT_2,
        bd=0,
        activebackground=SURFACE_3,
        activeforeground=TEXT,
        anchor="w",
        padx=17,
        pady=7,
        font=("Segoe UI", 8, "bold"),
    ).pack(
        fill="x",
        padx=7,
        pady=1,
    )

for text, command in [
    ("Control Library", open_control_library),
    ("Profile Manager", open_methodology_settings),
    ("Entra Configuration", open_entra_config),
]:
    tk.Button(
        sidebar,
        text=text,
        command=command,
        bg=SIDEBAR,
        fg=TEXT_2,
        bd=0,
        activebackground=SURFACE_3,
        activeforeground=TEXT,
        anchor="w",
        padx=17,
        pady=7,
        font=("Segoe UI", 8, "bold"),
    ).pack(
        fill="x",
        padx=7,
        pady=1,
    )

profile_card = tk.Frame(
    sidebar,
    bg=SURFACE,
    highlightbackground=BORDER,
    highlightthickness=1,
    padx=12,
    pady=10,
)

profile_card.pack(
    side="bottom",
    fill="x",
    padx=10,
    pady=12,
)

tk.Label(
    profile_card,
    text="Active Profile",
    bg=SURFACE,
    fg=GREEN,
    font=("Segoe UI", 7, "bold"),
).pack(anchor="w")

sidebar_profile_name = tk.Label(
    profile_card,
    text="Loading...",
    bg=SURFACE,
    fg=TEXT,
    font=("Segoe UI", 10, "bold"),
)

sidebar_profile_name.pack(
    anchor="w",
    pady=(3, 0),
)

# ---------------- Main content ----------------
main = tk.Frame(shell, bg=BG)
main.grid(
    row=0,
    column=1,
    sticky="nsew",
)

main.grid_columnconfigure(0, weight=1)
main.grid_columnconfigure(1, weight=0)
main.grid_rowconfigure(4, weight=1)

# Header
header = tk.Frame(main, bg=BG)
header.grid(
    row=0,
    column=0,
    sticky="ew",
    padx=24,
    pady=(15, 6),
)

header.grid_columnconfigure(0, weight=1)

header_left = tk.Frame(header, bg=BG)
header_left.grid(
    row=0,
    column=0,
    sticky="w",
)

tk.Label(
    header_left,
    text="Security Assessment Dashboard",
    bg=BG,
    fg=TEXT,
    font=("Segoe UI", 23, "bold"),
).pack(anchor="w")

tk.Label(
    header_left,
    text=(
        "Comprehensive security posture assessment using Windows, "
        "Active Directory, and Entra ID evidence."
    ),
    bg=BG,
    fg=MUTED,
    font=("Segoe UI", 8),
).pack(
    anchor="w",
    pady=(2, 0),
)

status_line = tk.Frame(header_left, bg=BG)
status_line.pack(
    anchor="w",
    pady=(4, 0),
)

mode_label = tk.Label(
    status_line,
    text="Assessment Mode: Not Run",
    bg=BG,
    fg=GREEN,
    font=("Segoe UI", 8, "bold"),
)
mode_label.pack(side="left")

tk.Label(
    status_line,
    text="  |  ",
    bg=BG,
    fg=MUTED,
).pack(side="left")

profile_label = tk.Label(
    status_line,
    text="Active Methodology: Loading...",
    bg=BG,
    fg=YELLOW,
    font=("Segoe UI", 8, "bold"),
)
profile_label.pack(side="left")

right_rail = tk.Frame(
    main,
    bg=BG,
    width=170,
)
right_rail.grid(
    row=0,
    column=1,
    rowspan=7,
    sticky="nse",
    padx=(0, 16),
    pady=(18, 38),
)
right_rail.grid_propagate(False)

def rail_button(text, command, color):
    button = tk.Button(
        right_rail,
        text=text,
        command=command,
        bg=color,
        fg=TEXT,
        bd=0,
        activebackground=BLUE_2,
        activeforeground=TEXT,
        padx=10,
        pady=9,
        font=("Segoe UI", 7, "bold"),
        anchor="w",
    )
    button.pack(fill="x", pady=4)
    return button

rail_button("Control Library", open_control_library, GREEN)
rail_button("Profile Manager", open_methodology_settings, BLUE)
rail_button("Entra Config", open_entra_config, PURPLE)
rail_button("Export JSON", open_json, SURFACE_3)
rail_button("Export HTML Report", open_html, SURFACE_3)

# Status row
status_bar = tk.Frame(
    main,
    bg=SURFACE,
    highlightbackground=BORDER,
    highlightthickness=1,
    padx=10,
    pady=7,
)

status_bar.grid(
    row=1,
    column=0,
    sticky="ew",
    padx=24,
    pady=(0, 7),
)

status_bar.grid_columnconfigure(1, weight=1)

tk.Label(
    status_bar,
    text="●",
    bg=SURFACE,
    fg=GREEN,
    font=("Segoe UI", 10, "bold"),
).grid(
    row=0,
    column=0,
    padx=(0, 7),
)

activity_label = tk.Label(
    status_bar,
    text="Ready.",
    bg=SURFACE,
    fg=TEXT_2,
    font=("Segoe UI", 7),
)

activity_label.grid(
    row=0,
    column=1,
    sticky="w",
)

progress_var = tk.IntVar(value=0)
progress_bar = ttk.Progressbar(
    status_bar,
    maximum=100,
    variable=progress_var,
    style="Horizontal.TProgressbar",
    length=190,
)

progress_bar.grid(
    row=0,
    column=2,
    sticky="e",
)

# KPI cards
cards = tk.Frame(main, bg=BG)
cards.grid(
    row=2,
    column=0,
    sticky="ew",
    padx=24,
    pady=(0, 7),
)

for index in range(5):
    cards.grid_columnconfigure(
        index,
        weight=1,
        uniform="kpi",
    )

def make_card(parent, column, title, accent, icon_kind):
    frame = tk.Frame(
        parent,
        bg=SURFACE,
        highlightbackground=BORDER,
        highlightthickness=1,
        padx=11,
        pady=9,
    )
    frame.grid(
        row=0,
        column=column,
        sticky="nsew",
        padx=4,
    )
    frame.grid_columnconfigure(1, weight=1)

    icon_canvas = tk.Canvas(
        frame,
        width=48,
        height=48,
        bg=SURFACE,
        highlightthickness=0,
    )
    icon_canvas.grid(row=0, column=0, rowspan=3, sticky="w", padx=(0, 8))
    draw_card_icon(icon_canvas, icon_kind, accent)

    tk.Label(
        frame,
        text=title,
        bg=SURFACE,
        fg=MUTED,
        font=("Segoe UI", 7, "bold"),
    ).grid(row=0, column=1, sticky="w")

    value = tk.Label(
        frame,
        text="—",
        bg=SURFACE,
        fg=accent,
        font=("Segoe UI", 18, "bold"),
    )
    value.grid(row=1, column=1, sticky="w", pady=(5, 1))

    subtitle = tk.Label(
        frame,
        text="",
        bg=SURFACE,
        fg=TEXT_2,
        font=("Segoe UI", 6),
        wraplength=170,
        justify="left",
    )
    subtitle.grid(row=2, column=1, sticky="w")

    return value, subtitle

score_label, score_sub = make_card(
    cards,
    0,
    "OVERALL ASSESSMENT SCORE",
    CYAN,
    "shield",
)

grade_label, grade_sub = make_card(
    cards,
    1,
    "ASSESSMENT GRADE",
    YELLOW,
    "medal",
)

readiness_label, readiness_sub = make_card(
    cards,
    2,
    "READINESS LEVEL",
    GREEN,
    "warning",
)

passed_label, passed_sub = make_card(
    cards,
    3,
    "CONTROLS PASSED",
    GREEN,
    "check",
)

failed_label, failed_sub = make_card(
    cards,
    4,
    "CONTROLS FAILED",
    RED,
    "cross",
)

grade_sub.config(
    text="Assessment grade based on active profile"
)

readiness_sub.config(
    text="Overall security readiness"
)

# Visual panels
visuals = tk.Frame(main, bg=BG)
visuals.grid(
    row=3,
    column=0,
    sticky="ew",
    padx=24,
    pady=(0, 7),
)

for index in range(3):
    visuals.grid_columnconfigure(
        index,
        weight=1,
        uniform="visual",
    )

def visual_panel(parent, column):
    frame = tk.Frame(
        parent,
        bg=SURFACE,
        highlightbackground=BORDER,
        highlightthickness=1,
    )

    frame.grid(
        row=0,
        column=column,
        sticky="nsew",
        padx=4,
    )

    return frame

gauge_panel = visual_panel(visuals, 0)
domain_panel = visual_panel(visuals, 1)
method_panel = visual_panel(visuals, 2)

gauge = tk.Canvas(
    gauge_panel,
    bg=SURFACE,
    height=235,
    highlightthickness=0,
)
gauge.pack(
    fill="both",
    expand=True,
    padx=7,
    pady=7,
)

domain_canvas = tk.Canvas(
    domain_panel,
    bg=SURFACE,
    height=235,
    highlightthickness=0,
)
domain_canvas.pack(
    fill="both",
    expand=True,
    padx=7,
    pady=7,
)

method_canvas = tk.Canvas(
    method_panel,
    bg=SURFACE,
    height=235,
    highlightthickness=0,
)
method_canvas.pack(
    fill="both",
    expand=True,
    padx=7,
    pady=7,
)

# Bottom section
bottom = tk.Frame(main, bg=BG)
bottom.grid(
    row=4,
    column=0,
    sticky="nsew",
    padx=24,
    pady=(0, 7),
)

bottom.grid_columnconfigure(0, weight=1)
bottom.grid_columnconfigure(1, weight=3)
bottom.grid_rowconfigure(0, weight=1)

summary_frame = tk.Frame(
    bottom,
    bg=SURFACE,
    highlightbackground=BORDER,
    highlightthickness=1,
    padx=12,
    pady=10,
)

summary_frame.grid(
    row=0,
    column=0,
    sticky="nsew",
    padx=(4, 5),
)

tk.Label(
    summary_frame,
    text="EXECUTIVE SUMMARY",
    bg=SURFACE,
    fg=TEXT,
    font=("Segoe UI", 10, "bold"),
).pack(anchor="w")

tk.Label(
    summary_frame,
    text="Plain-language assessment outcome and readiness explanation.",
    bg=SURFACE,
    fg=MUTED,
    font=("Segoe UI", 6),
).pack(
    anchor="w",
    pady=(2, 7),
)

summary_text = tk.Text(
    summary_frame,
    bg=SURFACE,
    fg=TEXT_2,
    font=("Segoe UI", 8),
    bd=0,
    wrap="word",
    padx=0,
    pady=0,
    height=8,
)

summary_text.pack(
    fill="both",
    expand=True,
)

summary_text.config(state="disabled")

results_area = tk.Frame(bottom, bg=BG)
results_area.grid(
    row=0,
    column=1,
    sticky="nsew",
    padx=(5, 4),
)

results_area.grid_rowconfigure(1, weight=1)
results_area.grid_columnconfigure(0, weight=1)

results_header = tk.Frame(
    results_area,
    bg=BG,
)

results_header.grid(
    row=0,
    column=0,
    sticky="ew",
    pady=(0, 5),
)

results_header.grid_columnconfigure(0, weight=1)

tk.Label(
    results_header,
    text="CONTROL ASSESSMENT RESULTS",
    bg=BG,
    fg=TEXT,
    font=("Segoe UI", 11, "bold"),
).grid(
    row=0,
    column=0,
    sticky="w",
)

visible_label = tk.Label(
    results_header,
    text="Showing 0 controls",
    bg=BG,
    fg=CYAN,
    font=("Segoe UI", 7, "bold"),
)

visible_label.grid(
    row=0,
    column=1,
    sticky="e",
)

table_frame = tk.Frame(
    results_area,
    bg=SURFACE,
    highlightbackground=BORDER,
    highlightthickness=1,
)

table_frame.grid(
    row=1,
    column=0,
    sticky="nsew",
)

table_frame.grid_rowconfigure(0, weight=1)
table_frame.grid_columnconfigure(0, weight=1)

columns = (
    "Control ID",
    "Domain",
    "Control",
    "Status",
    "Risk",
    "Score",
    "Result",
    "Evidence",
)

results_table = ttk.Treeview(
    table_frame,
    columns=columns,
    show="headings",
    height=6,
)

for column in columns:
    results_table.heading(
        column,
        text=column,
    )

column_widths = {
    "Control ID": 95,
    "Domain": 160,
    "Control": 225,
    "Status": 80,
    "Risk": 70,
    "Score": 70,
    "Result": 190,
    "Evidence": 60,
}

for column, width in column_widths.items():
    results_table.column(
        column,
        width=width,
        minwidth=55,
        stretch=True,
    )

results_table.tag_configure(
    "pass",
    background=DARK_GREEN,
    foreground="#DCFCE7",
)

results_table.tag_configure(
    "fail",
    background=DARK_RED,
    foreground="#FEE2E2",
)

results_table.tag_configure(
    "na",
    background=SURFACE_3,
    foreground=TEXT_2,
)

vertical_scroll = ttk.Scrollbar(
    table_frame,
    orient="vertical",
    command=results_table.yview,
)

horizontal_scroll = ttk.Scrollbar(
    table_frame,
    orient="horizontal",
    command=results_table.xview,
)

results_table.configure(
    yscrollcommand=vertical_scroll.set,
    xscrollcommand=horizontal_scroll.set,
)

results_table.grid(
    row=0,
    column=0,
    sticky="nsew",
    padx=(7, 0),
    pady=(7, 0),
)

vertical_scroll.grid(
    row=0,
    column=1,
    sticky="ns",
    pady=(7, 0),
)

horizontal_scroll.grid(
    row=1,
    column=0,
    sticky="ew",
    padx=(7, 0),
    pady=(0, 7),
)

results_table.bind(
    "<Double-1>",
    on_result_click,
)

# Footer
footer = tk.Frame(
    main,
    bg=SIDEBAR,
    height=30,
)

footer.grid(
    row=5,
    column=0,
    sticky="ew",
)

footer.grid_columnconfigure(1, weight=1)

tk.Label(
    footer,
    text="System Status: Ready",
    bg=SIDEBAR,
    fg=GREEN,
    font=("Segoe UI", 7, "bold"),
).grid(
    row=0,
    column=0,
    padx=15,
    pady=6,
    sticky="w",
)

tk.Label(
    footer,
    text="Assessment Engine: v4.2   |   Database: Connected",
    bg=SIDEBAR,
    fg=MUTED,
    font=("Segoe UI", 7),
).grid(
    row=0,
    column=1,
    pady=6,
)

clock_label = tk.Label(
    footer,
    text="",
    bg=SIDEBAR,
    fg=MUTED,
    font=("Segoe UI", 7),
)

clock_label.grid(
    row=0,
    column=2,
    padx=15,
    pady=6,
    sticky="e",
)

def update_clock():
    clock_label.config(
        text=datetime.now().strftime(
            "Current Time: %b %d, %Y %I:%M %p"
        )
    )
    root.after(30000, update_clock)

initialize_database(SAF_CONTROLS)
filter_domain("All")
update_profile_label()
update_clock()
run_demo("balanced")
root.mainloop()
