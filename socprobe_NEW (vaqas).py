
import tkinter as tk
from tkinter import ttk, messagebox
import json
import webbrowser
from datetime import datetime
import os

APP_VERSION = "SOCProbe SAF v1.1 - Enterprise Assessment Console"
REPORT_JSON = "socprobe_saf_assessment.json"
REPORT_HTML = "socprobe_saf_report.html"

SAF_CONTROLS = [
    {"id":"SAF-ID-01","domain":"Identity Security","name":"Privileged Account Assessment","objective":"Verify privileged accounts are limited and reviewed.","method":"Assess privileged group membership.","pass_criteria":"Privileged administrator count is within approved threshold.","weight":10,"risk":"High","recommendation":"Review privileged memberships and remove unnecessary administrative access."},
    {"id":"SAF-ID-02","domain":"Identity Security","name":"Inactive Account Assessment","objective":"Identify enabled accounts that have not been used recently.","method":"Review last logon evidence.","pass_criteria":"No enabled account exceeds the inactive account threshold.","weight":8,"risk":"High","recommendation":"Disable inactive accounts and confirm ownership before removal."},
    {"id":"SAF-ID-03","domain":"Identity Security","name":"Disabled Account Hygiene","objective":"Ensure disabled accounts do not retain sensitive access.","method":"Review disabled accounts for privileged access.","pass_criteria":"Disabled accounts do not remain in privileged groups.","weight":6,"risk":"Medium","recommendation":"Remove disabled accounts from privileged or sensitive groups."},
    {"id":"SAF-ID-04","domain":"Identity Security","name":"Service Account Review","objective":"Identify service accounts that may create access risk.","method":"Review service-like accounts and non-expiring passwords.","pass_criteria":"Service accounts are documented and controlled.","weight":6,"risk":"Medium","recommendation":"Document service accounts, rotate credentials, and restrict access."},
    {"id":"SAF-AU-01","domain":"Authentication","name":"Password Policy Assessment","objective":"Assess password length, age, and complexity controls.","method":"Evaluate password and lockout policy evidence.","pass_criteria":"Password settings meet SAF requirements.","weight":8,"risk":"High","recommendation":"Strengthen password length, lockout threshold, and expiration policy."},
    {"id":"SAF-AU-02","domain":"Authentication","name":"Account Lockout Assessment","objective":"Verify account lockout controls reduce brute-force risk.","method":"Review lockout threshold and duration.","pass_criteria":"Account lockout is enabled and reasonable.","weight":7,"risk":"High","recommendation":"Enable account lockout and tune threshold to reduce password attacks."},
    {"id":"SAF-AU-03","domain":"Authentication","name":"Credential Exposure Assessment","objective":"Identify settings that increase credential exposure.","method":"Assess risky authentication configurations.","pass_criteria":"Credential exposure risks are not present.","weight":7,"risk":"High","recommendation":"Reduce credential exposure through hardened authentication settings."},
    {"id":"SAF-AU-04","domain":"Authentication","name":"Multi-Factor Readiness","objective":"Assess readiness for stronger authentication.","method":"Check readiness for MFA or equivalent controls.","pass_criteria":"Privileged accounts are ready for MFA or equivalent control.","weight":6,"risk":"Medium","recommendation":"Prepare privileged accounts for MFA enforcement."},
    {"id":"SAF-INF-01","domain":"Infrastructure","name":"Domain Controller Assessment","objective":"Verify domain controller visibility and health.","method":"Review domain controller evidence.","pass_criteria":"Domain controllers are reachable and visible.","weight":8,"risk":"High","recommendation":"Investigate domain controller visibility, availability, and health."},
    {"id":"SAF-INF-02","domain":"Infrastructure","name":"Replication Health Assessment","objective":"Assess directory replication health.","method":"Review replication evidence for failures.","pass_criteria":"No replication failures are detected.","weight":7,"risk":"High","recommendation":"Resolve replication failures and verify synchronization."},
    {"id":"SAF-INF-03","domain":"Infrastructure","name":"Remote Access Exposure","objective":"Assess exposure from remote administrative access.","method":"Review remote access posture.","pass_criteria":"Remote access is restricted and controlled.","weight":6,"risk":"Medium","recommendation":"Restrict remote access and require controlled administrative access."},
    {"id":"SAF-INF-04","domain":"Infrastructure","name":"Firewall Posture Assessment","objective":"Verify host firewall posture supports baseline protection.","method":"Assess firewall state evidence.","pass_criteria":"Firewall protection is enabled and aligned to baseline.","weight":5,"risk":"Medium","recommendation":"Enable and validate firewall profiles."},
    {"id":"SAF-LOG-01","domain":"Logging","name":"Audit Policy Assessment","objective":"Verify key audit categories are enabled.","method":"Review audit policy configuration evidence.","pass_criteria":"Required audit categories are enabled.","weight":8,"risk":"High","recommendation":"Enable required audit categories and apply policy updates."},
    {"id":"SAF-LOG-02","domain":"Logging","name":"Security Log Accessibility","objective":"Verify Security logs are available for assessment evidence.","method":"Attempt to read recent Security log records.","pass_criteria":"Security log is accessible and contains recent events.","weight":7,"risk":"High","recommendation":"Grant appropriate read access and verify Security logs are recording."},
    {"id":"SAF-LOG-03","domain":"Logging","name":"Critical Event Coverage","objective":"Assess whether key security events are visible.","method":"Review presence of important event categories.","pass_criteria":"Critical event categories are present.","weight":6,"risk":"Medium","recommendation":"Enable missing event collection and validate audit policy."},
    {"id":"SAF-LOG-04","domain":"Logging","name":"Log Retention Readiness","objective":"Assess whether log retention is sufficient.","method":"Review log availability and retention posture.","pass_criteria":"Security evidence is retained long enough for review.","weight":5,"risk":"Medium","recommendation":"Increase log size and retention to support investigations."},
    {"id":"SAF-PR-01","domain":"Privilege Management","name":"Administrative Group Review","objective":"Assess high privilege groups for excessive membership.","method":"Review administrative groups and role membership.","pass_criteria":"Administrative group membership is limited and approved.","weight":10,"risk":"High","recommendation":"Remove unnecessary administrators and document approvals."},
    {"id":"SAF-PR-02","domain":"Privilege Management","name":"Delegation Assessment","objective":"Identify risky delegation or permission exposure.","method":"Review delegation posture indicators.","pass_criteria":"No risky delegation is detected.","weight":8,"risk":"High","recommendation":"Review delegation and remove excessive permissions."},
    {"id":"SAF-PR-03","domain":"Privilege Management","name":"Admin Change Assessment","objective":"Assess recent administrative access changes.","method":"Review evidence of privileged group changes.","pass_criteria":"No unexpected administrative changes are detected.","weight":8,"risk":"High","recommendation":"Confirm administrative changes are authorized and documented."},
    {"id":"SAF-EP-01","domain":"Endpoint Security","name":"Defender Readiness","objective":"Assess endpoint protection readiness.","method":"Review endpoint protection posture.","pass_criteria":"Endpoint protection is enabled and functional.","weight":6,"risk":"Medium","recommendation":"Enable endpoint protection and verify real-time protection."},
    {"id":"SAF-EP-02","domain":"Endpoint Security","name":"Disk Protection Readiness","objective":"Assess readiness for disk encryption.","method":"Review disk protection evidence.","pass_criteria":"Disk protection is enabled or planned for sensitive systems.","weight":5,"risk":"Medium","recommendation":"Enable disk encryption for sensitive endpoints and servers."},
    {"id":"SAF-EP-03","domain":"Endpoint Security","name":"Patch Readiness","objective":"Assess readiness for patch management.","method":"Review update posture and patch readiness indicators.","pass_criteria":"Systems are prepared for timely patching.","weight":6,"risk":"Medium","recommendation":"Ensure patching process is active and regularly reviewed."},
    {"id":"SAF-PC-01","domain":"Policy & Configuration","name":"Group Policy Assessment","objective":"Assess whether baseline security policies are configured.","method":"Review policy baseline evidence.","pass_criteria":"Baseline security policies are present.","weight":7,"risk":"High","recommendation":"Apply and validate baseline security policies."},
    {"id":"SAF-PC-02","domain":"Policy & Configuration","name":"Security Options Assessment","objective":"Assess key Windows security options.","method":"Review local and domain security option posture.","pass_criteria":"Security options align to SAF baseline.","weight":6,"risk":"Medium","recommendation":"Harden security options through policy."},
    {"id":"SAF-PC-03","domain":"Policy & Configuration","name":"Assessment Configuration Review","objective":"Verify the assessment has enough evidence.","method":"Review whether required evidence sources are available.","pass_criteria":"Evidence sources are available for assessment.","weight":5,"risk":"Medium","recommendation":"Enable required evidence sources and rerun assessment."},
    {"id":"SAF-CR-01","domain":"Cloud Readiness","name":"Hybrid Identity Readiness","objective":"Assess readiness to evaluate hybrid identity environments.","method":"Review whether cloud assessment inputs are configured.","pass_criteria":"Cloud identity inputs are configured or intentionally excluded.","weight":5,"risk":"Medium","recommendation":"Configure cloud identity connection when hybrid assessment is required."},
    {"id":"SAF-CR-02","domain":"Cloud Readiness","name":"Cloud Administrative Review","objective":"Assess cloud administrator review readiness.","method":"Review whether cloud privileged role evidence can be assessed.","pass_criteria":"Cloud administrative evidence is available or marked out of scope.","weight":5,"risk":"Medium","recommendation":"Add cloud administrative evidence source for hybrid assessment."},
    {"id":"SAF-CR-03","domain":"Cloud Readiness","name":"Cloud Authentication Readiness","objective":"Assess readiness for cloud authentication controls.","method":"Review whether MFA and cloud authentication evidence can be assessed.","pass_criteria":"Cloud authentication evidence is available or marked out of scope.","weight":5,"risk":"Medium","recommendation":"Add cloud authentication evidence source when Entra assessment is enabled."},
]

GRADE_BANDS = [("A+",95,"Enterprise Ready"),("A",90,"Excellent"),("B",80,"Good"),("C",70,"Needs Improvement"),("D",60,"High Risk"),("F",0,"Critical")]

def get_grade(score):
    for grade, minimum, label in GRADE_BANDS:
        if score >= minimum:
            return grade, label
    return "F", "Critical"

def score_color(score):
    if score >= 90: return "#22c55e"
    if score >= 80: return "#a3e635"
    if score >= 70: return "#facc15"
    if score >= 60: return "#fb923c"
    return "#ef4444"

def create_assessment(scenario="balanced"):
    scenario_failures = {
        "excellent": [],
        "identity_risk": ["SAF-ID-01","SAF-ID-02","SAF-ID-04","SAF-PR-01"],
        "logging_gap": ["SAF-LOG-01","SAF-LOG-02","SAF-LOG-03","SAF-LOG-04","SAF-PC-03"],
        "privilege_risk": ["SAF-ID-01","SAF-PR-01","SAF-PR-02","SAF-PR-03"],
        "cloud_readiness_gap": ["SAF-CR-01","SAF-CR-02","SAF-CR-03"],
        "critical": ["SAF-ID-01","SAF-ID-02","SAF-AU-01","SAF-AU-02","SAF-INF-01","SAF-LOG-01","SAF-LOG-02","SAF-PR-01","SAF-PR-03","SAF-PC-01"],
        "balanced": ["SAF-ID-02","SAF-LOG-03","SAF-PC-03","SAF-CR-01"],
    }
    failed_ids = set(scenario_failures.get(scenario, scenario_failures["balanced"]))
    results = []
    for control in SAF_CONTROLS:
        passed = control["id"] not in failed_ids
        evidence = f"Evidence meets SAF criteria for {control['id']}." if passed else f"Assessment evidence did not meet SAF criteria for {control['id']}."
        results.append({**control, "status": "PASS" if passed else "FAIL", "earned": control["weight"] if passed else 0, "evidence": evidence})
    total = sum(r["weight"] for r in results)
    earned = sum(r["earned"] for r in results)
    score = round((earned/total)*100) if total else 0
    grade, readiness = get_grade(score)
    domains = {}
    for r in results:
        d = r["domain"]
        domains.setdefault(d, {"earned":0,"total":0,"passed":0,"total_controls":0})
        domains[d]["earned"] += r["earned"]
        domains[d]["total"] += r["weight"]
        domains[d]["total_controls"] += 1
        if r["status"] == "PASS": domains[d]["passed"] += 1
    for d in domains:
        domains[d]["score"] = round((domains[d]["earned"]/domains[d]["total"])*100) if domains[d]["total"] else 0
    failed = [r for r in results if r["status"] == "FAIL"]
    return {
        "tool":"SOCProbe Security Assessment Framework",
        "version":APP_VERSION,
        "assessment_time":str(datetime.now()),
        "scenario":scenario,
        "methodology":["Evidence Collection","Control Evaluation","Risk Assessment","Score Calculation","Recommendation Generation"],
        "overall_score":score,
        "grade":grade,
        "readiness":readiness,
        "total_controls":len(results),
        "passed_controls":len([r for r in results if r["status"] == "PASS"]),
        "failed_controls":len(failed),
        "domain_scores":domains,
        "results":results,
        "findings":failed,
        "summary":f"SOCProbe SAF assessed {len(results)} internal controls across {len(domains)} domains. The environment scored {score}/100 with grade {grade} ({readiness}). {len(failed)} controls require attention. This assessment uses only the SOCProbe Security Assessment Framework."
    }

def generate_html_report(report):
    domain_rows = "".join([f"<tr><td>{d}</td><td>{v['score']}%</td><td>{v['passed']} / {v['total_controls']}</td></tr>" for d,v in report["domain_scores"].items()])
    result_rows = ""
    for r in report["results"]:
        cls = "pass" if r["status"] == "PASS" else "fail"
        result_rows += f"<tr class='{cls}'><td>{r['id']}</td><td>{r['domain']}</td><td>{r['name']}</td><td>{r['status']}</td><td>{r['risk']}</td><td>{r['earned']} / {r['weight']}</td><td>{r['recommendation']}</td></tr>"
    html = f"""
<html><head><title>SOCProbe SAF Report</title><style>
body{{background:#121018;color:#f8fafc;font-family:Segoe UI,Arial;padding:30px}}.card{{background:#1d1826;border:1px solid #5b21b6;border-radius:18px;padding:22px;margin-bottom:22px}}h1{{color:#c4b5fd}}.score{{font-size:52px;font-weight:bold;color:{score_color(report['overall_score'])}}}.grade{{font-size:34px;font-weight:bold;color:#facc15}}table{{width:100%;border-collapse:collapse;margin-top:12px}}th{{background:#4c1d95;color:white;padding:12px;text-align:left}}td{{padding:10px;border-bottom:1px solid #3a3543}}.pass{{background:#12351f}}.fail{{background:#3b1022}}
</style></head><body>
<div class="card"><h1>SOCProbe Security Assessment Framework Report</h1><p><b>Assessment Time:</b> {report['assessment_time']}</p><p><b>Scenario:</b> {report['scenario']}</p><div class="score">{report['overall_score']}/100</div><div class="grade">Grade {report['grade']} - {report['readiness']}</div><p>{report['summary']}</p></div>
<div class="card"><h2>Assessment Methodology</h2><ol><li>Evidence Collection</li><li>Control Evaluation</li><li>Risk Assessment</li><li>Score Calculation</li><li>Recommendation Generation</li></ol></div>
<div class="card"><h2>Domain Scores</h2><table><tr><th>Domain</th><th>Score</th><th>Controls Passed</th></tr>{domain_rows}</table></div>
<div class="card"><h2>SAF Control Results</h2><table><tr><th>Control ID</th><th>Domain</th><th>Control</th><th>Status</th><th>Risk</th><th>Score</th><th>Recommendation</th></tr>{result_rows}</table></div>
</body></html>"""
    with open(REPORT_HTML, "w", encoding="utf-8") as f: f.write(html)
    with open(REPORT_JSON, "w", encoding="utf-8") as f: json.dump(report, f, indent=4)

current_report = None
current_domain_filter = "All"

def draw_gauge(score=0):
    gauge.delete("all")
    w,h,cx,cy,r = 330,220,165,175,120
    gauge.create_arc(cx-r, cy-r, cx+r, cy+r, start=180, extent=-45, width=24, style="arc", outline="#ef4444")
    gauge.create_arc(cx-r, cy-r, cx+r, cy+r, start=135, extent=-45, width=24, style="arc", outline="#fb923c")
    gauge.create_arc(cx-r, cy-r, cx+r, cy+r, start=90, extent=-45, width=24, style="arc", outline="#facc15")
    gauge.create_arc(cx-r, cy-r, cx+r, cy+r, start=45, extent=-45, width=24, style="arc", outline="#22c55e")
    import math
    angle = 180 - (score/100)*180
    rad = math.radians(angle)
    x = cx + 95*math.cos(rad)
    y = cy - 95*math.sin(rad)
    gauge.create_line(cx, cy, x, y, fill="#f8fafc", width=4)
    gauge.create_oval(cx-8, cy-8, cx+8, cy+8, fill="#f8fafc", outline="")
    gauge.create_text(cx, 28, text="Assessment Score", fill="#f8fafc", font=("Segoe UI", 13, "bold"))
    gauge.create_text(cx, 108, text=f"{score}/100", fill=score_color(score), font=("Segoe UI", 26, "bold"))

def draw_domain_bars(report):
    domain_canvas.delete("all")
    domain_canvas.create_text(225, 24, text="Domain Scores", fill="#f8fafc", font=("Segoe UI", 13, "bold"))
    y = 58
    for domain, d in report["domain_scores"].items():
        score = d["score"]
        domain_canvas.create_text(15, y+10, text=domain, fill="#e5e7eb", font=("Segoe UI", 9, "bold"), anchor="w")
        domain_canvas.create_rectangle(190, y, 420, y+20, fill="#2e2638", outline="")
        domain_canvas.create_rectangle(190, y, 190 + int(score*2.3), y+20, fill=score_color(score), outline="")
        domain_canvas.create_text(430, y+10, text=f"{score}%", fill="#f8fafc", font=("Segoe UI", 9, "bold"), anchor="w")
        y += 32

def draw_methodology(report):
    method_canvas.delete("all")
    method_canvas.create_text(190, 24, text="SAF Assessment Flow", fill="#f8fafc", font=("Segoe UI", 13, "bold"))
    x,y = 38,95
    for i, step in enumerate(report["methodology"]):
        method_canvas.create_oval(x, y-22, x+44, y+22, fill="#7e22ce", outline="#c4b5fd", width=2)
        method_canvas.create_text(x+22, y, text=str(i+1), fill="white", font=("Segoe UI", 11, "bold"))
        method_canvas.create_text(x+22, y+45, text=step, fill="#e5e7eb", font=("Segoe UI", 8, "bold"), width=90)
        if i < len(report["methodology"])-1:
            method_canvas.create_line(x+48, y, x+92, y, fill="#9ca3af", width=2, arrow=tk.LAST)
        x += 95

def populate_results(report):
    for item in results_table.get_children(): results_table.delete(item)
    visible = 0
    for r in report["results"]:
        if current_domain_filter != "All" and r["domain"] != current_domain_filter: continue
        visible += 1
        tag = "pass" if r["status"] == "PASS" else "fail"
        results_table.insert("", tk.END, values=(r["id"],r["domain"],r["name"],r["status"],r["risk"],f"{r['earned']} / {r['weight']}",r["evidence"]), tags=(tag,))
    visible_label.config(text=f"Showing {visible} control(s)")

def filter_domain(domain):
    global current_domain_filter
    current_domain_filter = domain
    for name, btn in domain_buttons.items(): btn.config(bg=PURPLE if name == domain else PANEL)
    if current_report: populate_results(current_report)

def load_report(report):
    global current_report
    current_report = report
    generate_html_report(report)
    score_label.config(text=f"{report['overall_score']} / 100", fg=score_color(report["overall_score"]))
    grade_label.config(text=f"Grade {report['grade']}", fg=score_color(report["overall_score"]))
    readiness_label.config(text=report["readiness"])
    passed_label.config(text=f"{report['passed_controls']} / {report['total_controls']}")
    failed_label.config(text=f"{report['failed_controls']} Failed")
    summary_text.delete("1.0", tk.END)
    summary_text.insert(tk.END, report["summary"])
    draw_gauge(report["overall_score"])
    draw_domain_bars(report)
    draw_methodology(report)
    populate_results(report)

def start_assessment(scenario="balanced"):
    load_report(create_assessment(scenario))

def open_json():
    if os.path.exists(REPORT_JSON): os.startfile(REPORT_JSON)
    else: messagebox.showinfo("No Report", "Run an assessment first.")

def open_html():
    if os.path.exists(REPORT_HTML): webbrowser.open(REPORT_HTML)
    else: messagebox.showinfo("No Report", "Run an assessment first.")

def on_result_click(event):
    selected = results_table.focus()
    if not selected or not current_report: return
    values = results_table.item(selected, "values")
    if not values: return
    control = next((r for r in current_report["results"] if r["id"] == values[0]), None)
    if not control: return
    detail = f"""Control ID: {control['id']}
Domain: {control['domain']}
Control Name: {control['name']}
Status: {control['status']}
Risk: {control['risk']}
Score: {control['earned']} / {control['weight']}

Objective:
{control['objective']}

Assessment Method:
{control['method']}

Pass Criteria:
{control['pass_criteria']}

Evidence:
{control['evidence']}

Recommendation:
{control['recommendation']}
"""
    messagebox.showinfo("SAF Control Details", detail)


root = tk.Tk()
root.title(APP_VERSION)
root.geometry("1680x1020")
root.minsize(1400, 900)
root.configure(bg="#0B1120")

# Premium enterprise color system
BG = "#0B1120"          # deep navy
SURFACE = "#111827"     # card background
SURFACE_2 = "#172033"   # elevated card
SURFACE_3 = "#1E293B"   # hover/secondary
BORDER = "#263449"
BORDER_ACTIVE = "#38BDF8"
TEXT = "#F8FAFC"
TEXT_2 = "#CBD5E1"
MUTED = "#94A3B8"
CYAN = "#38BDF8"
BLUE = "#2563EB"
BLUE_2 = "#1D4ED8"
GREEN = "#22C55E"
YELLOW = "#FACC15"
ORANGE = "#FB923C"
RED = "#EF4444"
PURPLE = "#8B5CF6"

style = ttk.Style()
style.theme_use("default")
style.configure(
    "Treeview",
    background=SURFACE,
    foreground=TEXT_2,
    fieldbackground=SURFACE,
    rowheight=48,
    borderwidth=0,
    font=("Segoe UI", 10)
)
style.configure(
    "Treeview.Heading",
    background="#0F172A",
    foreground=TEXT,
    font=("Segoe UI", 10, "bold"),
    padding=12
)
style.map("Treeview", background=[("selected", "#1D4ED8")])

# ---------- App Shell ----------
shell = tk.Frame(root, bg=BG)
shell.pack(fill="both", expand=True)

# ---------- Sidebar ----------
sidebar = tk.Frame(shell, bg="#0F172A", width=250)
sidebar.pack(side="left", fill="y")
sidebar.pack_propagate(False)

brand_frame = tk.Frame(sidebar, bg="#0F172A")
brand_frame.pack(fill="x", padx=22, pady=(24, 20))

tk.Label(
    brand_frame,
    text="SOCProbe",
    bg="#0F172A",
    fg=TEXT,
    font=("Segoe UI", 24, "bold")
).pack(anchor="w")

tk.Label(
    brand_frame,
    text="SAF Assessment Console",
    bg="#0F172A",
    fg=CYAN,
    font=("Segoe UI", 10, "bold")
).pack(anchor="w", pady=(2, 0))

tk.Label(
    brand_frame,
    text="Original Security Assessment Framework",
    bg="#0F172A",
    fg=MUTED,
    font=("Segoe UI", 8)
).pack(anchor="w", pady=(2, 0))

tk.Frame(sidebar, bg=BORDER, height=1).pack(fill="x", padx=20, pady=(4, 16))

domain_buttons = {}
current_domain_filter = "All"

def sidebar_button(text, command, active=False):
    btn = tk.Button(
        sidebar,
        text=text,
        command=command,
        bg=BLUE if active else "#0F172A",
        fg=TEXT if active else TEXT_2,
        activebackground=BLUE_2,
        activeforeground=TEXT,
        font=("Segoe UI", 10, "bold"),
        anchor="w",
        padx=18,
        pady=10,
        bd=0,
        relief="flat"
    )
    btn.pack(fill="x", padx=14, pady=2)
    return btn

def filter_domain(domain):
    global current_domain_filter
    current_domain_filter = domain

    for name, btn in domain_buttons.items():
        btn.config(
            bg=BLUE if name == domain else "#0F172A",
            fg=TEXT if name == domain else TEXT_2
        )

    if current_report:
        populate_results(current_report)

domains = ["All"] + sorted(set(c["domain"] for c in SAF_CONTROLS))
for d in domains:
    domain_buttons[d] = sidebar_button(d, lambda x=d: filter_domain(x), active=(d == "All"))

tk.Frame(sidebar, bg=BORDER, height=1).pack(fill="x", padx=20, pady=18)

tk.Label(
    sidebar,
    text="Assessment Modes",
    bg="#0F172A",
    fg=MUTED,
    font=("Segoe UI", 9, "bold")
).pack(anchor="w", padx=22, pady=(0, 6))

# ---------- Main Area ----------
main = tk.Frame(shell, bg=BG)
main.pack(side="left", fill="both", expand=True)

# ---------- Header ----------
header = tk.Frame(main, bg=BG)
header.pack(fill="x", padx=28, pady=(22, 14))

left_header = tk.Frame(header, bg=BG)
left_header.pack(side="left", fill="x", expand=True)

tk.Label(
    left_header,
    text="Security Assessment Dashboard",
    bg=BG,
    fg=TEXT,
    font=("Segoe UI", 26, "bold")
).pack(anchor="w")

tk.Label(
    left_header,
    text="Assessment-focused security posture review using the SOCProbe Security Assessment Framework only.",
    bg=BG,
    fg=MUTED,
    font=("Segoe UI", 10)
).pack(anchor="w", pady=(3, 0))

tk.Label(
    left_header,
    text=APP_VERSION,
    bg=BG,
    fg="#64748B",
    font=("Segoe UI", 8)
).pack(anchor="w", pady=(3, 0))

right_header = tk.Frame(header, bg=BG)
right_header.pack(side="right")

def top_button(text, command, color=BLUE):
    return tk.Button(
        right_header,
        text=text,
        command=command,
        bg=color,
        fg="white",
        activebackground=BLUE_2,
        activeforeground="white",
        bd=0,
        padx=14,
        pady=9,
        font=("Segoe UI", 9, "bold")
    )

top_button("Open HTML Report", open_html, SURFACE_3).pack(side="right", padx=(8, 0))
top_button("Open JSON", open_json, SURFACE_3).pack(side="right", padx=(8, 0))

# ---------- Scenario Buttons ----------
scenario_frame = tk.Frame(main, bg=BG)
scenario_frame.pack(fill="x", padx=28, pady=(0, 14))

def scenario_btn(text, scenario, color):
    return tk.Button(
        scenario_frame,
        text=text,
        command=lambda: start_assessment(scenario),
        bg=color,
        fg="white",
        activebackground=CYAN,
        activeforeground="#020617",
        bd=0,
        padx=13,
        pady=8,
        font=("Segoe UI", 9, "bold")
    )

scenario_btn("Run Standard Assessment", "balanced", BLUE).pack(side="left", padx=(0, 8))
scenario_btn("Excellent", "excellent", GREEN).pack(side="left", padx=4)
scenario_btn("Identity Risk", "identity_risk", ORANGE).pack(side="left", padx=4)
scenario_btn("Logging Gap", "logging_gap", ORANGE).pack(side="left", padx=4)
scenario_btn("Privilege Risk", "privilege_risk", RED).pack(side="left", padx=4)
scenario_btn("Cloud Readiness Gap", "cloud_readiness_gap", PURPLE).pack(side="left", padx=4)
scenario_btn("Critical", "critical", "#991B1B").pack(side="left", padx=4)

# ---------- Score Cards ----------
cards = tk.Frame(main, bg=BG)
cards.pack(fill="x", padx=28, pady=(0, 14))

def make_card(parent, title, value, accent, width=220):
    frame = tk.Frame(
        parent,
        bg=SURFACE,
        highlightbackground=BORDER,
        highlightthickness=1,
        padx=18,
        pady=14,
        width=width,
        height=100
    )
    frame.pack_propagate(False)
    frame.pack(side="left", padx=(0, 12))

    tk.Frame(frame, bg=accent, height=4).pack(fill="x", pady=(0, 10))

    tk.Label(
        frame,
        text=title,
        bg=SURFACE,
        fg=MUTED,
        font=("Segoe UI", 8, "bold")
    ).pack(anchor="w")

    label = tk.Label(
        frame,
        text=value,
        bg=SURFACE,
        fg=TEXT,
        font=("Segoe UI", 19, "bold")
    )
    label.pack(anchor="w", pady=(5, 0))
    return label

score_label = make_card(cards, "OVERALL ASSESSMENT SCORE", "-- / 100", CYAN, 285)
grade_label = make_card(cards, "ASSESSMENT GRADE", "--", YELLOW, 210)
readiness_label = make_card(cards, "READINESS LEVEL", "Not assessed", GREEN, 270)
passed_label = make_card(cards, "CONTROLS PASSED", "0 / 0", BLUE, 210)
failed_label = make_card(cards, "CONTROLS FAILED", "0 Failed", RED, 210)

# ---------- Visuals ----------
visuals = tk.Frame(main, bg=BG)
visuals.pack(fill="x", padx=28, pady=(0, 14))

def visual_box(parent, width, height=250):
    frame = tk.Frame(
        parent,
        bg=SURFACE,
        highlightbackground=BORDER,
        highlightthickness=1,
        width=width,
        height=height,
        padx=10,
        pady=10
    )
    frame.pack_propagate(False)
    frame.pack(side="left", padx=(0, 12))
    return frame

gauge_box = visual_box(visuals, 360)
gauge = tk.Canvas(gauge_box, width=335, height=230, bg=SURFACE, highlightthickness=0)
gauge.pack(fill="both", expand=True)

domain_box = visual_box(visuals, 520)
domain_canvas = tk.Canvas(domain_box, width=490, height=230, bg=SURFACE, highlightthickness=0)
domain_canvas.pack(fill="both", expand=True)

method_box = visual_box(visuals, 520)
method_canvas = tk.Canvas(method_box, width=490, height=230, bg=SURFACE, highlightthickness=0)
method_canvas.pack(fill="both", expand=True)

# ---------- Content ----------
content = tk.Frame(main, bg=BG)
content.pack(fill="both", expand=True, padx=28, pady=(0, 14))

left = tk.Frame(content, bg=BG, width=390)
left.pack(side="left", fill="both", padx=(0, 12))
left.pack_propagate(False)

right = tk.Frame(content, bg=BG)
right.pack(side="left", fill="both", expand=True)

summary_frame = tk.Frame(
    left,
    bg=SURFACE,
    highlightbackground=BORDER,
    highlightthickness=1,
    padx=14,
    pady=14
)
summary_frame.pack(fill="both", expand=True)

tk.Label(
    summary_frame,
    text="Executive Assessment Summary",
    bg=SURFACE,
    fg=TEXT,
    font=("Segoe UI", 13, "bold")
).pack(anchor="w")

tk.Label(
    summary_frame,
    text="Plain-language assessment outcome and readiness explanation.",
    bg=SURFACE,
    fg=MUTED,
    font=("Segoe UI", 8)
).pack(anchor="w", pady=(2, 10))

summary_text = tk.Text(
    summary_frame,
    height=20,
    width=42,
    bg="#0F172A",
    fg=TEXT_2,
    insertbackground="white",
    font=("Consolas", 10),
    bd=0,
    wrap="word",
    padx=12,
    pady=12
)
summary_text.pack(fill="both", expand=True)

table_header = tk.Frame(right, bg=BG)
table_header.pack(fill="x", pady=(0, 8))

tk.Label(
    table_header,
    text="SAF Control Assessment Results",
    bg=BG,
    fg=TEXT,
    font=("Segoe UI", 15, "bold")
).pack(side="left")

visible_label = tk.Label(
    table_header,
    text="Showing 0 control(s)",
    bg=BG,
    fg=CYAN,
    font=("Segoe UI", 9, "bold")
)
visible_label.pack(side="right")

table_frame = tk.Frame(
    right,
    bg=SURFACE,
    highlightbackground=BORDER,
    highlightthickness=1
)
table_frame.pack(fill="both", expand=True)

columns = ("Control ID", "Domain", "Control", "Status", "Risk", "Score", "Evidence")
results_table = ttk.Treeview(table_frame, columns=columns, show="headings", height=13)

for col in columns:
    results_table.heading(col, text=col)

results_table.column("Control ID", width=105)
results_table.column("Domain", width=165)
results_table.column("Control", width=240)
results_table.column("Status", width=85)
results_table.column("Risk", width=85)
results_table.column("Score", width=85)
results_table.column("Evidence", width=500)

results_table.tag_configure("pass", background="#052E16", foreground="#DCFCE7")
results_table.tag_configure("fail", background="#450A0A", foreground="#FEE2E2")

results_table.bind("<Double-1>", on_result_click)
results_table.pack(fill="both", expand=True, padx=10, pady=10)

footer = tk.Label(
    main,
    text="SOCProbe SAF v1.1 | Original assessment framework | Designed as an assessment platform, not a monitoring tool",
    bg=BG,
    fg="#64748B",
    font=("Segoe UI", 9)
)
footer.pack(pady=(0, 10))

# Override canvas drawing colors to match enterprise theme
def draw_gauge(score=0):
    gauge.delete("all")
    w,h,cx,cy,r = 335,230,167,180,120
    gauge.create_text(cx, 24, text="Assessment Score", fill=TEXT, font=("Segoe UI", 13, "bold"))
    gauge.create_arc(cx-r, cy-r, cx+r, cy+r, start=180, extent=-45, width=24, style="arc", outline=RED)
    gauge.create_arc(cx-r, cy-r, cx+r, cy+r, start=135, extent=-45, width=24, style="arc", outline=ORANGE)
    gauge.create_arc(cx-r, cy-r, cx+r, cy+r, start=90, extent=-45, width=24, style="arc", outline=YELLOW)
    gauge.create_arc(cx-r, cy-r, cx+r, cy+r, start=45, extent=-45, width=24, style="arc", outline=GREEN)
    import math
    angle = 180 - (score/100)*180
    rad = math.radians(angle)
    x = cx + 95*math.cos(rad)
    y = cy - 95*math.sin(rad)
    gauge.create_line(cx, cy, x, y, fill=TEXT, width=4)
    gauge.create_oval(cx-8, cy-8, cx+8, cy+8, fill=TEXT, outline="")
    gauge.create_text(cx, 110, text=f"{score}/100", fill=score_color(score), font=("Segoe UI", 27, "bold"))
    gauge.create_text(cx, 210, text="Poor     High Risk     Needs Improvement     Excellent", fill=MUTED, font=("Segoe UI", 7))

def draw_domain_bars(report):
    domain_canvas.delete("all")
    domain_canvas.create_text(245, 24, text="Domain Assessment Scores", fill=TEXT, font=("Segoe UI", 13, "bold"))
    y = 58
    for domain, d in report["domain_scores"].items():
        score = d["score"]
        domain_canvas.create_text(15, y+10, text=domain, fill=TEXT_2, font=("Segoe UI", 9, "bold"), anchor="w")
        domain_canvas.create_rectangle(195, y, 430, y+20, fill="#0F172A", outline="")
        domain_canvas.create_rectangle(195, y, 195 + int(score*2.35), y+20, fill=score_color(score), outline="")
        domain_canvas.create_text(445, y+10, text=f"{score}%", fill=TEXT, font=("Segoe UI", 9, "bold"), anchor="w")
        y += 32

def draw_methodology(report):
    method_canvas.delete("all")
    method_canvas.create_text(245, 24, text="SAF Assessment Workflow", fill=TEXT, font=("Segoe UI", 13, "bold"))
    x,y = 35,105
    for i, step in enumerate(report["methodology"]):
        method_canvas.create_oval(x, y-24, x+48, y+24, fill=BLUE, outline=CYAN, width=2)
        method_canvas.create_text(x+24, y, text=str(i+1), fill="white", font=("Segoe UI", 11, "bold"))
        method_canvas.create_text(x+24, y+50, text=step, fill=TEXT_2, font=("Segoe UI", 8, "bold"), width=86)
        if i < len(report["methodology"])-1:
            method_canvas.create_line(x+52, y, x+88, y, fill=MUTED, width=2, arrow=tk.LAST)
        x += 94

start_assessment("balanced")
root.mainloop()
