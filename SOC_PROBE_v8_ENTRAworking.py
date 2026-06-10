import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import json
import webbrowser
from datetime import datetime
import os
import urllib.request
import urllib.parse
import urllib.error

APP_VERSION = "SOCProbe UI v6.4 - Polished Professor Demo Dashboard"

REQUIRED_EVENT_IDS = [4624, 4625, 4648, 4720, 4728, 4776]

WEIGHTS = {
    "privileged_group": 25,
    "stale_accounts": 20,
    "log_access": 20,
    "disabled_accounts": 10,
    "failed_logons": 10,
    "event_coverage": 10,
    "audit_policy": 5
}

BRUTE_FORCE_PENALTY = 10
PRIV_CHANGE_PENALTY = 5
SCORE_HISTORY_FILE = "soc_score_history.json"
monitoring_enabled = False

# Groups considered privileged (used to highlight accounts in the Accounts view)
PRIVILEGED_GROUPS = {
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Backup Operators",
    "Account Operators",
    "Server Operators",
}

# Fallback sample accounts shown when there is no live AD connection
# (e.g. running the Professor Demo on a machine that is not domain-joined).
DEMO_ACCOUNTS = [
    {"SamAccountName": "Administrator", "Name": "Administrator", "Enabled": True, "LastLogon": "2026-06-08", "Groups": "Domain Admins; Administrators"},
    {"SamAccountName": "jsmith", "Name": "John Smith", "Enabled": True, "LastLogon": "2026-06-07", "Groups": "Domain Users"},
    {"SamAccountName": "akhan", "Name": "Ayesha Khan", "Enabled": True, "LastLogon": "2026-05-30", "Groups": "Domain Users; HR"},
    {"SamAccountName": "svc_backup", "Name": "Backup Service Account", "Enabled": True, "LastLogon": "2026-06-01", "Groups": "Backup Operators"},
    {"SamAccountName": "demo_stale_user", "Name": "demo_stale_user", "Enabled": True, "LastLogon": "Never", "Groups": "Domain Users"},
    {"SamAccountName": "oldtemp", "Name": "Temporary Contractor", "Enabled": False, "LastLogon": "2025-11-02", "Groups": "Domain Users"},
]


def run_ps(command):
    result = subprocess.run(
        ["powershell", "-Command", command],
        capture_output=True,
        text=True
    )
    return result.stdout.strip()



# =========================
# DEMO / SIMULATION MODE
# Lab use only
# =========================

def demo_create_stale_user():
    try:
        cmd = """
        if (-not (Get-ADUser -Filter "SamAccountName -eq 'demo_stale_user'")) {
            New-ADUser -Name "demo_stale_user" `
            -SamAccountName "demo_stale_user" `
            -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
            -Enabled $true
        }
        """
        run_ps(cmd)
        messagebox.showinfo(
            "Demo Complete",
            "Demo stale user created. Run SOC Assessment again."
        )
    except Exception as e:
        messagebox.showerror("Demo Error", str(e))


def demo_trigger_failed_logons():
    try:
        cmd = """
        for ($i=1; $i -le 6; $i++) {
            net use \\\\localhost\\IPC$ /user:soclab\\demo_stale_user WrongPassword
        }
        """
        run_ps(cmd)
        messagebox.showinfo(
            "Demo Complete",
            "Failed logon activity generated. Run SOC Assessment again."
        )
    except Exception as e:
        messagebox.showerror("Demo Error", str(e))


def demo_add_temp_domain_admin():
    try:
        cmd = """
        if (-not (Get-ADUser -Filter "SamAccountName -eq 'demo_admin_user'")) {
            New-ADUser -Name "demo_admin_user" `
            -SamAccountName "demo_admin_user" `
            -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
            -Enabled $true
        }

        Add-ADGroupMember `
        -Identity "Domain Admins" `
        -Members "demo_admin_user" `
        -ErrorAction SilentlyContinue
        """
        run_ps(cmd)
        messagebox.showinfo(
            "Demo Complete",
            "Demo admin user added to Domain Admins. Run SOC Assessment again."
        )
    except Exception as e:
        messagebox.showerror("Demo Error", str(e))


def demo_reset_environment():
    try:
        cmd = """
        Remove-ADGroupMember `
        -Identity "Domain Admins" `
        -Members "demo_admin_user" `
        -Confirm:$false `
        -ErrorAction SilentlyContinue

        Remove-ADUser `
        -Identity "demo_admin_user" `
        -Confirm:$false `
        -ErrorAction SilentlyContinue

        Remove-ADUser `
        -Identity "demo_stale_user" `
        -Confirm:$false `
        -ErrorAction SilentlyContinue
        """
        run_ps(cmd)
        messagebox.showinfo(
            "Demo Reset Complete",
            "Demo users removed. Run SOC Assessment again."
        )
    except Exception as e:
        messagebox.showerror("Demo Reset Error", str(e))


def get_event_count(event_id):
    output = run_ps(
        f"(Get-WinEvent -FilterHashtable @{{LogName='Security'; ID={event_id}}} -MaxEvents 100).Count"
    )
    try:
        return int(output)
    except:
        return 0


def score_control(result, weight):
    return weight if result else 0


def check_privileged_group():
    output = run_ps("Get-ADGroupMember 'Domain Admins' | Select-Object -ExpandProperty SamAccountName")
    members = [m for m in output.splitlines() if m.strip()]
    return len(members) <= 3, members


def check_stale_accounts():
    output = run_ps("""
    $cutoff = (Get-Date).AddDays(-90)
    Get-ADUser -Filter * -Properties LastLogonDate,Enabled |
    Where-Object {$_.Enabled -eq $true -and ($_.LastLogonDate -eq $null -or $_.LastLogonDate -lt $cutoff)} |
    Select-Object -ExpandProperty SamAccountName
    """)
    stale = [x for x in output.splitlines() if x.strip()]
    return len(stale) == 0, stale


def check_logs():
    output = run_ps("Get-WinEvent -LogName Security -MaxEvents 5")
    return bool(output), None


def check_disabled_accounts():
    output = run_ps("""
    $privGroups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators","Backup Operators")
    foreach ($group in $privGroups) {
        try {
            Get-ADGroupMember $group -Recursive |
            Where-Object {$_.objectClass -eq "user"} |
            ForEach-Object {
                $u = Get-ADUser $_.SamAccountName -Properties Enabled
                if ($u.Enabled -eq $false) { $u.SamAccountName }
            }
        } catch {}
    }
    """)
    disabled = [x for x in output.splitlines() if x.strip()]
    return len(disabled) == 0, disabled


def check_failed_logons():
    count = get_event_count(4625)
    return count > 0, count


def check_event_coverage():
    missing = []
    for eid in REQUIRED_EVENT_IDS:
        if get_event_count(eid) == 0:
            missing.append(eid)
    return len(missing) == 0, missing


def check_audit_policy():
    output = run_ps("auditpol /get /category:*")
    required_terms = ["Logon", "Credential Validation", "User Account Management", "Security Group Management"]
    missing = [term for term in required_terms if term not in output]
    return len(missing) == 0, missing


def detect_bruteforce():
    output = run_ps("""
    Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 100 |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $targetUser = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
        if ($targetUser) { $targetUser }
    }
    """)

    attempts = {}
    for user in output.splitlines():
        user = user.strip()
        if user and user not in ["-", "SYSTEM"]:
            attempts[user] = attempts.get(user, 0) + 1

    return {u: c for u, c in attempts.items() if c >= 5}


def detect_privileged_group_change():
    count = get_event_count(4728)
    return count > 0, count


def get_frameworks(control):
    mappings = {
        "Privileged Group Membership": ["CIS 5.4", "NIST PR.AC-4", "ISO 27001 A.8.2"],
        "Stale Account Detection": ["CIS 5.3", "NIST PR.AC-6", "ISO 27001 A.5.16"],
        "Log Accessibility": ["CISA Logging Made Easy", "NIST DE.CM-1", "CIS 8.2"],
        "Disabled Account Hygiene": ["CIS 6.2", "ISO 27001 A.5.18", "NIST PR.AC-1"],
        "Failed Logon Detection": ["NIST DE.CM-3", "CIS 8.11", "ISO 27001 A.8.5"],
        "Event ID Coverage": ["CISA Logging Made Easy", "CIS 8.5", "NIST DE.AE-2"],
        "Audit Policy Validation": ["NIST DE.AE-2", "CIS 8.5", "ISO 27001 A.8.15"]
    }
    return mappings.get(control, [])


def get_remediation(control):
    remediations = {
        "Privileged Group Membership": "Reduce Domain Admins membership and remove unnecessary privileged access.",
        "Stale Account Detection": "Disable stale accounts first, confirm with HR/manager, then remove after review.",
        "Log Accessibility": "Enable Security log collection and verify Event Viewer permissions.",
        "Disabled Account Hygiene": "Remove disabled accounts from privileged groups immediately.",
        "Failed Logon Detection": "Enable failed logon auditing and test with incorrect password attempts.",
        "Event ID Coverage": "Enable or generate required events: 4624, 4625, 4648, 4720, 4728, and 4776.",
        "Audit Policy Validation": "Enable required audit policies using auditpol and run gpupdate /force.",
        "Brute Force Detection": "Investigate affected accounts, review source workstation/IP, and enforce account lockout policy.",
        "Privileged Group Change Detection": "Review Domain Admins and confirm all privileged group changes were authorized."
    }
    return remediations.get(control, "Review control and remediate according to policy.")


def category_for_control(control):
    if control in ["Privileged Group Membership", "Stale Account Detection", "Disabled Account Hygiene", "Failed Logon Detection", "Brute Force Detection"]:
        return "Account Security"
    if control in ["Log Accessibility", "Event ID Coverage"]:
        return "AD Infrastructure"
    if control in ["Audit Policy Validation"]:
        return "Group Policy Security"
    if control in ["Privileged Group Change Detection"]:
        return "AD Delegation"
    return "Hybrid Security"


def indicator_description(control):
    descriptions = {
        "Privileged Group Membership": "Checks whether highly privileged groups have excessive members.",
        "Stale Account Detection": "Looks for enabled accounts that are stale or have never logged in.",
        "Log Accessibility": "Validates that Windows Security logs can be accessed for monitoring.",
        "Disabled Account Hygiene": "Checks whether disabled accounts still exist in privileged groups.",
        "Failed Logon Detection": "Verifies visibility into failed logon activity using Event ID 4625.",
        "Event ID Coverage": "Checks whether important Windows Security Event IDs are present.",
        "Audit Policy Validation": "Validates that required audit policy categories are enabled.",
        "Brute Force Detection": "Detects repeated failed logons that may indicate password guessing.",
        "Privileged Group Change Detection": "Detects privileged group membership changes using Event ID 4728."
    }
    return descriptions.get(control, "Security indicator generated by SOCProbe.")


def selected_framework_summary():
    frameworks = []
    if framework_nist_var.get():
        frameworks.append("NIST")
    if framework_cis_var.get():
        frameworks.append("CIS")
    if framework_iso_var.get():
        frameworks.append("ISO 27001")
    if framework_mitre_var.get():
        frameworks.append("MITRE ATT&CK")
    return frameworks


def filter_frameworks(frameworks):
    selected = []
    for fw in frameworks:
        fw_upper = fw.upper()
        if framework_nist_var.get() and "NIST" in fw_upper:
            selected.append(fw)
        elif framework_cis_var.get() and "CIS" in fw_upper:
            selected.append(fw)
        elif framework_iso_var.get() and "ISO" in fw_upper:
            selected.append(fw)
    return selected if selected else ["Framework not selected"]


def calculate_soc_maturity(score, findings):
    high = len([f for f in findings if f["severity"] == "High"])
    if score >= 90 and high == 0:
        return "Level 5 - Optimized SOC"
    elif score >= 80:
        return "Level 4 - Managed Detection"
    elif score >= 70:
        return "Level 3 - Detection Capable"
    elif score >= 50:
        return "Level 2 - Basic Monitoring"
    else:
        return "Level 1 - Initial / Limited Visibility"


def ai_explanation(score, tier, maturity, controls, findings):
    high = len([f for f in findings if f["severity"] == "High"])
    failed = len([c for c in controls if c["status"] == "FAIL"])

    return (
        f"SOCProbe assessed the selected environment at {score}/100 with a {tier} rating. "
        f"The maturity level is {maturity}. "
        f"{failed} selected controls failed and {high} high-severity indicators were identified. "
        f"The dashboard combines identity, logging, audit, detection, and framework mapping into a threat-indicator view."
    )


def save_score_history(score, tier):
    history = []
    if os.path.exists(SCORE_HISTORY_FILE):
        try:
            with open(SCORE_HISTORY_FILE, "r") as f:
                history = json.load(f)
        except:
            history = []
    history.append({"time": str(datetime.now()), "score": score, "tier": tier})
    history = history[-10:]
    with open(SCORE_HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=4)
    return history


def selected_scope_summary():
    scope = []
    if scan_ad_var.get():
        scope.append("Active Directory")
    if scan_logs_var.get():
        scope.append("Windows Security Logs")
    if scan_audit_var.get():
        scope.append("Audit Policy")
    if scan_detection_var.get():
        scope.append("Detection Rules")
    return scope


def generate_html_report(report):
    finding_rows = ""
    for f in report["findings"]:
        finding_rows += f"""
        <tr>
            <td>{f["category"]}</td>
            <td>{f["control"]}</td>
            <td>{f["description"]}</td>
            <td>{f["severity"]}</td>
            <td>{", ".join(f["frameworks"])}</td>
            <td>{f.get("mitre_attack", "N/A")}</td>
        </tr>
        """

    html = f"""
    <html>
    <head>
        <title>SOCProbe Purple Report</title>
        <style>
            body {{ background:#19171d; color:#f5f5f5; font-family:Segoe UI, Arial; padding:30px; }}
            .card {{ background:#211d28; border:1px solid #8a2be2; border-radius:18px; padding:22px; margin-bottom:25px; }}
            h1 {{ color:#c084fc; }}
            .score {{ font-size:44px; font-weight:bold; color:#a3e635; }}
            .tier {{ font-size:26px; font-weight:bold; color:#facc15; }}
            table {{ width:100%; border-collapse:collapse; background:#211d28; }}
            th {{ background:linear-gradient(90deg,#4c1d95,#7e22ce); color:white; padding:14px; text-align:left; }}
            td {{ padding:14px; border-bottom:1px solid #3a3543; color:#d1d5db; }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>{APP_VERSION}</h1>
            <p><b>Run Time:</b> {report["run_time"]}</p>
            <p><b>Selected Scope:</b> {", ".join(report["selected_scope"])}</p>
            <p><b>Selected Frameworks:</b> {", ".join(report["selected_frameworks"])}</p>
            <div class="score">{report["score"]}/100</div>
            <div class="tier">{report["risk_tier"]}</div>
            <p><b>SOC Maturity:</b> {report["soc_maturity"]}</p>
        </div>

        <div class="card">
            <h2>Executive Summary</h2>
            <p>{report["ai_style_summary"]}</p>
        </div>

        <div class="card">
            <h2>Threat Indicator Findings</h2>
            <table>
                <tr>
                    <th>Category</th>
                    <th>Indicator Name</th>
                    <th>Description</th>
                    <th>Severity</th>
                    <th>Framework</th>
                    <th>IOE/IOC</th>
                </tr>
                {finding_rows}
            </table>
        </div>
    </body>
    </html>
    """

    with open("soc_report.html", "w", encoding="utf-8") as f:
        f.write(html)


def run_assessment():
    total_score = 0
    findings = []
    controls = []

    checks = []

    if scan_ad_var.get():
        checks.extend([
            ("Privileged Group Membership", "privileged_group", check_privileged_group),
            ("Stale Account Detection", "stale_accounts", check_stale_accounts),
            ("Disabled Account Hygiene", "disabled_accounts", check_disabled_accounts),
        ])

    if scan_logs_var.get():
        checks.extend([
            ("Log Accessibility", "log_access", check_logs),
            ("Failed Logon Detection", "failed_logons", check_failed_logons),
            ("Event ID Coverage", "event_coverage", check_event_coverage),
        ])

    if scan_audit_var.get():
        checks.append(("Audit Policy Validation", "audit_policy", check_audit_policy))

    if not checks:
        messagebox.showwarning("No Scan Selected", "Please select at least one scan scope.")
        return None

    for control_name, weight_key, func in checks:
        result, data = func()
        weight = WEIGHTS[weight_key]
        earned = score_control(result, weight)
        total_score += earned

        controls.append({
            "control": control_name,
            "status": "PASS" if result else "FAIL",
            "earned": earned,
            "weight": weight,
            "data": data
        })

        if not result:
            frameworks = filter_frameworks(get_frameworks(control_name))
            findings.append({
                "category": category_for_control(control_name),
                "control": control_name,
                "description": indicator_description(control_name),
                "severity": "Medium",
                "issue": f"{control_name} failed. Details: {data}",
                "remediation": get_remediation(control_name),
                "frameworks": frameworks,
                "mitre_attack": "IOE"
            })

    possible_score = sum(c["weight"] for c in controls)
    total_score = round((total_score / possible_score) * 100) if possible_score else 0

    if scan_detection_var.get():
        brute_force = detect_bruteforce()
        if brute_force:
            total_score -= BRUTE_FORCE_PENALTY
            findings.append({
                "category": "Account Security",
                "control": "Brute Force Detection",
                "description": "Detects repeated failed logons that may indicate password guessing or credential attack activity.",
                "severity": "High",
                "issue": f"Potential brute force detected: {brute_force}",
                "remediation": get_remediation("Brute Force Detection"),
                "frameworks": filter_frameworks(["NIST DE.CM-3", "CIS 8.11", "ISO 27001 A.8.5"]),
                "mitre_attack": "T1110 - Brute Force" if framework_mitre_var.get() else "Not selected"
            })

        priv_change, count = detect_privileged_group_change()
        if priv_change:
            total_score -= PRIV_CHANGE_PENALTY
            findings.append({
                "category": "AD Delegation",
                "control": "Privileged Group Change Detection",
                "description": "Detects changes to privileged groups that could indicate privilege escalation or administrative misuse.",
                "severity": "High",
                "issue": f"Privileged group change detected. Event ID 4728 count: {count}",
                "remediation": get_remediation("Privileged Group Change Detection"),
                "frameworks": filter_frameworks(["CIS 5.4", "NIST PR.AC-4", "ISO 27001 A.8.2"]),
                "mitre_attack": "T1098 - Account Manipulation" if framework_mitre_var.get() else "Not selected"
            })

    total_score = max(total_score, 0)

    high_count = len([f for f in findings if f["severity"] == "High"])
    if total_score >= 85 and high_count == 0:
        tier = "HIGH READINESS"
    elif total_score >= 70:
        tier = "MODERATE"
    elif total_score >= 50:
        tier = "LOW"
    else:
        tier = "POOR"

    maturity = calculate_soc_maturity(total_score, findings)
    explanation = ai_explanation(total_score, tier, maturity, controls, findings)
    history = save_score_history(total_score, tier)

    report = {
        "tool_name": "SOCProbe Purple Threat Indicator Dashboard",
        "version": APP_VERSION,
        "run_time": str(datetime.now()),
        "selected_scope": selected_scope_summary(),
        "selected_frameworks": selected_framework_summary(),
        "score": total_score,
        "risk_tier": tier,
        "soc_maturity": maturity,
        "controls": controls,
        "findings": findings,
        "score_history": history,
        "ai_style_summary": explanation
    }

    with open("soc_report.json", "w") as f:
        json.dump(report, f, indent=4)

    generate_html_report(report)
    return report


def open_report():
    subprocess.run(["notepad", "soc_report.json"])


def open_html_report():
    webbrowser.open("soc_report.html")


def open_history():
    if os.path.exists(SCORE_HISTORY_FILE):
        subprocess.run(["notepad", SCORE_HISTORY_FILE])
    else:
        messagebox.showinfo("No History", "No score history file exists yet.")


def update_ui(report):
    if report is None:
        return

    score_label.config(text=f"{report['score']} / 100")
    tier_label.config(text=report["risk_tier"])
    maturity_label.config(text=report["soc_maturity"])
    summary_text.delete("1.0", tk.END)
    summary_text.insert(tk.END, report["ai_style_summary"])

    if "demo_scenario" in report:
        scenario_label.config(text=f"Active Scenario: {report['demo_scenario']}")
    else:
        scenario_label.config(text="Active Scenario: Real Scan")

    for item in indicator_table.get_children():
        indicator_table.delete(item)

    for f in report["findings"]:
        tag = f["severity"].lower()
        indicator_table.insert(
            "",
            tk.END,
            values=(
                f["category"],
                f["control"],
                f["description"],
                f["severity"],
                ", ".join(f["frameworks"]),
                f.get("mitre_attack", "N/A")
            ),
            tags=(tag,)
        )

    alert_text.delete("1.0", tk.END)
    high_findings = [f for f in report["findings"] if f["severity"] == "High"]

    if high_findings:
        for f in high_findings:
            alert_text.insert(tk.END, f"ACTIVE ALERT: {f['control']} | {f['issue']} | {f.get('mitre_attack', 'N/A')}\n")
    else:
        alert_text.insert(tk.END, "No active high severity alerts detected.\n")


def start_scan():
    report = run_assessment()
    update_ui(report)
    if report and any(f["severity"] == "High" for f in report["findings"]):
        messagebox.showwarning("High Risk Detected", "High severity indicators detected. Review the indicator table.")


def monitor_loop():
    global monitoring_enabled
    if monitoring_enabled:
        report = run_assessment()
        update_ui(report)
        root.after(15000, monitor_loop)


def start_monitoring():
    global monitoring_enabled
    monitoring_enabled = True
    monitor_status.config(text="Monitoring: ON", fg="#a3e635")
    monitor_loop()


def stop_monitoring():
    global monitoring_enabled
    monitoring_enabled = False
    monitor_status.config(text="Monitoring: OFF", fg="#f87171")


def on_indicator_click(event):
    selected = indicator_table.focus()
    if not selected:
        return

    values = indicator_table.item(selected, "values")
    if not values:
        return

    detail = f"""
Category: {values[0]}
Indicator: {values[1]}
Description: {values[2]}
Severity: {values[3]}
Framework: {values[4]}
IOE/IOC: {values[5]}

Suggested investigation:
- Review related Windows Security events.
- Validate whether the activity was expected.
- Confirm affected account, source machine, and timestamp.
- Apply remediation from the generated executive report.
"""
    messagebox.showinfo("Indicator Drill-Down", detail)



def demo_run_full_scenario():
    try:
        cmd = """
        # Create demo stale user
        if (-not (Get-ADUser -Filter "SamAccountName -eq 'demo_stale_user'")) {
            New-ADUser -Name "demo_stale_user" `
            -SamAccountName "demo_stale_user" `
            -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
            -Enabled $true
        }

        # Create demo admin user
        if (-not (Get-ADUser -Filter "SamAccountName -eq 'demo_admin_user'")) {
            New-ADUser -Name "demo_admin_user" `
            -SamAccountName "demo_admin_user" `
            -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
            -Enabled $true
        }

        # Add demo admin user to Domain Admins
        Add-ADGroupMember `
        -Identity "Domain Admins" `
        -Members "demo_admin_user" `
        -ErrorAction SilentlyContinue

        # Generate failed logons for brute-force demo
        for ($i=1; $i -le 6; $i++) {
            net use \\\\localhost\\IPC$ /user:soclab\\demo_stale_user WrongPassword
        }
        """
        run_ps(cmd)
        messagebox.showinfo(
            "Full Demo Scenario Complete",
            "All demo scenarios were generated:\n\n"
            "- Demo stale user created\n"
            "- Failed logons generated\n"
            "- Demo admin added to Domain Admins\n\n"
            "Now click Run SOC Assessment to view the findings."
        )
    except Exception as e:
        messagebox.showerror("Full Demo Error", str(e))



# =========================
# ACCOUNTS VIEW
# Read-only enumeration of local Active Directory accounts.
# =========================

def get_ad_accounts():
    """Query the local AD for all user accounts (read-only).

    Returns a list of dicts: SamAccountName, Name, Enabled, LastLogon, Groups.
    Returns [] if AD is unavailable or the query fails.
    """
    output = run_ps("""
    try {
        Get-ADUser -Filter * -Properties SamAccountName,Name,Enabled,LastLogonDate,MemberOf |
        Select-Object SamAccountName,
                      Name,
                      Enabled,
                      @{Name='LastLogon';Expression={ if ($_.LastLogonDate) { $_.LastLogonDate.ToString('yyyy-MM-dd') } else { 'Never' } }},
                      @{Name='Groups';Expression={ ($_.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace 'CN=','' }) -join '; ' }} |
        ConvertTo-Json -Depth 3
    } catch {
        Write-Output ''
    }
    """)

    if not output:
        return []

    try:
        data = json.loads(output)
    except Exception:
        return []

    # ConvertTo-Json returns a single object (not a list) when there is one result
    if isinstance(data, dict):
        data = [data]

    return data


def show_accounts_view():
    """Open a window listing Active Directory accounts with filtering and
    privileged/disabled/stale highlighting. Falls back to demo data when no
    live AD connection is available."""
    win = tk.Toplevel(root)
    win.title("Active Directory Accounts")
    win.geometry("1120x700")
    win.configure(bg=BG)
    win.minsize(900, 560)

    # Header
    head = tk.Frame(win, bg=BG)
    head.pack(fill="x", padx=20, pady=(16, 8))
    tk.Label(head, text="Active Directory Accounts", font=("Segoe UI", 18, "bold"), fg=TEXT, bg=BG).pack(side="left")
    source_label = tk.Label(head, text="Loading...", font=("Segoe UI", 9), fg=MUTED, bg=BG)
    source_label.pack(side="right")

    # Summary cards (reuses the existing card() helper for consistent styling)
    summary_bar = tk.Frame(win, bg=BG)
    summary_bar.pack(fill="x", padx=20, pady=(0, 8))
    total_lbl = card(summary_bar, "Total Accounts", "0", PURPLE_SOFT, width=200)
    enabled_lbl = card(summary_bar, "Enabled", "0", GREEN, width=170)
    disabled_lbl = card(summary_bar, "Disabled", "0", RED, width=170)
    priv_lbl = card(summary_bar, "Privileged", "0", YELLOW, width=170)

    # Controls row: filter + buttons
    controls_bar = tk.Frame(win, bg=BG)
    controls_bar.pack(fill="x", padx=20, pady=(0, 8))

    tk.Label(controls_bar, text="Filter:", bg=BG, fg=YELLOW, font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 6))
    search_var = tk.StringVar()
    search_entry = tk.Entry(
        controls_bar, textvariable=search_var, bg=PANEL, fg=TEXT,
        insertbackground="white", font=("Segoe UI", 10), bd=0, width=42
    )
    search_entry.pack(side="left", ipady=4)

    accounts_cache = {"data": []}

    def is_privileged(groups):
        return any(pg in groups for pg in PRIVILEGED_GROUPS)

    def populate(*_):
        for item in tree.get_children():
            tree.delete(item)
        ft = search_var.get().lower().strip()
        total = enabled = disabled = priv = 0
        for acc in accounts_cache["data"]:
            sam = str(acc.get("SamAccountName", "") or "")
            name = str(acc.get("Name", "") or "")
            en = bool(acc.get("Enabled", False))
            last = str(acc.get("LastLogon", "Unknown") or "Unknown")
            groups = str(acc.get("Groups", "") or "")

            if ft and ft not in f"{sam} {name} {groups}".lower():
                continue

            total += 1
            tags = []
            if is_privileged(groups):
                tags.append("privileged")
                priv += 1
            if en:
                enabled += 1
            else:
                tags.append("disabled")
                disabled += 1
            if last == "Never":
                tags.append("stale")

            tree.insert(
                "", tk.END,
                values=(sam, name, "Yes" if en else "No", last, groups),
                tags=tuple(tags)
            )

        total_lbl.config(text=str(total))
        enabled_lbl.config(text=str(enabled))
        disabled_lbl.config(text=str(disabled))
        priv_lbl.config(text=str(priv))

    def load(use_demo=False):
        source_label.config(text="Loading...")
        win.update_idletasks()
        if use_demo:
            accounts_cache["data"] = list(DEMO_ACCOUNTS)
            source_label.config(text="Source: Demo data (manual)")
        else:
            data = get_ad_accounts()
            if not data:
                accounts_cache["data"] = list(DEMO_ACCOUNTS)
                source_label.config(text="Source: Demo data (no live AD / query returned nothing)")
            else:
                accounts_cache["data"] = data
                source_label.config(text="Source: Live Active Directory")
        populate()

    def refresh():
        load(use_demo=False)

    def show_demo():
        load(use_demo=True)

    def account_detail(event):
        sel = tree.focus()
        if not sel:
            return
        v = tree.item(sel, "values")
        if not v:
            return
        privileged = "Yes" if any(pg in str(v[4]) for pg in PRIVILEGED_GROUPS) else "No"
        detail = f"""
SamAccountName : {v[0]}
Display Name   : {v[1]}
Enabled        : {v[2]}
Last Logon     : {v[3]}
Privileged     : {privileged}

Group Memberships:
{v[4] if v[4] else '(none)'}
"""
        messagebox.showinfo("Account Detail", detail)

    tk.Button(
        controls_bar, text="Refresh from AD", command=refresh,
        bg=PURPLE, fg="white", activebackground=PURPLE_SOFT, activeforeground="white",
        font=("Segoe UI", 9, "bold"), padx=12, pady=6, bd=0, cursor="hand2"
    ).pack(side="right", padx=(6, 0))

    tk.Button(
        controls_bar, text="Show Demo Data", command=show_demo,
        bg=PANEL_2, fg="white", activebackground=PURPLE_SOFT, activeforeground="white",
        font=("Segoe UI", 9, "bold"), padx=12, pady=6, bd=0, cursor="hand2"
    ).pack(side="right", padx=(6, 0))

    # Table
    table_wrap = tk.Frame(win, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
    table_wrap.pack(fill="both", expand=True, padx=20, pady=(0, 16))

    acc_style = ttk.Style()
    acc_style.configure("Accounts.Treeview", rowheight=30, background=PANEL,
                        fieldbackground=PANEL, foreground="#e5e7eb", borderwidth=0,
                        font=("Segoe UI", 10))

    cols = ("SamAccountName", "Display Name", "Enabled", "Last Logon", "Groups")
    tree = ttk.Treeview(table_wrap, columns=cols, show="headings", style="Accounts.Treeview")
    for c in cols:
        tree.heading(c, text=c)
    tree.column("SamAccountName", width=180)
    tree.column("Display Name", width=200)
    tree.column("Enabled", width=90, anchor="center")
    tree.column("Last Logon", width=120, anchor="center")
    tree.column("Groups", width=430)

    tree.tag_configure("privileged", background="#3b1022", foreground="#fecaca")
    tree.tag_configure("disabled", background="#1f2937", foreground="#9ca3af")
    tree.tag_configure("stale", background="#2f2a16", foreground="#fef08a")

    vsb = ttk.Scrollbar(table_wrap, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)
    vsb.pack(side="right", fill="y")
    tree.pack(side="left", fill="both", expand=True, padx=8, pady=8)
    tree.bind("<Double-1>", account_detail)

    # Legend
    legend = tk.Label(
        win,
        text="Double-click a row for details   |   Red = privileged group   |   Grey = disabled   |   Yellow = never logged on",
        fg="#9ca3af", bg=BG, font=("Segoe UI", 8)
    )
    legend.pack(pady=(0, 10))

    search_var.trace_add("write", populate)

    # Initial load: try live AD, fall back to demo data automatically
    load(use_demo=False)



# =========================
# ENTRA ID VIEW (Microsoft Graph)
# Reads cloud accounts via the Graph API using OAuth2 client-credentials.
# Standard /users, /groups and /directoryRoles reads are free on Entra ID Free.
# NOTE: user sign-in activity (last logon) requires Entra ID P1 and is NOT read here.
# =========================

ENTRA_CONFIG_FILE = "entra_config.json"

# Directory roles treated as privileged for highlighting purposes
GRAPH_PRIVILEGED_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
    "Security Administrator",
    "User Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Helpdesk Administrator",
}


def load_entra_config():
    if os.path.exists(ENTRA_CONFIG_FILE):
        try:
            with open(ENTRA_CONFIG_FILE) as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def get_entra_token(tenant_id, client_id, client_secret):
    """Client-credentials OAuth2 flow -> app-only access token for Graph."""
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = urllib.parse.urlencode({
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = json.loads(resp.read().decode())
    return body.get("access_token")


def graph_get(url, token):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def get_entra_users(token):
    """Return all users (handles paging). Free-tier safe property set."""
    users = []
    url = ("https://graph.microsoft.com/v1.0/users"
           "?$select=displayName,userPrincipalName,accountEnabled,id,createdDateTime"
           "&$top=100")
    while url:
        data = graph_get(url, token)
        users.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
    return users


def get_entra_privileged_members(token):
    """Map user id -> list of privileged role display names currently assigned.
    Requires Directory.Read.All (or RoleManagement.Read.Directory)."""
    priv_ids = {}
    try:
        roles = graph_get("https://graph.microsoft.com/v1.0/directoryRoles", token).get("value", [])
        for role in roles:
            rid = role.get("id")
            rname = role.get("displayName", "")
            if not rid:
                continue
            try:
                members = graph_get(
                    f"https://graph.microsoft.com/v1.0/directoryRoles/{rid}/members", token
                ).get("value", [])
            except Exception:
                members = []
            for m in members:
                priv_ids.setdefault(m.get("id"), []).append(rname)
    except Exception:
        pass
    return priv_ids


def show_entra_view():
    """Window that authenticates to Microsoft Graph and lists Entra ID users."""
    cfg = load_entra_config()

    win = tk.Toplevel(root)
    win.title("Entra ID - Cloud Accounts (Microsoft Graph)")
    win.geometry("1180x740")
    win.configure(bg=BG)
    win.minsize(960, 620)

    # Header
    head = tk.Frame(win, bg=BG)
    head.pack(fill="x", padx=20, pady=(16, 6))
    tk.Label(head, text="Entra ID Cloud Accounts", font=("Segoe UI", 18, "bold"), fg=TEXT, bg=BG).pack(side="left")
    status_label = tk.Label(head, text="Not connected", font=("Segoe UI", 9), fg=MUTED, bg=BG)
    status_label.pack(side="right")

    # App / credentials config
    cfg_frame = tk.LabelFrame(
        win, text=" Microsoft Graph App (OAuth2 client credentials) ",
        fg=YELLOW, bg=BG, font=("Segoe UI", 9, "bold")
    )
    cfg_frame.pack(fill="x", padx=20, pady=(0, 8))

    def field(label, default="", show=None):
        row = tk.Frame(cfg_frame, bg=BG)
        row.pack(fill="x", padx=8, pady=3)
        tk.Label(row, text=label, width=14, anchor="w", bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(side="left")
        var = tk.StringVar(value=default)
        entry = tk.Entry(row, textvariable=var, bg=PANEL, fg=TEXT, insertbackground="white",
                         font=("Consolas", 9), bd=0, show=show)
        entry.pack(side="left", fill="x", expand=True, ipady=3)
        return var

    tenant_var = field("Tenant ID:", cfg.get("tenant_id", ""))
    client_var = field("Client ID:", cfg.get("client_id", ""))
    secret_var = field("Client Secret:", cfg.get("client_secret", ""), show="*")

    opts_row = tk.Frame(cfg_frame, bg=BG)
    opts_row.pack(fill="x", padx=8, pady=(2, 6))
    save_var = tk.BooleanVar(value=bool(cfg))
    tk.Checkbutton(
        opts_row, text="Save credentials to entra_config.json (add to .gitignore)",
        variable=save_var, bg=BG, fg=TEXT, selectcolor=PANEL_2,
        activebackground=BG, activeforeground=TEXT, font=("Segoe UI", 8)
    ).pack(side="left")

    # Summary cards
    summary_bar = tk.Frame(win, bg=BG)
    summary_bar.pack(fill="x", padx=20, pady=(0, 8))
    total_lbl = card(summary_bar, "Total Users", "0", PURPLE_SOFT, width=200)
    enabled_lbl = card(summary_bar, "Enabled", "0", GREEN, width=170)
    disabled_lbl = card(summary_bar, "Disabled", "0", RED, width=170)
    priv_lbl = card(summary_bar, "Privileged", "0", YELLOW, width=170)

    # Table
    table_wrap = tk.Frame(win, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
    table_wrap.pack(fill="both", expand=True, padx=20, pady=(0, 6))

    entra_style = ttk.Style()
    entra_style.configure("Entra.Treeview", rowheight=30, background=PANEL,
                          fieldbackground=PANEL, foreground="#e5e7eb", borderwidth=0,
                          font=("Segoe UI", 10))

    cols = ("User Principal Name", "Display Name", "Enabled", "Created", "Privileged Roles")
    tree = ttk.Treeview(table_wrap, columns=cols, show="headings", style="Entra.Treeview")
    for c in cols:
        tree.heading(c, text=c)
    tree.column("User Principal Name", width=300)
    tree.column("Display Name", width=200)
    tree.column("Enabled", width=80, anchor="center")
    tree.column("Created", width=110, anchor="center")
    tree.column("Privileged Roles", width=320)

    tree.tag_configure("privileged", background="#3b1022", foreground="#fecaca")
    tree.tag_configure("disabled", background="#1f2937", foreground="#9ca3af")

    vsb = ttk.Scrollbar(table_wrap, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)
    vsb.pack(side="right", fill="y")
    tree.pack(side="left", fill="both", expand=True, padx=8, pady=8)

    note = tk.Label(
        win,
        text=("Reads /users and /directoryRoles via Microsoft Graph (free tier). "
              "Requires the Directory.Read.All application permission + admin consent. "
              "Last sign-in / risky sign-in data requires Entra ID P1."),
        fg="#9ca3af", bg=BG, font=("Segoe UI", 8), wraplength=1120, justify="left"
    )
    note.pack(fill="x", padx=20, pady=(0, 8))

    def fetch():
        tenant = tenant_var.get().strip()
        cid = client_var.get().strip()
        sec = secret_var.get().strip()
        if not (tenant and cid and sec):
            messagebox.showwarning("Missing Config", "Enter Tenant ID, Client ID, and Client Secret.")
            return

        status_label.config(text="Connecting to Microsoft Graph...")
        win.update_idletasks()

        try:
            token = get_entra_token(tenant, cid, sec)
            if not token:
                status_label.config(text="Authentication failed")
                messagebox.showerror("Auth Error", "No access token returned. Check the credentials.")
                return
            users = get_entra_users(token)
            priv = get_entra_privileged_members(token)
        except urllib.error.HTTPError as e:
            try:
                detail = e.read().decode()
            except Exception:
                detail = ""
            status_label.config(text="Graph error")
            messagebox.showerror("Graph Error", f"{e.code} {e.reason}\n\n{detail[:900]}")
            return
        except Exception as e:
            status_label.config(text="Connection error")
            messagebox.showerror("Connection Error", str(e))
            return

        if save_var.get():
            try:
                with open(ENTRA_CONFIG_FILE, "w") as f:
                    json.dump({"tenant_id": tenant, "client_id": cid, "client_secret": sec}, f, indent=2)
            except Exception:
                pass

        for item in tree.get_children():
            tree.delete(item)

        total = enabled = disabled = privc = 0
        for u in users:
            total += 1
            roles = priv.get(u.get("id"), [])
            is_priv = bool(roles)
            en = bool(u.get("accountEnabled", False))
            created = (u.get("createdDateTime") or "")[:10] or "Unknown"

            tags = []
            if is_priv:
                tags.append("privileged")
                privc += 1
            if en:
                enabled += 1
            else:
                tags.append("disabled")
                disabled += 1

            tree.insert(
                "", tk.END,
                values=(
                    u.get("userPrincipalName", ""),
                    u.get("displayName", ""),
                    "Yes" if en else "No",
                    created,
                    "; ".join(roles),
                ),
                tags=tuple(tags)
            )

        total_lbl.config(text=str(total))
        enabled_lbl.config(text=str(enabled))
        disabled_lbl.config(text=str(disabled))
        priv_lbl.config(text=str(privc))
        status_label.config(text=f"Connected - {total} users via Microsoft Graph")

    btns = tk.Frame(win, bg=BG)
    btns.pack(fill="x", padx=20, pady=(0, 14))
    tk.Button(
        btns, text="Connect and Fetch Users", command=fetch,
        bg=PURPLE, fg="white", activebackground=PURPLE_SOFT, activeforeground="white",
        font=("Segoe UI", 9, "bold"), padx=14, pady=7, bd=0, cursor="hand2"
    ).pack(side="left")
    tk.Label(
        btns, text="Red = privileged role   |   Grey = disabled account",
        fg="#9ca3af", bg=BG, font=("Segoe UI", 8)
    ).pack(side="right")


# =========================
# PROFESSOR DEMO MODE
# No AD changes. Uses simulated reports only.
# =========================

def build_demo_report(score, tier, maturity, findings, summary, scenario="Demo Scenario"):
    return {
        "tool_name": "SOCProbe Purple Threat Indicator Dashboard - Demo Mode",
        "version": APP_VERSION,
        "run_time": str(datetime.now()),
        "selected_scope": ["Demo Mode - No AD changes"],
        "selected_frameworks": ["NIST", "CIS", "ISO 27001", "MITRE ATT&CK"],
        "score": score,
        "risk_tier": tier,
        "soc_maturity": maturity,
        "controls": [],
        "findings": findings,
        "score_history": [],
        "ai_style_summary": summary,
        "demo_scenario": scenario
    }


def demo_clean_environment():
    report = build_demo_report(
        95,
        "HIGH READINESS",
        "Level 5 - Optimized SOC",
        [],
        "Demo Scenario: Clean Environment. SOCProbe found no high-severity indicators. Identity, logging, and audit controls appear healthy in this simulated environment.",
        "Clean Environment"
    )
    update_ui(report)


def demo_stale_accounts():
    findings = [
        {
            "category": "Account Security",
            "control": "Stale Account Detection",
            "description": "Simulated finding: enabled accounts have not logged in for more than 90 days.",
            "severity": "Medium",
            "issue": "Demo users stale_user01 and stale_user02 appear inactive.",
            "remediation": "Disable stale accounts first, confirm ownership with HR/manager, then remove after review.",
            "frameworks": ["CIS 5.3", "NIST PR.AC-6", "ISO 27001 A.5.16"],
            "mitre_attack": "IOE"
        }
    ]
    report = build_demo_report(
        78,
        "MODERATE",
        "Level 3 - Detection Capable",
        findings,
        "Demo Scenario: Stale Accounts. The score is reduced because inactive enabled accounts can become unauthorized access points.",
        "Stale Accounts"
    )
    update_ui(report)


def demo_bruteforce_attack():
    findings = [
        {
            "category": "Account Security",
            "control": "Brute Force Detection",
            "description": "Simulated finding: repeated failed logons were detected for one account.",
            "severity": "High",
            "issue": "User demo_user generated 10 failed logons in a short time window.",
            "remediation": "Investigate the account, review source workstation/IP, and enforce account lockout policy.",
            "frameworks": ["NIST DE.CM-3", "CIS 8.11", "ISO 27001 A.8.5"],
            "mitre_attack": "T1110 - Brute Force"
        }
    ]
    report = build_demo_report(
        65,
        "LOW",
        "Level 2 - Basic Monitoring",
        findings,
        "Demo Scenario: Brute Force Attack. SOCProbe lowers the score because active credential attack behavior was detected.",
        "Brute Force Attack"
    )
    update_ui(report)


def demo_privileged_group_change():
    findings = [
        {
            "category": "AD Delegation",
            "control": "Privileged Group Change Detection",
            "description": "Simulated finding: a user was added to a privileged group.",
            "severity": "High",
            "issue": "demo_admin_user was added to Domain Admins.",
            "remediation": "Review Domain Admin membership and confirm whether the change was authorized.",
            "frameworks": ["CIS 5.4", "NIST PR.AC-4", "ISO 27001 A.8.2"],
            "mitre_attack": "T1098 - Account Manipulation"
        }
    ]
    report = build_demo_report(
        68,
        "LOW",
        "Level 2 - Basic Monitoring",
        findings,
        "Demo Scenario: Privileged Group Change. SOCProbe highlights privileged access changes because they may indicate privilege escalation.",
        "Privileged Group Change"
    )
    update_ui(report)


def demo_multiple_risks():
    findings = [
        {
            "category": "Account Security",
            "control": "Stale Account Detection",
            "description": "Simulated finding: enabled accounts have not logged in for more than 90 days.",
            "severity": "Medium",
            "issue": "Multiple stale accounts found.",
            "remediation": "Disable stale accounts and complete ownership review.",
            "frameworks": ["CIS 5.3", "NIST PR.AC-6", "ISO 27001 A.5.16"],
            "mitre_attack": "IOE"
        },
        {
            "category": "Account Security",
            "control": "Brute Force Detection",
            "description": "Simulated finding: repeated failed logons were detected.",
            "severity": "High",
            "issue": "demo_user generated repeated failed logons.",
            "remediation": "Investigate source system and enforce lockout policy.",
            "frameworks": ["NIST DE.CM-3", "CIS 8.11", "ISO 27001 A.8.5"],
            "mitre_attack": "T1110 - Brute Force"
        },
        {
            "category": "AD Delegation",
            "control": "Privileged Group Change Detection",
            "description": "Simulated finding: privileged group membership changed.",
            "severity": "High",
            "issue": "demo_admin_user was added to Domain Admins.",
            "remediation": "Validate authorization and remove unnecessary privileged access.",
            "frameworks": ["CIS 5.4", "NIST PR.AC-4", "ISO 27001 A.8.2"],
            "mitre_attack": "T1098 - Account Manipulation"
        }
    ]
    report = build_demo_report(
        42,
        "POOR",
        "Level 1 - Initial / Limited Visibility",
        findings,
        "Demo Scenario: Multiple Risks. SOCProbe shows how several findings reduce the SOC readiness score and create a higher-risk posture.",
        "Multiple Risks"
    )
    update_ui(report)


def demo_clear_screen():
    report = build_demo_report(
        0,
        "Not scanned",
        "Not scanned",
        [],
        "Demo mode cleared. Click Run SOC Assessment for a real scan or select a demo scenario.",
        "Demo Cleared"
    )
    update_ui(report)


# =========================
# UI
# =========================

root = tk.Tk()
root.title(APP_VERSION)
root.geometry("1500x930")
root.minsize(1250, 820)
root.configure(bg="#121018")

# Theme colours
BG = "#121018"
PANEL = "#1d1826"
PANEL_2 = "#241b33"
PURPLE = "#7e22ce"
PURPLE_DARK = "#4c1d95"
PURPLE_SOFT = "#a855f7"
TEXT = "#f8fafc"
MUTED = "#c4b5fd"
YELLOW = "#facc15"
GREEN = "#a3e635"
RED = "#f87171"
BORDER = "#5b21b6"

style = ttk.Style()
style.theme_use("default")
style.configure(
    "Treeview",
    background=PANEL,
    foreground="#e5e7eb",
    fieldbackground=PANEL,
    rowheight=58,
    borderwidth=0,
    font=("Segoe UI", 10)
)
style.configure(
    "Treeview.Heading",
    background=PURPLE_DARK,
    foreground="white",
    font=("Segoe UI", 10, "bold"),
    padding=10
)
style.map("Treeview", background=[("selected", "#6d28d9")])

# ---------- Header ----------
header = tk.Frame(root, bg=BG)
header.pack(fill="x", padx=28, pady=(18, 10))

title = tk.Label(
    header,
    text="SOCProbe",
    font=("Segoe UI", 30, "bold"),
    fg=TEXT,
    bg=BG
)
title.pack(anchor="w")

subtitle = tk.Label(
    header,
    text="",
    font=("Segoe UI", 11),
    fg=MUTED,
    bg=BG
)
subtitle.pack(anchor="w", pady=(2, 0))

version_label = tk.Label(
    header,
    text=APP_VERSION,
    font=("Segoe UI", 9),
    fg="#9ca3af",
    bg=BG
)
version_label.pack(anchor="w", pady=(2, 0))

# ---------- Navigation Tabs ----------
tabs_frame = tk.Frame(root, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
tabs_frame.pack(fill="x", padx=28, pady=(4, 10))


def make_tab(parent, text, command, active=False):
    """Create a clickable navigation tab. If command is None the tab is
    static (current/home). Adds a simple hover effect for clickable tabs."""
    base_bg = PURPLE if active else PANEL
    lbl = tk.Label(
        parent,
        text=text,
        font=("Segoe UI", 9, "bold"),
        fg="white",
        bg=base_bg,
        padx=18,
        pady=10,
        cursor="hand2" if command else "arrow"
    )
    lbl.pack(side="left", padx=1, pady=1)
    if command:
        lbl.bind("<Button-1>", lambda e: command())
        lbl.bind("<Enter>", lambda e: lbl.config(bg=PURPLE_DARK))
        lbl.bind("<Leave>", lambda e: lbl.config(bg=base_bg))
    return lbl


make_tab(tabs_frame, "Account Security", None, active=True)
make_tab(tabs_frame, "Accounts", show_accounts_view)
make_tab(tabs_frame, "Entra ID", show_entra_view)

# ---------- Options ----------
options_frame = tk.LabelFrame(
    root,
    text=" Scan Scope and Frameworks ",
    fg=MUTED,
    bg=BG,
    font=("Segoe UI", 10, "bold"),
    bd=0,
    labelanchor="nw"
)
options_frame.pack(fill="x", padx=28, pady=(0, 10))

scan_ad_var = tk.BooleanVar(value=True)
scan_logs_var = tk.BooleanVar(value=True)
scan_audit_var = tk.BooleanVar(value=True)
scan_detection_var = tk.BooleanVar(value=True)

framework_nist_var = tk.BooleanVar(value=True)
framework_cis_var = tk.BooleanVar(value=True)
framework_iso_var = tk.BooleanVar(value=True)
framework_mitre_var = tk.BooleanVar(value=True)

def dark_check(parent, text, var):
    return tk.Checkbutton(
        parent,
        text=text,
        variable=var,
        bg=BG,
        fg=TEXT,
        selectcolor=PANEL_2,
        activebackground=BG,
        activeforeground=TEXT,
        font=("Segoe UI", 9)
    )

tk.Label(options_frame, text="Scope:", bg=BG, fg=YELLOW, font=("Segoe UI", 9, "bold")).pack(side="left", padx=(8, 4))
dark_check(options_frame, "Active Directory", scan_ad_var).pack(side="left")
dark_check(options_frame, "Security Logs", scan_logs_var).pack(side="left")
dark_check(options_frame, "Audit Policy", scan_audit_var).pack(side="left")
dark_check(options_frame, "Detection Rules", scan_detection_var).pack(side="left")

tk.Label(options_frame, text="Frameworks:", bg=BG, fg=YELLOW, font=("Segoe UI", 9, "bold")).pack(side="left", padx=(22, 4))
dark_check(options_frame, "NIST", framework_nist_var).pack(side="left")
dark_check(options_frame, "CIS", framework_cis_var).pack(side="left")
dark_check(options_frame, "ISO 27001", framework_iso_var).pack(side="left")
dark_check(options_frame, "MITRE", framework_mitre_var).pack(side="left")

# ---------- KPI Cards ----------
cards_frame = tk.Frame(root, bg=BG)
cards_frame.pack(fill="x", padx=28, pady=(0, 10))

def card(parent, title_text, value_text, accent="#7e22ce", width=260):
    frame = tk.Frame(
        parent,
        bg=PANEL,
        highlightbackground=accent,
        highlightthickness=1,
        padx=18,
        pady=14,
        width=width,
        height=88
    )
    frame.pack_propagate(False)
    tk.Label(frame, text=title_text, fg=MUTED, bg=PANEL, font=("Segoe UI", 9, "bold")).pack(anchor="w")
    label = tk.Label(frame, text=value_text, fg=TEXT, bg=PANEL, font=("Segoe UI", 17, "bold"))
    label.pack(anchor="w", pady=(6, 0))
    frame.pack(side="left", padx=(0, 10))
    return label

score_label = card(cards_frame, "SOC Readiness Score", "-- / 100", GREEN)
tier_label = card(cards_frame, "Risk Tier", "Not scanned", YELLOW)
maturity_label = card(cards_frame, "SOC Maturity", "Not scanned", PURPLE_SOFT, width=360)

# ---------- Action Buttons ----------
button_frame = tk.Frame(root, bg=BG)
button_frame.pack(fill="x", padx=28, pady=(0, 10))

def action_button(parent, text, command, bg=PURPLE, fg="white", width=None):
    return tk.Button(
        parent,
        text=text,
        command=command,
        bg=bg,
        fg=fg,
        activebackground=PURPLE_SOFT,
        activeforeground="white",
        font=("Segoe UI", 9, "bold"),
        padx=12,
        pady=8,
        bd=0,
        width=width
    )

action_button(button_frame, "Run Real SOC Assessment", start_scan, PURPLE).pack(side="left", padx=(0, 6))
action_button(button_frame, "Start Monitoring", start_monitoring, "#15803d").pack(side="left", padx=6)
action_button(button_frame, "Stop Monitoring", stop_monitoring, "#b91c1c").pack(side="left", padx=6)
action_button(button_frame, "Open JSON Report", open_report, PANEL_2).pack(side="left", padx=6)
action_button(button_frame, "Open Executive Report", open_html_report, PANEL_2).pack(side="left", padx=6)
action_button(button_frame, "Open Score History", open_history, PANEL_2).pack(side="left", padx=6)

monitor_status = tk.Label(button_frame, text="Monitoring: OFF", fg=RED, bg=BG, font=("Segoe UI", 10, "bold"))
monitor_status.pack(side="left", padx=16)

# ---------- Professor Demo Panel ----------
demo_frame = tk.LabelFrame(
    root,
    text=" Professor Demo Mode - Simulated Scenarios Only ",
    fg=YELLOW,
    bg=BG,
    font=("Segoe UI", 11, "bold"),
    padx=10,
    pady=8
)
demo_frame.pack(fill="x", padx=28, pady=(0, 10))

scenario_label = tk.Label(
    demo_frame,
    text="Active Scenario: None",
    fg=MUTED,
    bg=BG,
    font=("Segoe UI", 10, "bold")
)
scenario_label.pack(side="left", padx=(0, 14))

def demo_button(text, command, color=PURPLE_DARK):
    return tk.Button(
        demo_frame,
        text=text,
        command=command,
        bg=color,
        fg="white",
        activebackground=PURPLE,
        activeforeground="white",
        font=("Segoe UI", 9, "bold"),
        padx=10,
        pady=7,
        bd=0
    )

demo_button("Clean", demo_clean_environment, "#166534").pack(side="left", padx=4)
demo_button("Stale Accounts", demo_stale_accounts).pack(side="left", padx=4)
demo_button("Brute Force", demo_bruteforce_attack, "#b45309").pack(side="left", padx=4)
demo_button("Privileged Change", demo_privileged_group_change, "#b91c1c").pack(side="left", padx=4)
demo_button("Multiple Risks", demo_multiple_risks, "#7f1d1d").pack(side="left", padx=4)
demo_button("Clear Demo", demo_clear_screen, PANEL_2).pack(side="left", padx=4)

note = tk.Label(
    demo_frame,
    text="No users are created or modified in demo mode.",
    fg="#9ca3af",
    bg=BG,
    font=("Segoe UI", 8)
)
note.pack(side="right", padx=8)

# ---------- Main Content: Left/Right Layout ----------
content = tk.Frame(root, bg=BG)
content.pack(fill="both", expand=True, padx=28, pady=(0, 10))

left_col = tk.Frame(content, bg=BG)
left_col.pack(side="left", fill="both", expand=False, padx=(0, 10))

right_col = tk.Frame(content, bg=BG)
right_col.pack(side="left", fill="both", expand=True)

# Alert panel
alert_frame = tk.LabelFrame(
    left_col,
    text=" Active Alert Panel ",
    fg=MUTED,
    bg=BG,
    font=("Segoe UI", 10, "bold"),
    padx=8,
    pady=8
)
alert_frame.pack(fill="both", expand=False, pady=(0, 10))

alert_text = tk.Text(
    alert_frame,
    height=9,
    width=48,
    bg=PANEL,
    fg=YELLOW,
    insertbackground="white",
    font=("Consolas", 9),
    bd=0,
    wrap="word"
)
alert_text.pack(fill="both", expand=True)
alert_text.insert(tk.END, "No scan has been run yet.\n")

# Executive summary
summary_frame = tk.LabelFrame(
    left_col,
    text=" Executive Summary ",
    fg=MUTED,
    bg=BG,
    font=("Segoe UI", 10, "bold"),
    padx=8,
    pady=8
)
summary_frame.pack(fill="both", expand=True)

summary_text = tk.Text(
    summary_frame,
    height=16,
    width=48,
    bg=PANEL,
    fg="#e5e7eb",
    insertbackground="white",
    font=("Consolas", 9),
    bd=0,
    wrap="word"
)
summary_text.pack(fill="both", expand=True)

# Indicator table
table_header = tk.Frame(right_col, bg=BG)
table_header.pack(fill="x", pady=(0, 6))

tk.Label(
    table_header,
    text="Threat Indicator Findings",
    bg=BG,
    fg=TEXT,
    font=("Segoe UI", 14, "bold")
).pack(side="left")

tk.Label(
    table_header,
    text="Double-click a finding for investigation guidance",
    bg=BG,
    fg="#9ca3af",
    font=("Segoe UI", 9)
).pack(side="right")

table_frame = tk.Frame(right_col, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
table_frame.pack(fill="both", expand=True)

columns = ("Category", "Indicator Name", "Description", "Severity", "Framework", "IOE/IOC")
indicator_table = ttk.Treeview(table_frame, columns=columns, show="headings", height=12)

for col in columns:
    indicator_table.heading(col, text=col)

indicator_table.column("Category", width=150)
indicator_table.column("Indicator Name", width=210)
indicator_table.column("Description", width=510)
indicator_table.column("Severity", width=120)
indicator_table.column("Framework", width=250)
indicator_table.column("IOE/IOC", width=175)

indicator_table.tag_configure("high", background="#3b1022", foreground="#fecaca")
indicator_table.tag_configure("medium", background="#2e163f", foreground="#f5d0fe")
indicator_table.tag_configure("warning", background="#2f2a16", foreground="#fef08a")
indicator_table.tag_configure("informational", background="#111827", foreground="#bfdbfe")

indicator_table.bind("<Double-1>", on_indicator_click)
indicator_table.pack(fill="both", expand=True, padx=8, pady=8)

footer = tk.Label(
    root,
    text="SOCProbe Capstone Prototype | Real scan mode + professor-safe simulation mode | Read-only assessment output",
    fg="#9ca3af",
    bg=BG,
    font=("Segoe UI", 9)
)
footer.pack(pady=(0, 8))

root.mainloop()
