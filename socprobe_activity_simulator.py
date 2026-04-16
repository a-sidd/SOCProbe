from __future__ import annotations

import os
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

from ldap3 import Connection, NTLM, SIMPLE, Server
from ldap3.core.exceptions import LDAPException

from modules.config_loader import load_config


APP_BG = "#0B1621"
PANEL_BG = "#173149"
SURFACE_BG = "#214761"
TEXT = "#E8F4FF"
MUTED = "#9CB5C9"
ACCENT = "#30C8FF"
SUCCESS = "#59D791"
WARNING = "#F0BB4E"
FAIL = "#FF7182"


def _escape_ps(value: str) -> str:
    return value.replace("'", "''")


def _normalize_username(config: dict, username: str) -> str:
    if "\\" in username or "@" in username:
        return username
    fqdn = config.get("domain", {}).get("fqdn", "")
    if fqdn:
        return f"{fqdn.split('.', 1)[0].upper()}\\{username}"
    return username


class SOCProbeActivitySimulator:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SOCProbe Activity Simulator")
        self.root.geometry("1060x760")
        self.root.minsize(980, 700)
        self.root.configure(bg=APP_BG)

        self.config = load_config()
        self.running = False

        org_name = self.config.get("organization", {}).get("name", "SOCProbe Lab")
        domain_name = self.config.get("domain", {}).get("fqdn", "local domain")

        self.user_var = tk.StringVar(value="demo.user")
        self.password_var = tk.StringVar()
        self.demo_group_var = tk.StringVar(value="VPN Users")
        self.failed_attempts_var = tk.IntVar(value=3)
        self.status_var = tk.StringVar(value="Ready for controlled demo actions")

        self._configure_styles()
        self._build_header(org_name, domain_name)
        self._build_layout()
        self._log("SOCProbe Activity Simulator loaded.", "info")
        self._log("Use this utility only for controlled lab and presentation activity.", "muted")

    def _configure_styles(self) -> None:
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Sim.TFrame", background=APP_BG)
        style.configure("SimCard.TFrame", background=PANEL_BG)
        style.configure("Sim.TLabel", background=APP_BG, foreground=TEXT)
        style.configure("SimMuted.TLabel", background=APP_BG, foreground=MUTED)
        style.configure("SimCard.TLabel", background=PANEL_BG, foreground=TEXT)
        style.configure("Sim.TButton", padding=(10, 8))

    def _build_header(self, org_name: str, domain_name: str) -> None:
        header = tk.Frame(self.root, bg=PANEL_BG, padx=20, pady=16)
        header.pack(fill="x")

        title = tk.Label(
            header,
            text="SOCProbe Activity Simulator",
            font=("Segoe UI Semibold", 22),
            bg=PANEL_BG,
            fg=ACCENT,
        )
        title.pack(anchor="w")

        subtitle = tk.Label(
            header,
            text=(
                "Companion lab utility for generating controlled Active Directory and Windows Security Log activity."
            ),
            font=("Segoe UI", 10),
            bg=PANEL_BG,
            fg=TEXT,
        )
        subtitle.pack(anchor="w", pady=(4, 0))

        metadata = tk.Label(
            header,
            text=f"Organization: {org_name}   |   Domain: {domain_name}   |   Scope: demo-only lab support",
            font=("Segoe UI", 9),
            bg=PANEL_BG,
            fg=MUTED,
        )
        metadata.pack(anchor="w", pady=(6, 0))

        status = tk.Label(
            header,
            textvariable=self.status_var,
            font=("Segoe UI Semibold", 10),
            bg=SURFACE_BG,
            fg=TEXT,
            padx=12,
            pady=6,
        )
        status.pack(anchor="e", pady=(10, 0))

    def _build_layout(self) -> None:
        body = tk.Frame(self.root, bg=APP_BG, padx=18, pady=18)
        body.pack(fill="both", expand=True)
        body.grid_columnconfigure(0, weight=0)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        left = tk.Frame(body, bg=PANEL_BG, padx=16, pady=16)
        left.grid(row=0, column=0, sticky="nsw", padx=(0, 14))

        right = tk.Frame(body, bg=APP_BG)
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_rowconfigure(1, weight=1)
        right.grid_columnconfigure(0, weight=1)

        self._build_inputs(left)
        self._build_actions(right)
        self._build_log(right)

    def _build_inputs(self, parent: tk.Frame) -> None:
        tk.Label(parent, text="Demo Inputs", font=("Segoe UI Semibold", 13), bg=PANEL_BG, fg=TEXT).pack(anchor="w")
        tk.Label(
            parent,
            text="Use test accounts and groups only. Impactful changes require confirmation.",
            font=("Segoe UI", 9),
            bg=PANEL_BG,
            fg=MUTED,
            wraplength=260,
            justify="left",
        ).pack(anchor="w", pady=(4, 12))

        self._labeled_entry(parent, "Target user", self.user_var)
        self._labeled_entry(parent, "Password for logon helper", self.password_var, show="*")
        self._labeled_entry(parent, "Demo group", self.demo_group_var)

        tk.Label(parent, text="Failed logon attempts", font=("Segoe UI", 9), bg=PANEL_BG, fg=TEXT).pack(anchor="w")
        tk.Spinbox(
            parent,
            from_=1,
            to=10,
            textvariable=self.failed_attempts_var,
            width=8,
            bg=SURFACE_BG,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
        ).pack(anchor="w", pady=(4, 14))

        notes = [
            "Failed logon helper performs repeated LDAP binds with an invalid password.",
            "Successful logon helper performs a real LDAP bind using the provided password.",
            "Group-change actions use the local ActiveDirectory PowerShell module.",
        ]
        tk.Label(parent, text="Notes", font=("Segoe UI Semibold", 11), bg=PANEL_BG, fg=TEXT).pack(anchor="w", pady=(10, 6))
        for note in notes:
            tk.Label(parent, text=f"- {note}", font=("Segoe UI", 9), bg=PANEL_BG, fg=MUTED, wraplength=260, justify="left").pack(anchor="w", pady=1)

    def _labeled_entry(self, parent: tk.Frame, label: str, variable: tk.StringVar, show: str | None = None) -> None:
        tk.Label(parent, text=label, font=("Segoe UI", 9), bg=PANEL_BG, fg=TEXT).pack(anchor="w")
        entry = tk.Entry(
            parent,
            textvariable=variable,
            width=34,
            bg=SURFACE_BG,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            show=show or "",
        )
        entry.pack(anchor="w", pady=(4, 10), ipady=5)

    def _build_actions(self, parent: tk.Frame) -> None:
        actions_frame = tk.Frame(parent, bg=APP_BG)
        actions_frame.grid(row=0, column=0, sticky="ew")
        actions_frame.grid_columnconfigure(0, weight=1)
        actions_frame.grid_columnconfigure(1, weight=1)
        actions_frame.grid_columnconfigure(2, weight=1)

        sections = [
            (
                "Logon Activity",
                [
                    ("Generate failed logon attempts", self._run_failed_logon_helper),
                    ("Generate successful logon helper", self._run_successful_logon_helper),
                ],
            ),
            (
                "Account State",
                [
                    ("Disable user", self._disable_user),
                    ("Enable user", self._enable_user),
                ],
            ),
            (
                "Group Membership",
                [
                    ("Add user to VPN/demo group", self._add_to_demo_group),
                    ("Remove user from VPN/demo group", self._remove_from_demo_group),
                    ("Add user to Domain Admins", self._add_to_domain_admins),
                    ("Remove user from Domain Admins", self._remove_from_domain_admins),
                    ("Remove disabled privileged accounts from Domain Admins", self._cleanup_disabled_domain_admins),
                ],
            ),
            (
                "Tools and Shortcuts",
                [
                    ("Open Event Viewer", self._open_event_viewer),
                    ("Open Active Directory Users and Computers", self._open_aduc),
                    ("Launch main SOCProbe app", self._launch_main_app),
                    ("Open reports folder", self._open_reports_folder),
                ],
            ),
        ]

        row = 0
        for title, buttons in sections:
            card = tk.Frame(actions_frame, bg=PANEL_BG, padx=14, pady=14)
            card.grid(row=row // 2, column=row % 2, sticky="nsew", padx=6, pady=6)
            tk.Label(card, text=title, font=("Segoe UI Semibold", 12), bg=PANEL_BG, fg=TEXT).pack(anchor="w", pady=(0, 10))
            for label, handler in buttons:
                ttk.Button(card, text=label, command=handler, style="Sim.TButton").pack(fill="x", pady=4)
            row += 1

    def _build_log(self, parent: tk.Frame) -> None:
        log_card = tk.Frame(parent, bg=PANEL_BG, padx=14, pady=14)
        log_card.grid(row=1, column=0, sticky="nsew", pady=(12, 0))
        log_card.grid_rowconfigure(1, weight=1)
        log_card.grid_columnconfigure(0, weight=1)

        tk.Label(log_card, text="Activity Log", font=("Segoe UI Semibold", 12), bg=PANEL_BG, fg=TEXT).grid(row=0, column=0, sticky="w")
        self.log_text = tk.Text(
            log_card,
            wrap="word",
            bg="#0F2232",
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            font=("Consolas", 10),
        )
        self.log_text.grid(row=1, column=0, sticky="nsew", pady=(10, 0))

    def _set_status(self, text: str) -> None:
        self.status_var.set(text)

    def _log(self, message: str, level: str = "info") -> None:
        color = {"info": ACCENT, "success": SUCCESS, "warn": WARNING, "fail": FAIL, "muted": MUTED}.get(level, TEXT)
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"{message}\n")
        line_start = "end-2l linestart"
        line_end = "end-2l lineend"
        tag_name = f"tag_{self.log_text.index('end-2l').replace('.', '_')}"
        self.log_text.tag_add(tag_name, line_start, line_end)
        self.log_text.tag_config(tag_name, foreground=color)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _run_async(self, title: str, callback, confirm: str | None = None) -> None:
        if self.running:
            messagebox.showinfo("Action in progress", "Wait for the current simulator action to complete.")
            return
        if confirm and not messagebox.askyesno(title, confirm):
            return

        self.running = True
        self._set_status(f"Running: {title}")
        self._log(f"Starting: {title}", "info")

        def worker() -> None:
            try:
                message = callback()
                self.root.after(0, lambda: self._complete_action(title, message, "success"))
            except Exception as exc:  # pragma: no cover - GUI safeguard
                self.root.after(0, lambda: self._complete_action(title, str(exc), "fail"))

        threading.Thread(target=worker, daemon=True).start()

    def _complete_action(self, title: str, message: str, level: str) -> None:
        self.running = False
        self._set_status("Ready for controlled demo actions")
        self._log(f"{title}: {message}", level)
        if level == "success":
            messagebox.showinfo(title, message)
        else:
            messagebox.showerror(title, message)

    def _require_user(self) -> str:
        username = self.user_var.get().strip()
        if not username:
            raise ValueError("Enter a target user before running this action.")
        return username

    def _require_password(self) -> str:
        password = self.password_var.get()
        if not password:
            raise ValueError("Enter a password for the logon helper.")
        return password

    def _ldap_bind(self, username: str, password: str) -> None:
        server = Server(self.config["domain"]["server"], port=self.config["domain"].get("port", 389))
        bind_user = _normalize_username(self.config, username)
        authentication = NTLM if "\\" in bind_user else SIMPLE
        conn = Connection(server, user=bind_user, password=password, authentication=authentication, auto_bind=True)
        conn.unbind()

    def _run_failed_logon_helper(self) -> None:
        user = self._require_user()
        attempts = max(1, int(self.failed_attempts_var.get()))

        def action() -> str:
            failures = 0
            for _ in range(attempts):
                try:
                    self._ldap_bind(user, "IncorrectPassword!123")
                except LDAPException:
                    failures += 1
            if failures == 0:
                raise RuntimeError("No failed LDAP bind attempts were recorded.")
            return f"Submitted {failures} failed LDAP bind attempt(s) for {user}."

        self._run_async(
            "Generate failed logon attempts",
            action,
            confirm=f"Generate {attempts} failed LDAP logon attempt(s) for {user}?",
        )

    def _run_successful_logon_helper(self) -> None:
        user = self._require_user()
        password = self._require_password()

        def action() -> str:
            self._ldap_bind(user, password)
            return f"Successful LDAP bind completed for {user}."

        self._run_async(
            "Generate successful logon helper",
            action,
            confirm=f"Perform a successful LDAP bind for {user} using the supplied password?",
        )

    def _run_powershell(self, script: str) -> str:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if result.returncode != 0:
            error = result.stderr.strip() or result.stdout.strip() or "PowerShell action failed."
            raise RuntimeError(error)
        return result.stdout.strip() or "Action completed."

    def _disable_user(self) -> None:
        user = self._require_user()
        script = f"Import-Module ActiveDirectory; Disable-ADAccount -Identity '{_escape_ps(user)}'; Write-Output 'Disabled {user}.'"
        self._run_async("Disable user", lambda: self._run_powershell(script), confirm=f"Disable user {user}?")

    def _enable_user(self) -> None:
        user = self._require_user()
        script = f"Import-Module ActiveDirectory; Enable-ADAccount -Identity '{_escape_ps(user)}'; Write-Output 'Enabled {user}.'"
        self._run_async("Enable user", lambda: self._run_powershell(script), confirm=f"Enable user {user}?")

    def _add_to_demo_group(self) -> None:
        user = self._require_user()
        group = self.demo_group_var.get().strip() or "VPN Users"
        script = (
            f"Import-Module ActiveDirectory; Add-ADGroupMember -Identity '{_escape_ps(group)}' "
            f"-Members '{_escape_ps(user)}'; Write-Output 'Added {user} to {group}.'"
        )
        self._run_async("Add user to VPN/demo group", lambda: self._run_powershell(script), confirm=f"Add {user} to {group}?")

    def _remove_from_demo_group(self) -> None:
        user = self._require_user()
        group = self.demo_group_var.get().strip() or "VPN Users"
        script = (
            f"Import-Module ActiveDirectory; Remove-ADGroupMember -Identity '{_escape_ps(group)}' "
            f"-Members '{_escape_ps(user)}' -Confirm:$false; Write-Output 'Removed {user} from {group}.'"
        )
        self._run_async("Remove user from VPN/demo group", lambda: self._run_powershell(script), confirm=f"Remove {user} from {group}?")

    def _add_to_domain_admins(self) -> None:
        user = self._require_user()
        script = (
            f"Import-Module ActiveDirectory; Add-ADGroupMember -Identity 'Domain Admins' "
            f"-Members '{_escape_ps(user)}'; Write-Output 'Added {user} to Domain Admins.'"
        )
        self._run_async("Add user to Domain Admins", lambda: self._run_powershell(script), confirm=f"Add {user} to Domain Admins?")

    def _remove_from_domain_admins(self) -> None:
        user = self._require_user()
        script = (
            f"Import-Module ActiveDirectory; Remove-ADGroupMember -Identity 'Domain Admins' "
            f"-Members '{_escape_ps(user)}' -Confirm:$false; Write-Output 'Removed {user} from Domain Admins.'"
        )
        self._run_async("Remove user from Domain Admins", lambda: self._run_powershell(script), confirm=f"Remove {user} from Domain Admins?")

    def _cleanup_disabled_domain_admins(self) -> None:
        script = (
            "Import-Module ActiveDirectory; "
            "$removed = @(); "
            "$members = Get-ADGroupMember -Identity 'Domain Admins' -Recursive | Where-Object {$_.objectClass -eq 'user'}; "
            "foreach ($member in $members) { "
            "  $user = Get-ADUser -Identity $member.SamAccountName -Properties Enabled; "
            "  if (-not $user.Enabled) { "
            "    Remove-ADGroupMember -Identity 'Domain Admins' -Members $user.SamAccountName -Confirm:$false; "
            "    $removed += $user.SamAccountName "
            "  } "
            "} "
            "if ($removed.Count -eq 0) { Write-Output 'No disabled privileged accounts were found in Domain Admins.' } "
            "else { Write-Output ('Removed disabled accounts: ' + ($removed -join ', ')) }"
        )
        self._run_async(
            "Remove disabled privileged accounts from Domain Admins",
            lambda: self._run_powershell(script),
            confirm="Remove every disabled user account currently found in Domain Admins?",
        )

    def _open_event_viewer(self) -> None:
        self._run_async("Open Event Viewer", lambda: self._launch_process(["eventvwr.msc"]))

    def _open_aduc(self) -> None:
        self._run_async("Open Active Directory Users and Computers", lambda: self._launch_process(["dsa.msc"]))

    def _launch_main_app(self) -> None:
        self._run_async("Launch main SOCProbe app", lambda: self._launch_process([sys.executable, str(Path(__file__).with_name("ui.py"))]))

    def _open_reports_folder(self) -> None:
        reports_folder = Path(self.config["output"]["report_path"]).resolve().parent

        def action() -> str:
            os.startfile(reports_folder)
            return f"Opened reports folder: {reports_folder}"

        self._run_async("Open reports folder", action)

    def _launch_process(self, command: list[str]) -> str:
        subprocess.Popen(command)
        return "Application launched."


def launch_activity_simulator() -> None:
    root = tk.Tk()
    SOCProbeActivitySimulator(root)
    root.mainloop()


if __name__ == "__main__":
    launch_activity_simulator()
