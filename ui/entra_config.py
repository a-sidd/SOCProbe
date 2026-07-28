
import json
import tkinter as tk
from tkinter import messagebox

from collectors.entra_id import CONFIG_FILE, check_entra_connection

BG = "#0B1120"
PANEL = "#111827"
TEXT = "#F8FAFC"
MUTED = "#94A3B8"
ACCENT = "#2563EB"
GREEN = "#22C55E"
RED = "#EF4444"
WARNING = "#FACC15"


class EntraConfigDialog(tk.Toplevel):
    """Prompts for the Entra app registration credentials, then tests the connection."""

    def __init__(self, parent, on_change=None):
        super().__init__(parent)
        self.title("Microsoft Entra Connection")
        self.geometry("540x460")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.on_change = on_change
        self.transient(parent)
        self.grab_set()

        self.tenant_id = tk.StringVar()
        self.client_id = tk.StringVar()
        self.client_secret = tk.StringVar()
        self.show_secret = tk.BooleanVar(value=False)

        self._build()
        self._load_existing()

    def _build(self):
        tk.Label(
            self,
            text="Connect to Microsoft Entra ID",
            bg=BG,
            fg=TEXT,
            font=("Segoe UI", 16, "bold"),
        ).pack(anchor="w", padx=20, pady=(20, 4))

        tk.Label(
            self,
            text=(
                "Enter the app registration credentials SOCProbe should use to\n"
                "authenticate to Microsoft Graph before running Entra controls."
            ),
            bg=BG,
            fg=MUTED,
            justify="left",
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=20, pady=(0, 16))

        form = tk.Frame(self, bg=BG)
        form.pack(fill="x", padx=20)

        def add_field(label_text, variable, show=None):
            tk.Label(
                form,
                text=label_text,
                bg=BG,
                fg="#CBD5E1",
                font=("Segoe UI", 9, "bold"),
            ).pack(anchor="w", pady=(8, 2))
            entry = tk.Entry(
                form,
                textvariable=variable,
                width=54,
                bg=PANEL,
                fg=TEXT,
                insertbackground=TEXT,
                relief="flat",
                show=show or "",
            )
            entry.pack(fill="x", ipady=6)
            return entry

        add_field("Tenant ID", self.tenant_id)
        add_field("Application (Client) ID", self.client_id)
        self.secret_entry = add_field("Client Secret", self.client_secret, show="*")

        tk.Checkbutton(
            form,
            text="Show secret",
            variable=self.show_secret,
            command=self._toggle_secret_visibility,
            bg=BG,
            fg=MUTED,
            selectcolor=PANEL,
            activebackground=BG,
            activeforeground=MUTED,
            bd=0,
            highlightthickness=0,
        ).pack(anchor="w", pady=(4, 0))

        self.status_label = tk.Label(
            self,
            text="",
            bg=BG,
            fg=MUTED,
            wraplength=490,
            justify="left",
            font=("Segoe UI", 9),
        )
        self.status_label.pack(fill="x", padx=20, pady=(16, 0))

        actions = tk.Frame(self, bg=BG)
        actions.pack(fill="x", padx=20, pady=20, side="bottom")

        tk.Button(
            actions,
            text="Test Connection",
            command=self.test_connection,
            bg="#0F766E",
            fg="white",
            bd=0,
            padx=14,
            pady=8,
            cursor="hand2",
        ).pack(side="left")

        tk.Button(
            actions,
            text="Save",
            command=self.save,
            bg=ACCENT,
            fg="white",
            bd=0,
            padx=18,
            pady=8,
            cursor="hand2",
        ).pack(side="right")

        tk.Button(
            actions,
            text="Close",
            command=self.destroy,
            bg="#475569",
            fg="white",
            bd=0,
            padx=14,
            pady=8,
            cursor="hand2",
        ).pack(side="right", padx=8)

    def _toggle_secret_visibility(self):
        self.secret_entry.config(show="" if self.show_secret.get() else "*")

    def _load_existing(self):
        if not CONFIG_FILE.exists():
            return
        try:
            saved = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return

        tenant_id = str(saved.get("tenant_id", ""))
        client_id = str(saved.get("client_id", ""))
        client_secret = str(saved.get("client_secret", ""))

        placeholders = {"YOUR_TENANT_ID", "YOUR_APPLICATION_CLIENT_ID", "YOUR_CLIENT_SECRET_VALUE"}
        self.tenant_id.set("" if tenant_id in placeholders else tenant_id)
        self.client_id.set("" if client_id in placeholders else client_id)
        self.client_secret.set("" if client_secret in placeholders else client_secret)

    def _collect(self):
        tenant_id = self.tenant_id.get().strip()
        client_id = self.client_id.get().strip()
        client_secret = self.client_secret.get().strip()
        if not all([tenant_id, client_id, client_secret]):
            raise ValueError("Tenant ID, Client ID, and Client Secret are all required.")
        return {
            "tenant_id": tenant_id,
            "client_id": client_id,
            "client_secret": client_secret,
        }

    def save(self, show_confirmation=True):
        try:
            config = self._collect()
        except ValueError as exc:
            messagebox.showerror("Missing Information", str(exc), parent=self)
            return False

        try:
            CONFIG_FILE.write_text(json.dumps(config, indent=2), encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("Unable to Save", str(exc), parent=self)
            return False

        if self.on_change:
            self.on_change()

        if show_confirmation:
            messagebox.showinfo(
                "Saved",
                "Entra credentials were saved to entra_config.json.",
                parent=self,
            )
        return True

    def test_connection(self):
        if not self.save(show_confirmation=False):
            return

        self.status_label.config(text="Connecting to Microsoft Graph...", fg=MUTED)
        self.update_idletasks()

        passed, evidence = check_entra_connection()
        if passed is True:
            self.status_label.config(text=f"Connected. {evidence}", fg=GREEN)
        elif passed is False:
            self.status_label.config(text=f"Connection failed. {evidence}", fg=RED)
        else:
            self.status_label.config(text=evidence, fg=WARNING)
