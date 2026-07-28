
import json
import tkinter as tk
from tkinter import ttk, messagebox

from database.repository import (
    add_custom_control,
    delete_custom_control,
    duplicate_control,
    get_control,
    list_controls,
    set_control_enabled,
    update_custom_control,
)

COLLECTOR_TYPES = [
    "windows_service",
    "registry_value",
    "event_id",
    "local_group_member_count",
    "powershell_boolean",
]
RISKS = ["Low", "Medium", "High", "Critical"]


class ControlLibraryManager(tk.Toplevel):
    def __init__(self, parent, on_change=None):
        super().__init__(parent)
        self.title("Control Library Manager")
        self.geometry("1250x760")
        self.configure(bg="#0B1120")
        self.on_change = on_change
        self._build()
        self.refresh()

    def _build(self):
        header = tk.Frame(self, bg="#0B1120")
        header.pack(fill="x", padx=20, pady=15)

        tk.Label(
            header,
            text="Control Library Manager",
            bg="#0B1120",
            fg="#F8FAFC",
            font=("Segoe UI", 20, "bold"),
        ).pack(anchor="w")

        tk.Label(
            header,
            text="Add safe custom assessment controls without editing the Python source.",
            bg="#0B1120",
            fg="#94A3B8",
            font=("Segoe UI", 10),
        ).pack(anchor="w")

        actions = tk.Frame(self, bg="#0B1120")
        actions.pack(fill="x", padx=20, pady=(0, 10))

        for text, command, color in [
            ("Add Control", self.add_control, "#2563EB"),
            ("Edit Custom", self.edit_selected, "#1E293B"),
            ("Duplicate", self.duplicate_selected, "#8B5CF6"),
            ("Enable/Disable", self.toggle_selected, "#B45309"),
            ("Delete Custom", self.delete_selected, "#991B1B"),
        ]:
            tk.Button(
                actions,
                text=text,
                command=command,
                bg=color,
                fg="white",
                bd=0,
                padx=12,
                pady=8,
            ).pack(side="left", padx=4)

        columns = (
            "Control ID", "Name", "Domain", "Collector",
            "Weight", "Risk", "Type", "Enabled"
        )
        self.tree = ttk.Treeview(self, columns=columns, show="headings", height=25)
        for col in columns:
            self.tree.heading(col, text=col)
        self.tree.column("Control ID", width=125)
        self.tree.column("Name", width=245)
        self.tree.column("Domain", width=185)
        self.tree.column("Collector", width=180)
        self.tree.column("Weight", width=75)
        self.tree.column("Risk", width=80)
        self.tree.column("Type", width=85)
        self.tree.column("Enabled", width=80)
        self.tree.pack(fill="both", expand=True, padx=20, pady=(0, 20))

    def refresh(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.controls = list_controls(include_disabled=True)
        for control in self.controls:
            self.tree.insert(
                "",
                "end",
                iid=control["control_id"],
                values=(
                    control["control_id"],
                    control["name"],
                    control["domain"],
                    control["collector_type"],
                    control["default_weight"],
                    control["default_risk"],
                    "Built-in" if control["is_builtin"] else "Custom",
                    "Yes" if control["is_enabled"] else "No",
                ),
            )

    def selected(self):
        selected = self.tree.focus()
        return get_control(selected) if selected else None

    def add_control(self):
        ControlEditor(self, on_save=self._add)

    def _add(self, values):
        try:
            add_custom_control(values)
            self.refresh()
            if self.on_change:
                self.on_change()
        except Exception as exc:
            messagebox.showerror("Unable to Add", str(exc), parent=self)

    def edit_selected(self):
        control = self.selected()
        if not control:
            return
        if control["is_builtin"]:
            messagebox.showinfo(
                "Built-in Control",
                "Built-in definitions cannot be edited here. Their weight, risk, thresholds, and enabled state remain configurable per profile.",
                parent=self,
            )
            return
        ControlEditor(self, control=control, on_save=lambda values: self._update(control["control_id"], values))

    def _update(self, control_id, values):
        try:
            update_custom_control(control_id, values)
            self.refresh()
            if self.on_change:
                self.on_change()
        except Exception as exc:
            messagebox.showerror("Unable to Update", str(exc), parent=self)

    def duplicate_selected(self):
        control = self.selected()
        if not control:
            return

        dialog = tk.Toplevel(self)
        dialog.title("Duplicate Control")
        dialog.geometry("420x220")
        dialog.grab_set()

        new_id = tk.StringVar(value=f"{control['control_id']}-COPY")
        new_name = tk.StringVar(value=f"{control['name']} Copy")

        tk.Label(dialog, text="New Control ID").pack(anchor="w", padx=15, pady=(15, 3))
        tk.Entry(dialog, textvariable=new_id, width=45).pack(padx=15)
        tk.Label(dialog, text="New Name").pack(anchor="w", padx=15, pady=(12, 3))
        tk.Entry(dialog, textvariable=new_name, width=45).pack(padx=15)

        def save():
            try:
                duplicate_control(control["control_id"], new_id.get().strip(), new_name.get().strip())
                dialog.destroy()
                self.refresh()
                if self.on_change:
                    self.on_change()
            except Exception as exc:
                messagebox.showerror("Unable to Duplicate", str(exc), parent=dialog)

        tk.Button(dialog, text="Duplicate", command=save).pack(pady=18)

    def toggle_selected(self):
        control = self.selected()
        if not control:
            return
        set_control_enabled(control["control_id"], not control["is_enabled"])
        self.refresh()
        if self.on_change:
            self.on_change()

    def delete_selected(self):
        control = self.selected()
        if not control:
            return
        try:
            delete_custom_control(control["control_id"])
            self.refresh()
            if self.on_change:
                self.on_change()
        except Exception as exc:
            messagebox.showerror("Unable to Delete", str(exc), parent=self)


class ControlEditor(tk.Toplevel):
    def __init__(self, parent, control=None, on_save=None):
        super().__init__(parent)
        self.title("Add Custom Control" if control is None else "Edit Custom Control")
        self.geometry("720x680")
        self.configure(bg="#0B1120")
        self.grab_set()
        self.on_save = on_save
        self.control = control or {}
        self._build()

    def _build(self):
        form = tk.Frame(self, bg="#0B1120")
        form.pack(fill="both", expand=True, padx=20, pady=20)

        self.control_id = tk.StringVar(value=self.control.get("control_id", "SAF-CUSTOM-"))
        self.name = tk.StringVar(value=self.control.get("name", ""))
        self.domain = tk.StringVar(value=self.control.get("domain", "Custom Controls"))
        self.collector_type = tk.StringVar(value=self.control.get("collector_type", COLLECTOR_TYPES[0]))
        self.weight = tk.StringVar(value=str(self.control.get("default_weight", 5)))
        self.risk = tk.StringVar(value=self.control.get("default_risk", "Medium"))
        self.enabled = tk.BooleanVar(value=self.control.get("is_enabled", True))

        config = self.control.get("collector_config", {})
        self.config_text = tk.Text(form, height=8, width=70)
        self.config_text.insert("1.0", json.dumps(config, indent=2))

        self.objective_text = tk.Text(form, height=4, width=70)
        self.objective_text.insert("1.0", self.control.get("objective", ""))

        self.recommendation_text = tk.Text(form, height=4, width=70)
        self.recommendation_text.insert("1.0", self.control.get("recommendation", ""))

        fields = [
            ("Control ID", tk.Entry(form, textvariable=self.control_id, width=45)),
            ("Control Name", tk.Entry(form, textvariable=self.name, width=55)),
            ("Domain", tk.Entry(form, textvariable=self.domain, width=45)),
            ("Collector Type", ttk.Combobox(form, textvariable=self.collector_type, values=COLLECTOR_TYPES, state="readonly", width=35)),
            ("Default Weight", tk.Entry(form, textvariable=self.weight, width=15)),
            ("Default Risk", ttk.Combobox(form, textvariable=self.risk, values=RISKS, state="readonly", width=15)),
        ]

        row = 0
        for label, widget in fields:
            tk.Label(form, text=label, bg="#0B1120", fg="#CBD5E1").grid(row=row, column=0, sticky="nw", pady=7)
            widget.grid(row=row, column=1, sticky="w", padx=10, pady=7)
            row += 1

        tk.Label(form, text="Objective", bg="#0B1120", fg="#CBD5E1").grid(row=row, column=0, sticky="nw", pady=7)
        self.objective_text.grid(row=row, column=1, padx=10, pady=7)
        row += 1

        tk.Label(form, text="Collector Config JSON", bg="#0B1120", fg="#CBD5E1").grid(row=row, column=0, sticky="nw", pady=7)
        self.config_text.grid(row=row, column=1, padx=10, pady=7)
        row += 1

        examples = (
            'windows_service: {"service_name":"Spooler","expected_status":"Stopped"}\n'
            'event_id: {"log_name":"Security","event_id":4625,"minimum_count":1}\n'
            'registry_value: {"path":"HKLM:\\\\...","name":"Value","operator":"equals","expected":1}\n'
            'local_group_member_count: {"group_name":"Administrators","maximum_members":5}\n'
            "powershell_boolean: {\"expression\":\"(Get-Service wuauserv).StartType -ne 'Disabled'\"}"
        )
        tk.Label(form, text=examples, bg="#0B1120", fg="#94A3B8", justify="left", font=("Consolas", 8)).grid(row=row, column=1, sticky="w", padx=10)
        row += 1

        tk.Label(form, text="Recommendation", bg="#0B1120", fg="#CBD5E1").grid(row=row, column=0, sticky="nw", pady=7)
        self.recommendation_text.grid(row=row, column=1, padx=10, pady=7)
        row += 1

        tk.Checkbutton(
            form,
            text="Enabled in Control Library",
            variable=self.enabled,
            bg="#0B1120",
            fg="#CBD5E1",
            selectcolor="#111827",
        ).grid(row=row, column=1, sticky="w", padx=10, pady=8)
        row += 1

        tk.Button(
            form,
            text="Save Control",
            command=self.save,
            bg="#2563EB",
            fg="white",
            bd=0,
            padx=14,
            pady=9,
        ).grid(row=row, column=1, sticky="e", padx=10, pady=15)

    def save(self):
        try:
            collector_config = json.loads(self.config_text.get("1.0", "end").strip() or "{}")
            weight = float(self.weight.get())
            values = {
                "control_id": self.control_id.get().strip(),
                "name": self.name.get().strip(),
                "domain": self.domain.get().strip(),
                "objective": self.objective_text.get("1.0", "end").strip(),
                "collector_type": self.collector_type.get(),
                "collector_config": collector_config,
                "recommendation": self.recommendation_text.get("1.0", "end").strip(),
                "default_weight": weight,
                "default_risk": self.risk.get(),
                "is_enabled": self.enabled.get(),
            }
            if not values["control_id"] or not values["name"]:
                raise ValueError("Control ID and name are required.")
            if self.on_save:
                self.on_save(values)
            self.destroy()
        except Exception as exc:
            messagebox.showerror("Unable to Save", str(exc), parent=self)
