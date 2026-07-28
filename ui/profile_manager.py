
import json
import tkinter as tk
from tkinter import ttk, messagebox

from database.repository import (
    activate_profile,
    create_profile,
    delete_profile,
    get_active_profile,
    list_profiles,
    save_control_settings,
    save_grade_bands,
    update_profile_metadata,
)
from framework.saf_controls import SAF_CONTROLS
from database.repository import list_controls

RISKS = ["Low", "Medium", "High", "Critical"]


class ProfileManager(tk.Toplevel):
    def __init__(self, parent, on_change=None):
        super().__init__(parent)
        self.title("Assessment Methodology Manager")
        self.geometry("1320x800")
        self.configure(bg="#0B1120")
        self.on_change = on_change
        self.control_rows = {}
        self.loaded_profile_id = None
        self.is_dirty = False
        self._loading_profile = False
        self._build()
        self.refresh_profiles()
        self.bind("<Control-s>", lambda event: self.save_changes())
        self.bind("<Control-S>", lambda event: self.save_changes())
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def _build(self):
        header = tk.Frame(self, bg="#0B1120")
        header.pack(fill="x", padx=20, pady=15)

        tk.Label(
            header,
            text="Assessment Methodology Manager",
            bg="#0B1120",
            fg="#F8FAFC",
            font=("Segoe UI", 20, "bold"),
        ).pack(anchor="w")

        tk.Label(
            header,
            text="Profiles, control weights, risks, thresholds, and grades are stored in SQLite.",
            bg="#0B1120",
            fg="#94A3B8",
            font=("Segoe UI", 10),
        ).pack(anchor="w")

        top = tk.Frame(self, bg="#111827", padx=12, pady=10)
        top.pack(fill="x", padx=20, pady=(0, 10))

        tk.Label(top, text="Profile", bg="#111827", fg="#CBD5E1").pack(side="left")
        self.profile_var = tk.StringVar()
        self.profile_combo = ttk.Combobox(top, textvariable=self.profile_var, state="readonly", width=30)
        self.profile_combo.pack(side="left", padx=8)
        self.profile_combo.bind("<<ComboboxSelected>>", lambda e: self.load_selected_profile())

        tk.Button(
            top,
            text="Activate",
            command=self.activate_selected,
            bg="#2563EB",
            fg="white",
            bd=0,
            padx=12,
            pady=7,
        ).pack(side="left", padx=4)

        tk.Button(
            top,
            text="Save",
            command=self.save_changes,
            bg="#7C3AED",
            fg="white",
            bd=0,
            padx=14,
            pady=7,
        ).pack(side="left", padx=4)

        tk.Button(
            top,
            text="New Profile",
            command=self.new_profile,
            bg="#16A34A",
            fg="white",
            bd=0,
            padx=12,
            pady=7,
        ).pack(side="left", padx=4)

        tk.Button(
            top,
            text="Duplicate",
            command=self.duplicate_selected,
            bg="#0F766E",
            fg="white",
            bd=0,
            padx=12,
            pady=7,
        ).pack(side="left", padx=4)

        tk.Button(
            top,
            text="Revert",
            command=self.revert_changes,
            bg="#475569",
            fg="white",
            bd=0,
            padx=12,
            pady=7,
        ).pack(side="left", padx=4)

        tk.Button(
            top,
            text="Delete",
            command=self.delete_selected,
            bg="#991B1B",
            fg="white",
            bd=0,
            padx=12,
            pady=7,
        ).pack(side="left", padx=4)

        self.active_label = tk.Label(
            top,
            text="",
            bg="#111827",
            fg="#38BDF8",
            font=("Segoe UI", 9, "bold"),
        )
        self.active_label.pack(side="right")

        self.dirty_label = tk.Label(
            top,
            text="Saved",
            bg="#111827",
            fg="#22C55E",
            font=("Segoe UI", 9, "bold"),
        )
        self.dirty_label.pack(side="right", padx=(0, 18))

        meta = tk.Frame(self, bg="#0B1120")
        meta.pack(fill="x", padx=20, pady=(0, 10))
        tk.Label(meta, text="Name", bg="#0B1120", fg="#CBD5E1").grid(row=0, column=0, sticky="w")
        self.name_var = tk.StringVar()
        self.name_var.trace_add("write", self.mark_dirty)
        tk.Entry(meta, textvariable=self.name_var, width=35).grid(row=0, column=1, padx=8)
        tk.Label(meta, text="Description", bg="#0B1120", fg="#CBD5E1").grid(row=0, column=2, sticky="w")
        self.desc_var = tk.StringVar()
        self.desc_var.trace_add("write", self.mark_dirty)
        tk.Entry(meta, textvariable=self.desc_var, width=70).grid(row=0, column=3, padx=8)

        bulk_actions = tk.Frame(self, bg="#0B1120")
        bulk_actions.pack(fill="x", padx=20, pady=(0, 4))

        tk.Button(
            bulk_actions,
            text="Enable All Controls",
            command=lambda: self.set_all_controls_enabled(True),
            bg="#15803D",
            fg="white",
            bd=0,
            padx=12,
            pady=6,
            cursor="hand2",
        ).pack(side="left", padx=(0, 6))

        tk.Button(
            bulk_actions,
            text="Disable All Controls",
            command=lambda: self.set_all_controls_enabled(False),
            bg="#B91C1C",
            fg="white",
            bd=0,
            padx=12,
            pady=6,
            cursor="hand2",
        ).pack(side="left")

        tk.Label(
            bulk_actions,
            text="Changes take effect after clicking Save.",
            bg="#0B1120",
            fg="#94A3B8",
            font=("Segoe UI", 8),
        ).pack(side="left", padx=12)

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=20, pady=10)

        controls_tab = tk.Frame(notebook, bg="#0B1120")
        grades_tab = tk.Frame(notebook, bg="#0B1120")
        notebook.add(controls_tab, text="Controls")
        notebook.add(grades_tab, text="Grade Bands")

        canvas = tk.Canvas(controls_tab, bg="#0B1120", highlightthickness=0)
        scrollbar = ttk.Scrollbar(controls_tab, orient="vertical", command=canvas.yview)
        self.controls_inner = tk.Frame(canvas, bg="#0B1120")
        self.controls_inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.controls_inner, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        headers = ["Enabled", "Control ID", "Control", "Weight", "Risk", "Thresholds JSON"]
        for col, title in enumerate(headers):
            tk.Label(self.controls_inner, text=title, bg="#1E293B", fg="#F8FAFC", font=("Segoe UI", 9, "bold"), padx=8, pady=8).grid(row=0, column=col, sticky="nsew", padx=1, pady=1)

        self.library_controls = list_controls(include_disabled=False)
        for row_num, library_control in enumerate(self.library_controls, 1):
            control = {
                "id": library_control["control_id"],
                "name": library_control["name"],
            }
            enabled = tk.BooleanVar()
            weight = tk.StringVar()
            risk = tk.StringVar()
            thresholds = tk.StringVar()

            enabled.trace_add("write", self.mark_dirty)
            weight.trace_add("write", self.mark_dirty)
            risk.trace_add("write", self.mark_dirty)
            thresholds.trace_add("write", self.mark_dirty)

            enabled_checkbox = tk.Checkbutton(
                self.controls_inner,
                variable=enabled,
                onvalue=True,
                offvalue=False,
                command=lambda control_id=control["id"]: self.on_enabled_changed(control_id),
                bg="#111827",
                fg="#F8FAFC",
                selectcolor="#334155",
                activebackground="#111827",
                activeforeground="#F8FAFC",
                highlightthickness=0,
                bd=0,
                relief="flat",
                cursor="hand2",
                takefocus=True,
            )
            enabled_checkbox.grid(
                row=row_num,
                column=0,
                sticky="nsew",
                padx=1,
                pady=1,
                ipadx=10,
                ipady=5,
            )

            # Make the entire Enabled cell clickable, not only the small square.
            enabled_checkbox.bind(
                "<Button-1>",
                lambda event, variable=enabled, control_id=control["id"]: (
                    variable.set(not variable.get()),
                    self.on_enabled_changed(control_id),
                    "break",
                )[-1],
            )
            tk.Label(self.controls_inner, text=control["id"], bg="#111827", fg="#38BDF8", padx=8).grid(row=row_num, column=1, sticky="nsew", padx=1, pady=1)
            tk.Label(self.controls_inner, text=control["name"], bg="#111827", fg="#CBD5E1", anchor="w", padx=8).grid(row=row_num, column=2, sticky="nsew", padx=1, pady=1)
            tk.Entry(self.controls_inner, textvariable=weight, width=8).grid(row=row_num, column=3, padx=1, pady=1)
            ttk.Combobox(self.controls_inner, textvariable=risk, values=RISKS, state="readonly", width=10).grid(row=row_num, column=4, padx=1, pady=1)
            tk.Entry(self.controls_inner, textvariable=thresholds, width=50).grid(row=row_num, column=5, padx=1, pady=1)

            self.control_rows[control["id"]] = {
                "enabled": enabled,
                "weight": weight,
                "risk": risk,
                "thresholds": thresholds,
            }

        self.grade_tree = ttk.Treeview(grades_tab, columns=("Grade", "Minimum", "Label"), show="headings", height=14)
        for column in ("Grade", "Minimum", "Label"):
            self.grade_tree.heading(column, text=column)
        self.grade_tree.pack(fill="both", expand=True, padx=20, pady=20)

        grade_actions = tk.Frame(grades_tab, bg="#0B1120")
        grade_actions.pack(fill="x", padx=20, pady=(0, 20))
        tk.Button(grade_actions, text="Add Band", command=self.add_band, bg="#2563EB", fg="white", bd=0, padx=12, pady=7).pack(side="left", padx=4)
        tk.Button(grade_actions, text="Edit", command=self.edit_band, bg="#1E293B", fg="white", bd=0, padx=12, pady=7).pack(side="left", padx=4)
        tk.Button(grade_actions, text="Delete", command=self.delete_band, bg="#991B1B", fg="white", bd=0, padx=12, pady=7).pack(side="left", padx=4)

        footer = tk.Frame(self, bg="#0B1120")
        footer.pack(fill="x", padx=20, pady=12)

        tk.Label(
            footer,
            text="Ctrl+S saves the selected methodology profile.",
            bg="#0B1120",
            fg="#94A3B8",
            font=("Segoe UI", 8),
        ).pack(side="left")

        tk.Button(
            footer,
            text="Save Changes",
            command=self.save_changes,
            bg="#2563EB",
            fg="white",
            bd=0,
            padx=16,
            pady=9,
        ).pack(side="right")

    def refresh_profiles(self):
        self.profiles = list_profiles()
        names = [p["name"] for p in self.profiles]
        self.profile_combo["values"] = names

        active = next((p for p in self.profiles if p["is_active"]), self.profiles[0] if self.profiles else None)
        if active:
            self.profile_var.set(active["name"])
            self.active_label.config(text=f"Active: {active['name']}")
            self.load_selected_profile()

    def selected_profile(self):
        return next((p for p in self.profiles if p["name"] == self.profile_var.get()), None)

    def load_selected_profile(self):
        selected = self.selected_profile()
        if not selected:
            return

        if self.is_dirty and self.loaded_profile_id is not None:
            choice = messagebox.askyesnocancel(
                "Unsaved Changes",
                "Save changes before opening another profile?",
                parent=self,
            )
            if choice is None:
                current = next(
                    (p for p in self.profiles if p["id"] == self.loaded_profile_id),
                    None,
                )
                if current:
                    self.profile_var.set(current["name"])
                return
            if choice:
                if not self.save_changes(show_confirmation=False):
                    return

        self._loading_profile = True
        current_active = get_active_profile()
        # temporarily activate selected for loading, then restore if needed
        original_id = current_active["id"]
        if selected["id"] != original_id:
            activate_profile(selected["id"])
        profile = get_active_profile()
        if selected["id"] != original_id:
            activate_profile(original_id)

        self.loaded_profile_id = selected["id"]
        self.name_var.set(profile["profile_name"])
        self.desc_var.set(profile.get("description", ""))

        for control_id, row in self.control_rows.items():
            settings = profile["controls"].get(control_id, {})
            row["enabled"].set(settings.get("enabled", True))
            row["weight"].set(str(settings.get("weight", 0)))
            row["risk"].set(settings.get("risk", "Medium"))
            row["thresholds"].set(json.dumps(settings.get("thresholds", {}), separators=(",", ":")))

        for item in self.grade_tree.get_children():
            self.grade_tree.delete(item)
        for band in profile["grade_bands"]:
            self.grade_tree.insert(
                "",
                "end",
                values=(band["grade"], band["minimum"], band["label"]),
            )

        self._loading_profile = False
        self.set_clean()

    def activate_selected(self):
        selected = self.selected_profile()
        if selected:
            activate_profile(selected["id"])
            self.refresh_profiles()
            if self.on_change:
                self.on_change()
            messagebox.showinfo("Activated", f"{selected['name']} is now active.", parent=self)

    def new_profile(self):
        dialog = tk.Toplevel(self)
        dialog.title("New Profile")
        dialog.geometry("400x220")
        dialog.grab_set()

        name = tk.StringVar()
        description = tk.StringVar()
        tk.Label(dialog, text="Profile Name").pack(anchor="w", padx=15, pady=(15, 3))
        tk.Entry(dialog, textvariable=name, width=45).pack(padx=15)
        tk.Label(dialog, text="Description").pack(anchor="w", padx=15, pady=(12, 3))
        tk.Entry(dialog, textvariable=description, width=45).pack(padx=15)

        def create():
            try:
                library = list_controls(include_disabled=False)
                definitions = [
                    {
                        "id": item["control_id"],
                        "weight": item["default_weight"],
                        "risk": item["default_risk"],
                    }
                    for item in library
                ]
                create_profile(name.get().strip(), description.get().strip(), definitions)
                dialog.destroy()
                self.refresh_profiles()
            except Exception as exc:
                messagebox.showerror("Unable to Create", str(exc), parent=dialog)

        tk.Button(dialog, text="Create", command=create).pack(pady=18)

    def duplicate_selected(self):
        selected = self.selected_profile()
        if not selected:
            return

        dialog = tk.Toplevel(self)
        dialog.title("Duplicate Profile")
        dialog.geometry("430x230")
        dialog.configure(bg="#0B1120")
        dialog.transient(self)
        dialog.grab_set()

        name = tk.StringVar(value=f"{selected['name']} Copy")
        description = tk.StringVar(value=self.desc_var.get().strip())

        tk.Label(
            dialog,
            text="New Profile Name",
            bg="#0B1120",
            fg="#CBD5E1",
        ).pack(anchor="w", padx=18, pady=(18, 4))
        tk.Entry(dialog, textvariable=name, width=48).pack(padx=18)

        tk.Label(
            dialog,
            text="Description",
            bg="#0B1120",
            fg="#CBD5E1",
        ).pack(anchor="w", padx=18, pady=(12, 4))
        tk.Entry(dialog, textvariable=description, width=48).pack(padx=18)

        def create_copy():
            try:
                new_name = name.get().strip()
                if not new_name:
                    raise ValueError("Profile name cannot be empty.")

                definitions = []
                settings = self.collect_control_settings()
                for control_id, value in settings.items():
                    definitions.append({
                        "id": control_id,
                        "weight": value["weight"],
                        "risk": value["risk"],
                    })

                new_id = create_profile(
                    new_name,
                    description.get().strip(),
                    definitions,
                )

                save_control_settings(new_id, settings)
                save_grade_bands(new_id, self.collect_grades())

                dialog.destroy()
                self.refresh_profiles()
                self.profile_var.set(new_name)
                self.load_selected_profile()
                messagebox.showinfo(
                    "Profile Duplicated",
                    f'"{new_name}" was created successfully.',
                    parent=self,
                )
            except Exception as exc:
                messagebox.showerror(
                    "Unable to Duplicate",
                    str(exc),
                    parent=dialog,
                )

        tk.Button(
            dialog,
            text="Create Duplicate",
            command=create_copy,
            bg="#0F766E",
            fg="white",
            bd=0,
            padx=15,
            pady=8,
        ).pack(pady=20)

    def revert_changes(self):
        if self.loaded_profile_id is None:
            return

        if self.is_dirty:
            confirm = messagebox.askyesno(
                "Revert Changes",
                "Discard all unsaved changes to this profile?",
                parent=self,
            )
            if not confirm:
                return

        self.is_dirty = False
        self.load_selected_profile()

    def delete_selected(self):
        selected = self.selected_profile()
        if not selected:
            return
        try:
            delete_profile(selected["id"])
            self.refresh_profiles()
        except Exception as exc:
            messagebox.showerror("Unable to Delete", str(exc), parent=self)

    def on_enabled_changed(self, control_id):
        """Record enabled/disabled changes made in the controls table."""
        if self._loading_profile:
            return

        row = self.control_rows.get(control_id)
        if row is None:
            return

        self.mark_dirty()

    def set_all_controls_enabled(self, enabled):
        """Enable or disable all controls currently displayed."""
        self._loading_profile = True
        try:
            for row in self.control_rows.values():
                row["enabled"].set(bool(enabled))
        finally:
            self._loading_profile = False

        self.mark_dirty()

    def collect_control_settings(self):
        values = {}
        for control_id, row in self.control_rows.items():
            try:
                thresholds = json.loads(row["thresholds"].get() or "{}")
                weight = float(row["weight"].get())
            except (ValueError, json.JSONDecodeError) as exc:
                raise ValueError(f"Invalid values for {control_id}: {exc}") from exc

            values[control_id] = {
                "enabled": row["enabled"].get(),
                "weight": weight,
                "risk": row["risk"].get(),
                "thresholds": thresholds,
            }
        return values

    def collect_grades(self):
        bands = []
        for item in self.grade_tree.get_children():
            grade, minimum, label = self.grade_tree.item(item, "values")
            bands.append({"grade": grade, "minimum": float(minimum), "label": label})
        return sorted(bands, key=lambda x: x["minimum"], reverse=True)

    def save_changes(self, show_confirmation=True):
        try:
            if self.loaded_profile_id is None:
                raise ValueError("No profile is currently selected.")

            profile_name = self.name_var.get().strip()
            if not profile_name:
                raise ValueError("Profile name cannot be empty.")

            update_profile_metadata(
                self.loaded_profile_id,
                profile_name,
                self.desc_var.get().strip(),
            )
            save_control_settings(
                self.loaded_profile_id,
                self.collect_control_settings(),
            )
            save_grade_bands(
                self.loaded_profile_id,
                self.collect_grades(),
            )

            self.set_clean()
            self.refresh_profiles()
            self.profile_var.set(profile_name)

            if self.on_change:
                self.on_change()

            if show_confirmation:
                messagebox.showinfo(
                    "Saved",
                    "Methodology changes were saved to SQLite.",
                    parent=self,
                )
            return True
        except Exception as exc:
            messagebox.showerror(
                "Unable to Save",
                str(exc),
                parent=self,
            )
            return False

    def mark_dirty(self, *args):
        if self._loading_profile:
            return
        self.is_dirty = True
        if hasattr(self, "dirty_label"):
            self.dirty_label.config(
                text="● Unsaved Changes",
                fg="#FACC15",
            )

    def set_clean(self):
        self.is_dirty = False
        if hasattr(self, "dirty_label"):
            self.dirty_label.config(
                text="Saved",
                fg="#22C55E",
            )

    def on_close(self):
        if self.is_dirty:
            choice = messagebox.askyesnocancel(
                "Unsaved Changes",
                "Save your methodology changes before closing?",
                parent=self,
            )
            if choice is None:
                return
            if choice and not self.save_changes(show_confirmation=False):
                return
        self.destroy()

    def band_dialog(self, title, values=None):
        dialog = tk.Toplevel(self)
        dialog.title(title)
        dialog.geometry("350x230")
        dialog.grab_set()

        grade = tk.StringVar(value=values[0] if values else "")
        minimum = tk.StringVar(value=str(values[1]) if values else "")
        label = tk.StringVar(value=values[2] if values else "")

        for text, variable in [("Grade", grade), ("Minimum", minimum), ("Label", label)]:
            tk.Label(dialog, text=text).pack(anchor="w", padx=15, pady=(10, 2))
            tk.Entry(dialog, textvariable=variable).pack(fill="x", padx=15)

        result = {}

        def save():
            try:
                result.update({
                    "grade": grade.get(),
                    "minimum": float(minimum.get()),
                    "label": label.get(),
                })
                dialog.destroy()
            except ValueError:
                messagebox.showerror("Invalid", "Minimum must be numeric.", parent=dialog)

        tk.Button(dialog, text="Save", command=save).pack(pady=15)
        self.wait_window(dialog)
        return result or None

    def add_band(self):
        result = self.band_dialog("Add Grade Band")
        if result:
            self.grade_tree.insert(
                "",
                "end",
                values=(result["grade"], result["minimum"], result["label"]),
            )
            self.mark_dirty()

    def edit_band(self):
        selected = self.grade_tree.focus()
        if not selected:
            return
        values = self.grade_tree.item(selected, "values")
        result = self.band_dialog("Edit Grade Band", values)
        if result:
            self.grade_tree.item(
                selected,
                values=(result["grade"], result["minimum"], result["label"]),
            )
            self.mark_dirty()

    def delete_band(self):
        selected = self.grade_tree.focus()
        if selected:
            self.grade_tree.delete(selected)
            self.mark_dirty()
