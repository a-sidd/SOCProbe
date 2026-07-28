
import json
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path

from framework.saf_controls import SAF_CONTROLS
from methodology.profile_loader import load_profile, save_profile, validate_profile

RISKS = ["Low", "Medium", "High", "Critical"]


class MethodologySettingsWindow(tk.Toplevel):
    def __init__(self, parent, on_saved=None):
        super().__init__(parent)
        self.title("Assessment Methodology Settings")
        self.geometry("1250x760")
        self.configure(bg="#0B1120")
        self.on_saved = on_saved
        self.profile = load_profile()
        self.control_lookup = {c["id"]: c for c in SAF_CONTROLS}
        self.rows = {}
        self._build()

    def _build(self):
        header = tk.Frame(self, bg="#0B1120")
        header.pack(fill="x", padx=20, pady=15)

        tk.Label(
            header,
            text="Assessment Methodology Settings",
            bg="#0B1120",
            fg="#F8FAFC",
            font=("Segoe UI", 20, "bold"),
        ).pack(anchor="w")

        tk.Label(
            header,
            text="Customize enabled controls, weights, risk levels, thresholds, and grade bands.",
            bg="#0B1120",
            fg="#94A3B8",
            font=("Segoe UI", 10),
        ).pack(anchor="w")

        meta = tk.Frame(self, bg="#111827", padx=12, pady=10)
        meta.pack(fill="x", padx=20, pady=(0, 10))

        tk.Label(meta, text="Profile Name", bg="#111827", fg="#CBD5E1").grid(row=0, column=0, sticky="w")
        self.name_var = tk.StringVar(value=self.profile.get("profile_name", "Custom"))
        tk.Entry(meta, textvariable=self.name_var, width=35).grid(row=0, column=1, padx=8)

        tk.Label(meta, text="Description", bg="#111827", fg="#CBD5E1").grid(row=0, column=2, sticky="w")
        self.desc_var = tk.StringVar(value=self.profile.get("description", ""))
        tk.Entry(meta, textvariable=self.desc_var, width=60).grid(row=0, column=3, padx=8)

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=20, pady=10)

        controls_tab = tk.Frame(notebook, bg="#0B1120")
        grades_tab = tk.Frame(notebook, bg="#0B1120")
        notebook.add(controls_tab, text="Controls")
        notebook.add(grades_tab, text="Grade Bands")

        canvas = tk.Canvas(controls_tab, bg="#0B1120", highlightthickness=0)
        scroll = ttk.Scrollbar(controls_tab, orient="vertical", command=canvas.yview)
        inner = tk.Frame(canvas, bg="#0B1120")
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        headers = ["Enabled", "Control ID", "Control", "Weight", "Risk", "Thresholds (JSON)"]
        for col, text in enumerate(headers):
            tk.Label(
                inner,
                text=text,
                bg="#1E293B",
                fg="#F8FAFC",
                font=("Segoe UI", 9, "bold"),
                padx=8,
                pady=8,
            ).grid(row=0, column=col, sticky="nsew", padx=1, pady=1)

        for row_index, control in enumerate(SAF_CONTROLS, start=1):
            settings = self.profile["controls"].get(control["id"], {})
            enabled = tk.BooleanVar(value=settings.get("enabled", True))
            weight = tk.StringVar(value=str(settings.get("weight", control["weight"])))
            risk = tk.StringVar(value=settings.get("risk", control["risk"]))
            thresholds = tk.StringVar(
                value=json.dumps(settings.get("thresholds", {}), separators=(",", ":"))
            )

            tk.Checkbutton(
                inner,
                variable=enabled,
                bg="#111827",
                selectcolor="#111827",
                activebackground="#111827",
            ).grid(row=row_index, column=0, sticky="nsew", padx=1, pady=1)
            tk.Label(inner, text=control["id"], bg="#111827", fg="#38BDF8", padx=8).grid(row=row_index, column=1, sticky="nsew", padx=1, pady=1)
            tk.Label(inner, text=control["name"], bg="#111827", fg="#CBD5E1", anchor="w", padx=8).grid(row=row_index, column=2, sticky="nsew", padx=1, pady=1)
            tk.Entry(inner, textvariable=weight, width=8).grid(row=row_index, column=3, padx=1, pady=1)
            ttk.Combobox(inner, textvariable=risk, values=RISKS, state="readonly", width=10).grid(row=row_index, column=4, padx=1, pady=1)
            tk.Entry(inner, textvariable=thresholds, width=48).grid(row=row_index, column=5, padx=1, pady=1)

            self.rows[control["id"]] = {
                "enabled": enabled,
                "weight": weight,
                "risk": risk,
                "thresholds": thresholds,
            }

        self.grade_tree = ttk.Treeview(
            grades_tab,
            columns=("Grade", "Minimum", "Label"),
            show="headings",
            height=12,
        )
        for col in ("Grade", "Minimum", "Label"):
            self.grade_tree.heading(col, text=col)
        self.grade_tree.pack(fill="both", expand=True, padx=20, pady=20)

        for band in self.profile.get("grade_bands", []):
            self.grade_tree.insert("", "end", values=(band["grade"], band["minimum"], band["label"]))

        grade_buttons = tk.Frame(grades_tab, bg="#0B1120")
        grade_buttons.pack(fill="x", padx=20, pady=(0, 20))
        tk.Button(grade_buttons, text="Add Band", command=self._add_band, bg="#2563EB", fg="white", bd=0, padx=12, pady=7).pack(side="left", padx=4)
        tk.Button(grade_buttons, text="Edit Selected", command=self._edit_band, bg="#1E293B", fg="white", bd=0, padx=12, pady=7).pack(side="left", padx=4)
        tk.Button(grade_buttons, text="Delete Selected", command=self._delete_band, bg="#991B1B", fg="white", bd=0, padx=12, pady=7).pack(side="left", padx=4)

        footer = tk.Frame(self, bg="#0B1120")
        footer.pack(fill="x", padx=20, pady=12)

        tk.Button(footer, text="Save Active Profile", command=self._save, bg="#2563EB", fg="white", bd=0, padx=14, pady=9).pack(side="right", padx=5)
        tk.Button(footer, text="Save As...", command=self._save_as, bg="#8B5CF6", fg="white", bd=0, padx=14, pady=9).pack(side="right", padx=5)
        tk.Button(footer, text="Load Profile...", command=self._load_file, bg="#1E293B", fg="white", bd=0, padx=14, pady=9).pack(side="right", padx=5)

    def _grade_dialog(self, title, values=None):
        dialog = tk.Toplevel(self)
        dialog.title(title)
        dialog.geometry("360x230")
        dialog.grab_set()

        grade_var = tk.StringVar(value=values[0] if values else "")
        minimum_var = tk.StringVar(value=str(values[1]) if values else "")
        label_var = tk.StringVar(value=values[2] if values else "")

        for i, (label, var) in enumerate([
            ("Grade", grade_var),
            ("Minimum Score", minimum_var),
            ("Label", label_var),
        ]):
            tk.Label(dialog, text=label).grid(row=i, column=0, padx=10, pady=10, sticky="w")
            tk.Entry(dialog, textvariable=var).grid(row=i, column=1, padx=10, pady=10)

        result = {}

        def submit():
            try:
                minimum = float(minimum_var.get())
            except ValueError:
                messagebox.showerror("Invalid", "Minimum score must be numeric.", parent=dialog)
                return
            result.update({"grade": grade_var.get(), "minimum": minimum, "label": label_var.get()})
            dialog.destroy()

        tk.Button(dialog, text="Save", command=submit).grid(row=4, column=0, columnspan=2, pady=15)
        self.wait_window(dialog)
        return result or None

    def _add_band(self):
        result = self._grade_dialog("Add Grade Band")
        if result:
            self.grade_tree.insert("", "end", values=(result["grade"], result["minimum"], result["label"]))

    def _edit_band(self):
        selected = self.grade_tree.focus()
        if not selected:
            return
        values = self.grade_tree.item(selected, "values")
        result = self._grade_dialog("Edit Grade Band", values)
        if result:
            self.grade_tree.item(selected, values=(result["grade"], result["minimum"], result["label"]))

    def _delete_band(self):
        selected = self.grade_tree.focus()
        if selected:
            self.grade_tree.delete(selected)

    def _collect(self):
        controls = {}
        for control_id, row in self.rows.items():
            try:
                weight = float(row["weight"].get())
                thresholds = json.loads(row["thresholds"].get() or "{}")
            except (ValueError, json.JSONDecodeError) as exc:
                raise ValueError(f"Invalid value for {control_id}: {exc}") from exc

            controls[control_id] = {
                "enabled": row["enabled"].get(),
                "weight": weight,
                "risk": row["risk"].get(),
                "thresholds": thresholds,
            }

        bands = []
        for item in self.grade_tree.get_children():
            grade, minimum, label = self.grade_tree.item(item, "values")
            bands.append({
                "grade": grade,
                "minimum": float(minimum),
                "label": label,
            })
        bands.sort(key=lambda x: x["minimum"], reverse=True)

        return {
            "profile_name": self.name_var.get().strip(),
            "description": self.desc_var.get().strip(),
            "version": "1.0",
            "controls": controls,
            "grade_bands": bands,
        }

    def _save(self):
        try:
            profile = self._collect()
            save_profile(profile)
            self.profile = profile
            messagebox.showinfo("Saved", "The active methodology profile was saved.", parent=self)
            if self.on_saved:
                self.on_saved(profile)
        except Exception as exc:
            messagebox.showerror("Unable to Save", str(exc), parent=self)

    def _save_as(self):
        try:
            profile = self._collect()
            path = filedialog.asksaveasfilename(
                parent=self,
                initialdir="profiles",
                defaultextension=".json",
                filetypes=[("JSON Profile", "*.json")],
            )
            if path:
                save_profile(profile, path)
                messagebox.showinfo("Saved", f"Profile saved to:\n{path}", parent=self)
        except Exception as exc:
            messagebox.showerror("Unable to Save", str(exc), parent=self)

    def _load_file(self):
        path = filedialog.askopenfilename(
            parent=self,
            initialdir="profiles",
            filetypes=[("JSON Profile", "*.json")],
        )
        if not path:
            return
        try:
            profile = load_profile(path)
            save_profile(profile)
            messagebox.showinfo(
                "Profile Activated",
                "The selected profile is now active. Reopen settings to edit it.",
                parent=self,
            )
            if self.on_saved:
                self.on_saved(profile)
            self.destroy()
        except Exception as exc:
            messagebox.showerror("Unable to Load", str(exc), parent=self)
