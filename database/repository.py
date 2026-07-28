
import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Any

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "socprobe.db"


def connect():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database(controls):
    with connect() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL DEFAULT '',
            is_active INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS controls (
            control_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            domain TEXT NOT NULL,
            objective TEXT NOT NULL DEFAULT '',
            collector_type TEXT NOT NULL,
            collector_config_json TEXT NOT NULL DEFAULT '{}',
            recommendation TEXT NOT NULL DEFAULT '',
            default_weight REAL NOT NULL DEFAULT 0,
            default_risk TEXT NOT NULL DEFAULT 'Medium',
            is_builtin INTEGER NOT NULL DEFAULT 0,
            is_enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS profile_controls (
            profile_id INTEGER NOT NULL,
            control_id TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            weight REAL NOT NULL DEFAULT 0,
            risk TEXT NOT NULL DEFAULT 'Medium',
            thresholds_json TEXT NOT NULL DEFAULT '{}',
            PRIMARY KEY (profile_id, control_id),
            FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE,
            FOREIGN KEY (control_id) REFERENCES controls(control_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS grade_bands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_id INTEGER NOT NULL,
            grade TEXT NOT NULL,
            minimum REAL NOT NULL,
            label TEXT NOT NULL,
            FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS assessment_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_name TEXT NOT NULL,
            mode TEXT NOT NULL,
            score REAL NOT NULL,
            grade TEXT NOT NULL,
            readiness TEXT NOT NULL,
            report_json TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """)

        for control in controls:
            conn.execute("""
                INSERT OR IGNORE INTO controls
                (control_id, name, domain, objective, collector_type,
                 collector_config_json, recommendation, default_weight,
                 default_risk, is_builtin, is_enabled)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1)
            """, (
                control["id"],
                control["name"],
                control["domain"],
                control.get("objective", ""),
                "builtin",
                json.dumps({"collector": control.get("collector", "")}),
                control.get("recommendation", ""),
                control.get("weight", 0),
                control.get("risk", "Medium"),
            ))

        existing = conn.execute("SELECT COUNT(*) AS count FROM profiles").fetchone()["count"]
        if existing == 0:
            profile_id = create_profile_in_connection(
                conn,
                "SOCProbe Default",
                "Default SOCProbe methodology.",
                controls,
                active=True,
            )
            create_profile_in_connection(
                conn,
                "Small Business",
                "Stronger emphasis on firewall, Defender, passwords, and administrator access.",
                controls,
                active=False,
                high_priority_ids={
                    "SAF-LW-01", "SAF-LW-02", "SAF-LW-07",
                    "SAF-LW-08", "SAF-LW-12"
                },
            )

        # Add all control-library items to every profile
        profile_rows = conn.execute("SELECT id FROM profiles").fetchall()
        control_rows = conn.execute("""
            SELECT control_id, default_weight, default_risk
            FROM controls WHERE is_enabled = 1
        """).fetchall()
        for profile in profile_rows:
            for control in control_rows:
                conn.execute("""
                    INSERT OR IGNORE INTO profile_controls
                    (profile_id, control_id, enabled, weight, risk, thresholds_json)
                    VALUES (?, ?, 1, ?, ?, ?)
                """, (
                    profile["id"],
                    control["control_id"],
                    control["default_weight"],
                    control["default_risk"],
                    json.dumps(default_thresholds(control["control_id"])),
                ))


def default_thresholds(control_id):
    values = {
        "SAF-LW-04": {"minimum_log_size_mb": 64},
        "SAF-LW-07": {"minimum_password_length": 8},
        "SAF-LW-08": {"maximum_lockout_threshold": 10, "must_be_enabled": True},
        "SAF-LW-12": {"maximum_local_admins": 5},
        "SAF-AD-03": {"maximum_domain_admins": 3},
        "SAF-AD-04": {"maximum_enterprise_admins": 2},
        "SAF-AD-05": {"stale_days": 90, "maximum_stale_users": 0},
        "SAF-AD-07": {"maximum_password_never_expires": 3},
        "SAF-AD-08": {"maximum_spn_accounts": 5},
        "SAF-EN-03": {"minimum_global_admins": 1, "maximum_global_admins": 5},
        "SAF-EN-04": {"maximum_guest_percentage": 10},
        "SAF-EN-05": {"maximum_disabled_percentage": 5},
        "SAF-EN-06": {"minimum_mfa_percentage": 90, "minimum_admin_mfa_percentage": 100},
        "SAF-EN-07": {"minimum_enabled_policies": 1},
    }
    return values.get(control_id, {})


def create_profile_in_connection(conn, name, description, controls, active=False, high_priority_ids=None):
    if active:
        conn.execute("UPDATE profiles SET is_active = 0")

    cursor = conn.execute(
        "INSERT INTO profiles (name, description, is_active) VALUES (?, ?, ?)",
        (name, description, 1 if active else 0),
    )
    profile_id = cursor.lastrowid
    high_priority_ids = high_priority_ids or set()

    for control in controls:
        weight = 15 if control["id"] in high_priority_ids else control.get("weight", 0)
        conn.execute("""
            INSERT INTO profile_controls
            (profile_id, control_id, enabled, weight, risk, thresholds_json)
            VALUES (?, ?, 1, ?, ?, ?)
        """, (
            profile_id,
            control["id"],
            weight,
            control.get("risk", "Medium"),
            json.dumps(default_thresholds(control["id"])),
        ))

    bands = [
        ("A+", 95, "Enterprise Ready"),
        ("A", 90, "Excellent"),
        ("B", 80, "Good"),
        ("C", 70, "Needs Improvement"),
        ("D", 60, "High Risk"),
        ("F", 0, "Critical"),
    ]
    conn.executemany(
        "INSERT INTO grade_bands (profile_id, grade, minimum, label) VALUES (?, ?, ?, ?)",
        [(profile_id, grade, minimum, label) for grade, minimum, label in bands],
    )
    return profile_id


def list_profiles():
    with connect() as conn:
        return [dict(row) for row in conn.execute(
            "SELECT id, name, description, is_active FROM profiles ORDER BY name"
        ).fetchall()]


def get_active_profile():
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM profiles WHERE is_active = 1 LIMIT 1"
        ).fetchone()
        if not row:
            row = conn.execute("SELECT * FROM profiles ORDER BY id LIMIT 1").fetchone()
            if not row:
                raise RuntimeError("No assessment profiles exist.")
            conn.execute("UPDATE profiles SET is_active = 1 WHERE id = ?", (row["id"],))

        controls = {}
        for item in conn.execute(
            "SELECT * FROM profile_controls WHERE profile_id = ?",
            (row["id"],),
        ).fetchall():
            controls[item["control_id"]] = {
                "enabled": bool(item["enabled"]),
                "weight": item["weight"],
                "risk": item["risk"],
                "thresholds": json.loads(item["thresholds_json"] or "{}"),
            }

        grades = [
            dict(item) for item in conn.execute(
                "SELECT grade, minimum, label FROM grade_bands "
                "WHERE profile_id = ? ORDER BY minimum DESC",
                (row["id"],),
            ).fetchall()
        ]

        return {
            "id": row["id"],
            "profile_name": row["name"],
            "description": row["description"],
            "controls": controls,
            "grade_bands": grades,
        }


def activate_profile(profile_id):
    with connect() as conn:
        conn.execute("UPDATE profiles SET is_active = 0")
        conn.execute("UPDATE profiles SET is_active = 1 WHERE id = ?", (profile_id,))


def create_profile(name, description, controls):
    with connect() as conn:
        return create_profile_in_connection(conn, name, description, controls, active=False)


def delete_profile(profile_id):
    with connect() as conn:
        active = conn.execute(
            "SELECT is_active FROM profiles WHERE id = ?", (profile_id,)
        ).fetchone()
        if not active:
            return
        if active["is_active"]:
            raise RuntimeError("The active profile cannot be deleted.")
        conn.execute("DELETE FROM profiles WHERE id = ?", (profile_id,))


def save_control_settings(profile_id, settings):
    with connect() as conn:
        for control_id, item in settings.items():
            conn.execute("""
                UPDATE profile_controls
                SET enabled = ?, weight = ?, risk = ?, thresholds_json = ?
                WHERE profile_id = ? AND control_id = ?
            """, (
                1 if item["enabled"] else 0,
                float(item["weight"]),
                item["risk"],
                json.dumps(item.get("thresholds", {})),
                profile_id,
                control_id,
            ))


def save_grade_bands(profile_id, bands):
    with connect() as conn:
        conn.execute("DELETE FROM grade_bands WHERE profile_id = ?", (profile_id,))
        conn.executemany(
            "INSERT INTO grade_bands (profile_id, grade, minimum, label) "
            "VALUES (?, ?, ?, ?)",
            [(profile_id, b["grade"], float(b["minimum"]), b["label"]) for b in bands],
        )


def update_profile_metadata(profile_id, name, description):
    with connect() as conn:
        conn.execute(
            "UPDATE profiles SET name = ?, description = ? WHERE id = ?",
            (name, description, profile_id),
        )


def save_assessment_run(report):
    with connect() as conn:
        conn.execute("""
            INSERT INTO assessment_runs
            (profile_name, mode, score, grade, readiness, report_json)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            report["active_profile"],
            report["assessment_mode"],
            report["overall_score"],
            report["grade"],
            report["readiness"],
            json.dumps(report),
        ))


def recent_assessments(limit=20):
    with connect() as conn:
        return [dict(row) for row in conn.execute(
            "SELECT id, profile_name, mode, score, grade, readiness, created_at "
            "FROM assessment_runs ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()]


def list_controls(include_disabled=True):
    query = "SELECT * FROM controls"
    if not include_disabled:
        query += " WHERE is_enabled = 1"
    query += " ORDER BY domain, control_id"
    with connect() as conn:
        rows = conn.execute(query).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["collector_config"] = json.loads(item.pop("collector_config_json") or "{}")
            item["is_builtin"] = bool(item["is_builtin"])
            item["is_enabled"] = bool(item["is_enabled"])
            result.append(item)
        return result


def get_control(control_id):
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM controls WHERE control_id = ?",
            (control_id,),
        ).fetchone()
        if not row:
            return None
        item = dict(row)
        item["collector_config"] = json.loads(item.pop("collector_config_json") or "{}")
        item["is_builtin"] = bool(item["is_builtin"])
        item["is_enabled"] = bool(item["is_enabled"])
        return item


def add_custom_control(control):
    with connect() as conn:
        conn.execute("""
            INSERT INTO controls
            (control_id, name, domain, objective, collector_type,
             collector_config_json, recommendation, default_weight,
             default_risk, is_builtin, is_enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
        """, (
            control["control_id"],
            control["name"],
            control["domain"],
            control.get("objective", ""),
            control["collector_type"],
            json.dumps(control.get("collector_config", {})),
            control.get("recommendation", ""),
            float(control.get("default_weight", 0)),
            control.get("default_risk", "Medium"),
            1 if control.get("is_enabled", True) else 0,
        ))

        profile_rows = conn.execute("SELECT id FROM profiles").fetchall()
        for profile in profile_rows:
            conn.execute("""
                INSERT INTO profile_controls
                (profile_id, control_id, enabled, weight, risk, thresholds_json)
                VALUES (?, ?, ?, ?, ?, '{}')
            """, (
                profile["id"],
                control["control_id"],
                1 if control.get("is_enabled", True) else 0,
                float(control.get("default_weight", 0)),
                control.get("default_risk", "Medium"),
            ))


def update_custom_control(control_id, control):
    with connect() as conn:
        row = conn.execute(
            "SELECT is_builtin FROM controls WHERE control_id = ?",
            (control_id,),
        ).fetchone()
        if not row:
            raise RuntimeError("Control was not found.")
        if row["is_builtin"]:
            raise RuntimeError("Built-in controls cannot be edited in the Control Library.")

        conn.execute("""
            UPDATE controls
            SET name = ?, domain = ?, objective = ?, collector_type = ?,
                collector_config_json = ?, recommendation = ?,
                default_weight = ?, default_risk = ?, is_enabled = ?
            WHERE control_id = ?
        """, (
            control["name"],
            control["domain"],
            control.get("objective", ""),
            control["collector_type"],
            json.dumps(control.get("collector_config", {})),
            control.get("recommendation", ""),
            float(control.get("default_weight", 0)),
            control.get("default_risk", "Medium"),
            1 if control.get("is_enabled", True) else 0,
            control_id,
        ))


def duplicate_control(source_control_id, new_control_id, new_name):
    source = get_control(source_control_id)
    if not source:
        raise RuntimeError("Source control was not found.")

    add_custom_control({
        "control_id": new_control_id,
        "name": new_name,
        "domain": source["domain"],
        "objective": source["objective"],
        "collector_type": source["collector_type"],
        "collector_config": source["collector_config"],
        "recommendation": source["recommendation"],
        "default_weight": source["default_weight"],
        "default_risk": source["default_risk"],
        "is_enabled": source["is_enabled"],
    })


def set_control_enabled(control_id, enabled):
    with connect() as conn:
        conn.execute(
            "UPDATE controls SET is_enabled = ? WHERE control_id = ?",
            (1 if enabled else 0, control_id),
        )


def delete_custom_control(control_id):
    with connect() as conn:
        row = conn.execute(
            "SELECT is_builtin FROM controls WHERE control_id = ?",
            (control_id,),
        ).fetchone()
        if not row:
            return
        if row["is_builtin"]:
            raise RuntimeError("Built-in controls cannot be deleted.")
        conn.execute("DELETE FROM controls WHERE control_id = ?", (control_id,))
