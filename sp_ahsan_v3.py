# ============================================================
# SOCProbe v1.0 — Single-File Edition
# IAM Compliance Auditor for SMBs
# Sheridan College INFO49402 — Group 23
# Team: Syed Ahmed, Ahsan Siddiq, Vaqas Mirza
# ============================================================
# All backend logic and UI in one file.
# Requires: ldap3, pywin32, reportlab (optional)
# Run as Administrator for Security Event Log access.
# ============================================================

from __future__ import annotations

import datetime
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import webbrowser
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import timedelta, timezone
from pathlib import Path
import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, ttk

# ============================================================
# SECTION 1 — CONFIG LOADER
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent


class ConfigLoadError(RuntimeError):
    def __init__(self, message: str, *, expected_path: Path, runtime_root: Path, report_directory: Path):
        super().__init__(message)
        self.expected_path = expected_path
        self.runtime_root = runtime_root
        self.report_directory = report_directory


def get_runtime_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return PROJECT_ROOT


def get_reports_root() -> Path:
    return get_runtime_root() / "reports"


def _fqdn_from_base_dn(base_dn: str) -> str:
    parts = []
    for segment in base_dn.split(","):
        segment = segment.strip()
        if segment.upper().startswith("DC="):
            parts.append(segment[3:])
    return ".".join(parts)


def _resolve_config_path(config_path: str | None = None) -> Path:
    if config_path:
        return Path(config_path)
    runtime_root = get_runtime_root()
    bundled_root = Path(getattr(sys, "_MEIPASS", runtime_root))
    candidates = [
        runtime_root / "config.json",
        bundled_root / "config.json",
        PROJECT_ROOT / "config.json",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def _resolve_output_path(output_root: Path, configured_path: str | None, default_name: str) -> Path:
    target = Path(configured_path or default_name)
    if not target.is_absolute():
        target = output_root / target
    return target


def load_config(config_path: str | None = None) -> dict:
    path = _resolve_config_path(config_path)
    runtime_root = get_runtime_root()
    reports_root = get_reports_root()

    if not path.exists():
        raise ConfigLoadError(
            "config.json is missing. Place config.json next to the executable or in the project root.",
            expected_path=path,
            runtime_root=runtime_root,
            report_directory=reports_root,
        )

    with path.open("r", encoding="utf-8") as handle:
        config = json.load(handle)

    organization = config.setdefault("organization", {})
    domain = config.setdefault("domain", {})
    thresholds = config.setdefault("thresholds", {})
    weights = config.setdefault("weights", {})
    output = config.setdefault("output", {})

    organization.setdefault("name", "Local Organization")
    organization.setdefault("industry", "Unspecified")
    organization.setdefault("environment", "Local deployment")
    organization.setdefault("summary", "Local SOC assessment profile.")

    if not domain.get("fqdn") and domain.get("base_dn"):
        domain["fqdn"] = _fqdn_from_base_dn(domain["base_dn"])

    thresholds.setdefault("stale_account_days", 45)
    thresholds.setdefault("max_domain_admins", 3)
    thresholds.setdefault("security_log_lookback_days", 7)
    thresholds.setdefault("security_log_max_events", 250)

    weights.setdefault("privileged_groups", 25)
    weights.setdefault("stale_accounts", 20)
    weights.setdefault("disabled_accounts", 10)
    weights.setdefault("log_validation", 20)

    report_path = _resolve_output_path(runtime_root, output.get("report_path"), "reports\\soc_report.json")
    pdf_report_path = _resolve_output_path(runtime_root, output.get("pdf_report_path"), "reports\\soc_report.pdf")
    html_report_path = _resolve_output_path(runtime_root, output.get("html_report_path"), "reports\\soc_report.html")
    history_path = _resolve_output_path(runtime_root, output.get("history_path"), "reports\\soc_score_history.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)

    output["report_path"] = str(report_path)
    output["pdf_report_path"] = str(pdf_report_path)
    output["html_report_path"] = str(html_report_path)
    output["history_path"] = str(history_path)
    output["report_directory"] = str(report_path.parent)
    output["project_root"] = str(PROJECT_ROOT)
    output["runtime_root"] = str(runtime_root)
    output["config_path"] = str(path)

    return config


# ============================================================
# SECTION 2 — AD CONNECTOR
# ============================================================

try:
    from ldap3 import ALL, Connection, NTLM, SIMPLE, Server
    from ldap3.core.exceptions import LDAPBindError, LDAPException
    from ldap3.utils.conv import escape_filter_chars
    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False


def _normalize_ntlm_username(config: dict) -> str:
    domain_cfg = config["domain"]
    username = domain_cfg["username"]
    if "\\" in username:
        return username
    sam = username.split("@", 1)[0]
    fqdn = domain_cfg.get("fqdn") or ""
    netbios = fqdn.split(".", 1)[0].upper() if fqdn else ""
    return f"{netbios}\\{sam}" if netbios else username


def get_ad_connection_details(config: dict) -> dict:
    domain_cfg = config["domain"]
    return {
        "server": domain_cfg["server"],
        "port": domain_cfg.get("port", 389),
        "base_dn": domain_cfg.get("base_dn", ""),
        "fqdn": domain_cfg.get("fqdn", ""),
        "username": domain_cfg.get("username", ""),
        "ntlm_username": _normalize_ntlm_username(config),
    }


def connect_to_ad(config: dict):
    if not LDAP3_AVAILABLE:
        raise RuntimeError("ldap3 is not installed. Run: pip install ldap3")
    domain_cfg = config["domain"]
    original_username = domain_cfg["username"]
    ntlm_username = _normalize_ntlm_username(config)
    server = Server(domain_cfg["server"], port=domain_cfg.get("port", 389), get_info=ALL)
    try:
        conn = Connection(server, user=ntlm_username, password=domain_cfg["password"],
                          authentication=NTLM, auto_bind=True, raise_exceptions=True)
        return conn
    except Exception as ntlm_exc:
        try:
            conn = Connection(server, user=original_username, password=domain_cfg["password"],
                              authentication=SIMPLE, auto_bind=True, raise_exceptions=True)
            return conn
        except Exception as simple_exc:
            raise RuntimeError(
                f"AD bind failed. NTLM error: {ntlm_exc}. SIMPLE error: {simple_exc}"
            ) from simple_exc


def test_ad_connection(config: dict) -> dict:
    conn = None
    details = get_ad_connection_details(config)
    try:
        conn = connect_to_ad(config)
        return {
            "connected": True,
            "details": details,
            "message": f"Connected to {details['server']}:{details['port']} as {details['ntlm_username']}",
        }
    except Exception as exc:
        return {"connected": False, "details": details, "message": str(exc)}
    finally:
        if conn is not None and conn.bound:
            conn.unbind()


# ============================================================
# SECTION 3 — AD ANALYSIS MODULES
# ============================================================

def check_privileged_groups(conn, config: dict) -> dict:
    base_dn = config["domain"]["base_dn"]
    privileged_groups = config["privileged_groups"]
    max_allowed = int(config["thresholds"]["max_domain_admins"])
    results = {}
    all_privileged_members = set()
    missing_groups = []

    for group in privileged_groups:
        conn.search(
            search_base=base_dn,
            search_filter=f"(&(objectClass=group)(cn={escape_filter_chars(group)}))",
            search_scope="SUBTREE",
            attributes=["member", "cn"],
        )
        if conn.entries:
            entry = conn.entries[0]
            members = entry.member.values if entry.member else []
            member_names = sorted({dn.split(",", 1)[0].replace("CN=", "") for dn in members})
            all_privileged_members.update(member_names)
            results[group] = {"group_found": True, "member_count": len(member_names), "members": member_names}
        else:
            missing_groups.append(group)
            results[group] = {"group_found": False, "member_count": 0, "members": []}

    domain_admin_count = results.get("Domain Admins", {}).get("member_count", 0)
    issues = []
    if missing_groups:
        issues.append(f"missing groups: {', '.join(missing_groups)}")
    if domain_admin_count > max_allowed:
        issues.append(f"Domain Admins has {domain_admin_count} members (max {max_allowed})")

    passed = not issues
    finding = "PASS - Privileged group membership is within threshold."
    if issues:
        finding = "FAIL - " + "; ".join(issues)

    return {
        "passed": passed,
        "domain_admin_count": domain_admin_count,
        "max_allowed": max_allowed,
        "missing_groups": missing_groups,
        "groups": results,
        "total_privileged_members": len(all_privileged_members),
        "finding": finding,
        "mitre_attack": "T1078 - Valid Accounts",
        "frameworks": ["CIS 5.4", "NIST PR.AC-4", "ISO 27001 A.8.2"],
        "remediation": "Reduce Domain Admins membership to the configured threshold. Remove service accounts and non-essential users. Use dedicated admin accounts.",
    }


def check_stale_accounts(conn, config: dict) -> dict:
    base_dn = config["domain"]["base_dn"]
    threshold_days = int(config["thresholds"]["stale_account_days"])
    cutoff = datetime.datetime.now(timezone.utc) - timedelta(days=threshold_days)

    conn.search(
        search_base=base_dn,
        search_filter="(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        search_scope="SUBTREE",
        attributes=["cn", "sAMAccountName", "lastLogonTimestamp", "whenCreated"],
    )

    stale_accounts = []
    never_logged_in = []

    for entry in conn.entries:
        attrs = entry.entry_attributes_as_dict
        name = str(attrs.get("cn", ["Unknown"])[0])
        sam = str(attrs.get("sAMAccountName", ["Unknown"])[0])

        raw_logon = getattr(entry, "lastLogonTimestamp", None)
        last_logon = raw_logon.value if raw_logon and "lastLogonTimestamp" in entry else None
        if last_logon and isinstance(last_logon, datetime.datetime):
            if last_logon.tzinfo is None:
                last_logon = last_logon.replace(tzinfo=timezone.utc)
            else:
                last_logon = last_logon.astimezone(timezone.utc)

        raw_created = getattr(entry, "whenCreated", None)
        when_created = raw_created.value if raw_created and "whenCreated" in entry else None
        if when_created and isinstance(when_created, datetime.datetime):
            if when_created.tzinfo is None:
                when_created = when_created.replace(tzinfo=timezone.utc)
            else:
                when_created = when_created.astimezone(timezone.utc)

        if last_logon is None:
            if when_created and when_created < cutoff:
                never_logged_in.append({"name": name, "sam": sam, "when_created": when_created.isoformat()})
            continue
        if last_logon < cutoff:
            stale_accounts.append({"name": name, "sam": sam, "last_logon": last_logon.isoformat()})

    total_stale = len(stale_accounts) + len(never_logged_in)
    passed = total_stale == 0
    finding = "PASS - No stale enabled accounts detected."
    if not passed:
        finding = f"FAIL - {total_stale} stale or never-used enabled account(s) exceeded the {threshold_days}-day threshold."

    return {
        "passed": passed,
        "stale_count": len(stale_accounts),
        "never_logged_in_count": len(never_logged_in),
        "stale_accounts": stale_accounts,
        "never_logged_in": never_logged_in,
        "threshold_days": threshold_days,
        "finding": finding,
        "mitre_attack": "T1078.002 - Domain Accounts",
        "frameworks": ["CIS 5.3", "NIST PR.AC-6", "ISO 27001 A.5.16"],
        "remediation": "Disable accounts inactive beyond the threshold. Confirm with HR/manager, then remove after review period.",
    }


def check_disabled_accounts(conn, config: dict) -> dict:
    base_dn = config["domain"]["base_dn"]
    privileged_groups = set(config["privileged_groups"])

    conn.search(
        search_base=base_dn,
        search_filter="(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=2))",
        search_scope="SUBTREE",
        attributes=["cn", "sAMAccountName", "memberOf"],
    )

    disabled_in_privileged = []
    for entry in conn.entries:
        attrs = entry.entry_attributes_as_dict
        name = str(attrs.get("cn", ["Unknown"])[0])
        sam = str(attrs.get("sAMAccountName", ["Unknown"])[0])
        groups = attrs.get("memberOf", [])
        for group_dn in groups:
            group_cn = group_dn.split(",", 1)[0].replace("CN=", "")
            if group_cn in privileged_groups:
                disabled_in_privileged.append({"name": name, "sam": sam, "privileged_group": group_cn})
                break

    passed = len(disabled_in_privileged) == 0
    finding = "PASS - No disabled accounts remain in privileged groups."
    if not passed:
        finding = f"FAIL - {len(disabled_in_privileged)} disabled account(s) found in privileged groups."

    return {
        "passed": passed,
        "count": len(disabled_in_privileged),
        "accounts": disabled_in_privileged,
        "finding": finding,
        "mitre_attack": "T1098 - Account Manipulation",
        "frameworks": ["CIS 6.2", "ISO 27001 A.5.18", "NIST PR.AC-1"],
        "remediation": "Remove disabled accounts from privileged groups immediately. Confirm access was fully revoked.",
    }


# ============================================================
# SECTION 4 — EVENT LOG READER
# ============================================================

try:
    import win32evtlog
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False

NS = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}

CATEGORY_MAP = {
    "successful_logons": {"label": "Successful logons", "event_ids": {4624}},
    "failed_logons": {"label": "Failed logons", "event_ids": {4625}},
    "lockouts": {"label": "Account lockouts", "event_ids": {4740}},
    "account_changes": {"label": "Account created or state changes", "event_ids": {4720, 4722, 4725}},
    "group_membership_changes": {"label": "Group membership changes", "event_ids": {4728, 4729, 4732, 4733, 4756, 4757}},
}

WELL_KNOWN_NON_HUMAN = {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", "DWM-1", "UMFD-0"}


def get_event_log_status(log_name: str = "Security") -> dict:
    if not WIN32_AVAILABLE:
        return {"accessible": False, "log_name": log_name, "record_count": 0, "error": "pywin32 not installed"}
    try:
        handle = win32evtlog.OpenEventLog(None, log_name)
        record_count = win32evtlog.GetNumberOfEventLogRecords(handle)
        win32evtlog.CloseEventLog(handle)
        return {"accessible": True, "log_name": log_name, "record_count": record_count}
    except Exception as exc:
        return {"accessible": False, "log_name": log_name, "record_count": 0, "error": str(exc)}


def _build_query(lookback_days: int) -> str:
    event_ids = sorted({eid for meta in CATEGORY_MAP.values() for eid in meta["event_ids"]})
    event_filter = " or ".join(f"EventID={eid}" for eid in event_ids)
    ms = max(1, int(lookback_days)) * 24 * 60 * 60 * 1000
    return f"*[System[({event_filter}) and TimeCreated[timediff(@SystemTime) <= {ms}]]]"


def _parse_xml_event(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)
    system = root.find("evt:System", NS)
    data_nodes = root.findall("evt:EventData/evt:Data", NS)
    data = {n.attrib.get("Name", f"field_{i}"): (n.text or "").strip() for i, n in enumerate(data_nodes)}
    event_id = int(system.findtext("evt:EventID", default="0", namespaces=NS))
    time_node = system.find("evt:TimeCreated", NS)
    raw_time = time_node.attrib.get("SystemTime") if time_node is not None else ""
    try:
        timestamp = datetime.datetime.fromisoformat(raw_time.replace("Z", "+00:00")).astimezone().isoformat()
    except (ValueError, AttributeError):
        timestamp = raw_time
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "computer": system.findtext("evt:Computer", default="", namespaces=NS),
        "subject": (data.get("TargetUserName") or data.get("MemberName") or
                    data.get("SubjectUserName") or data.get("SamAccountName") or "Unknown"),
        "secondary": data.get("IpAddress") or data.get("TargetDomainName") or data.get("GroupName") or "",
    }


def _activity_type(subject: str) -> str:
    normalized = (subject or "").strip().upper()
    if not normalized or normalized in WELL_KNOWN_NON_HUMAN:
        return "service_or_machine"
    if normalized.endswith("$") or normalized.startswith("SVC"):
        return "service_or_machine"
    return "human"


def read_security_events(config: dict) -> dict:
    lookback_days = int(config["thresholds"].get("security_log_lookback_days", 7))
    max_events = int(config["thresholds"].get("security_log_max_events", 250))
    status = get_event_log_status("Security")

    summary = {
        "accessible": status["accessible"],
        "record_count": status.get("record_count", 0),
        "lookback_days": lookback_days,
        "total_relevant_events": 0,
        "telemetry_quality": "unavailable",
        "activity_breakdown": {"human_successful_logons": 0, "service_or_machine_successful_logons": 0},
        "categories": {
            key: {"label": meta["label"], "event_ids": sorted(meta["event_ids"]),
                  "count": 0, "top_subjects": [], "sample_events": []}
            for key, meta in CATEGORY_MAP.items()
        },
    }

    if not status["accessible"] or not WIN32_AVAILABLE:
        return {
            "passed": False,
            "finding": "FAIL - Windows Security log is not accessible. Run as Administrator.",
            "connection": status,
            "summary": summary,
            "mitre_attack": "T1562.002 - Disable Windows Event Logging",
            "frameworks": ["CISA Logging Made Easy", "NIST DE.CM-1", "CIS 8.2"],
            "remediation": "Run the tool as Administrator. Verify local audit policy is enabled via auditpol /get /category:*",
        }

    try:
        query_handle = win32evtlog.EvtQuery(
            "Security",
            win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
            _build_query(lookback_days),
        )
    except Exception as exc:
        return {
            "passed": False,
            "finding": f"FAIL - Security log query failed: {exc}",
            "connection": status,
            "summary": summary,
            "mitre_attack": "T1562.002 - Disable Windows Event Logging",
            "frameworks": ["CISA Logging Made Easy", "NIST DE.CM-1", "CIS 8.2"],
            "remediation": "Verify audit policy settings and re-run as Administrator.",
        }

    counters = {key: Counter() for key in CATEGORY_MAP}
    events = {key: [] for key in CATEGORY_MAP}
    activity_breakdown = Counter()
    fetched = 0

    while fetched < max_events:
        batch = win32evtlog.EvtNext(query_handle, 25)
        if not batch:
            break
        for event_handle in batch:
            xml_text = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
            parsed = _parse_xml_event(xml_text)
            category = next((k for k, m in CATEGORY_MAP.items() if parsed["event_id"] in m["event_ids"]), None)
            if category is None:
                continue
            events[category].append(parsed)
            counters[category][parsed["subject"]] += 1
            if category == "successful_logons":
                activity_breakdown[_activity_type(parsed["subject"])] += 1
            fetched += 1
            if fetched >= max_events:
                break

    for cat_key, cat_summary in summary["categories"].items():
        cat_events = events[cat_key]
        cat_summary["count"] = len(cat_events)
        cat_summary["top_subjects"] = [{"subject": s, "count": c} for s, c in counters[cat_key].most_common(5)]
        cat_summary["sample_events"] = [
            {"timestamp": e["timestamp"], "event_id": e["event_id"], "subject": e["subject"],
             "secondary": e["secondary"], "computer": e["computer"]}
            for e in cat_events[:5]
        ]

    summary["total_relevant_events"] = sum(c["count"] for c in summary["categories"].values())
    summary["activity_breakdown"] = {
        "human_successful_logons": activity_breakdown.get("human", 0),
        "service_or_machine_successful_logons": activity_breakdown.get("service_or_machine", 0),
    }

    human_signal = summary["activity_breakdown"]["human_successful_logons"] > 0
    security_signal = any(summary["categories"][k]["count"] > 0
                          for k in ("failed_logons", "lockouts", "account_changes", "group_membership_changes"))
    baseline_signal = summary["total_relevant_events"] > 0

    if security_signal or human_signal:
        passed = True
        quality = "strong"
        finding = (f"PASS - Security log accessible with {summary['total_relevant_events']} "
                   f"relevant events over {lookback_days} day(s).")
    elif baseline_signal:
        passed = True
        quality = "baseline"
        finding = "PASS - Security log accessible. Baseline service logon telemetry present."
    else:
        passed = False
        quality = "limited"
        finding = f"FAIL - Security log accessible but no monitored events in last {lookback_days} day(s)."

    summary["telemetry_quality"] = quality
    return {
        "passed": passed,
        "finding": finding,
        "connection": status,
        "summary": summary,
        "mitre_attack": "T1562.002 - Disable Windows Event Logging",
        "frameworks": ["CISA Logging Made Easy", "NIST DE.CM-1", "CIS 8.2"],
        "remediation": "Ensure Security log is enabled and readable. Run as Administrator.",
    }


# ============================================================
# SECTION 5 — BRUTE FORCE AND GROUP CHANGE DETECTION
# (ported from Vaqas)
# ============================================================

def detect_bruteforce(config: dict) -> dict:
    """Groups 4625 events by user. Returns flagged accounts with 5+ failures."""
    if not WIN32_AVAILABLE:
        return {"detected": False, "flagged_accounts": {}, "error": "pywin32 not available"}

    threshold = int(config.get("thresholds", {}).get("max_failed_logons_24h", 5))
    try:
        query_handle = win32evtlog.EvtQuery(
            "Security",
            win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
            "*[System[EventID=4625 and TimeCreated[timediff(@SystemTime) <= 86400000]]]",
        )
    except Exception as exc:
        return {"detected": False, "flagged_accounts": {}, "error": str(exc)}

    attempts: dict[str, int] = {}
    batch_count = 0
    while batch_count < 200:
        batch = win32evtlog.EvtNext(query_handle, 25)
        if not batch:
            break
        for event_handle in batch:
            xml_text = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
            parsed = _parse_xml_event(xml_text)
            user = parsed["subject"].strip()
            if user and user.upper() not in WELL_KNOWN_NON_HUMAN and user != "-":
                attempts[user] = attempts.get(user, 0) + 1
            batch_count += 1

    flagged = {u: c for u, c in attempts.items() if c >= threshold}
    return {"detected": bool(flagged), "flagged_accounts": flagged, "threshold": threshold}


def detect_privileged_group_change(config: dict) -> dict:
    """Checks for Event ID 4728 (member added to security group) in last 24h."""
    if not WIN32_AVAILABLE:
        return {"detected": False, "count": 0, "error": "pywin32 not available"}
    try:
        query_handle = win32evtlog.EvtQuery(
            "Security",
            win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
            "*[System[EventID=4728 and TimeCreated[timediff(@SystemTime) <= 86400000]]]",
        )
        count = 0
        while True:
            batch = win32evtlog.EvtNext(query_handle, 25)
            if not batch:
                break
            count += len(batch)
        return {"detected": count > 0, "count": count}
    except Exception as exc:
        return {"detected": False, "count": 0, "error": str(exc)}


# ============================================================
# SECTION 6 — SCORING ENGINE
# ============================================================

BRUTE_FORCE_PENALTY = 10
PRIV_CHANGE_PENALTY = 5

DEFAULT_WEIGHTS = {
    "privileged_groups": 25,
    "stale_accounts": 20,
    "disabled_accounts": 10,
    "log_validation": 20,
}


def get_control_weights(config: dict | None = None) -> dict:
    weights = dict(DEFAULT_WEIGHTS)
    if config:
        weights.update(config.get("weights", {}))
    return weights


def calculate_score(findings: dict, config: dict | None = None) -> tuple[float, str]:
    weights = get_control_weights(config)
    total_weight = sum(weights.values())
    passed_weight = sum(w for ctrl, w in weights.items() if findings.get(ctrl, {}).get("passed", False))
    score = round((passed_weight / total_weight) * 100, 1) if total_weight else 0.0

    # Brute force penalty
    bf = findings.get("brute_force", {})
    if bf.get("detected", False):
        score = max(0.0, score - BRUTE_FORCE_PENALTY)

    # Privileged group change penalty
    pgc = findings.get("priv_group_change", {})
    if pgc.get("detected", False):
        score = max(0.0, score - PRIV_CHANGE_PENALTY)

    if score >= 80:
        tier = "HIGH READINESS"
    elif score >= 60:
        tier = "MODERATE"
    elif score >= 40:
        tier = "LOW"
    else:
        tier = "POOR"

    return score, tier


def build_score_breakdown(findings: dict, config: dict | None = None) -> dict:
    weights = get_control_weights(config)
    total_weight = sum(weights.values())
    passed_weight = sum(w for ctrl, w in weights.items() if findings.get(ctrl, {}).get("passed", False))
    score, tier = calculate_score(findings, config)
    return {
        "formula": "Readiness Score = (Passed Control Weight / Total Control Weight) x 100",
        "passed_control_weight": passed_weight,
        "total_control_weight": total_weight,
        "controls": {
            ctrl: {"weight": w, "passed": findings.get(ctrl, {}).get("passed", False)}
            for ctrl, w in weights.items()
        },
        "score": score,
        "tier": tier,
    }


def calculate_soc_maturity(score: float, findings: dict) -> str:
    high = sum(1 for f in findings.values() if isinstance(f, dict) and not f.get("passed", True))
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


def save_score_history(score: float, tier: str, config: dict) -> list:
    history_path = Path(config["output"]["history_path"])
    history = []
    if history_path.exists():
        try:
            with history_path.open("r", encoding="utf-8") as f:
                history = json.load(f)
        except Exception:
            history = []
    history.append({"time": datetime.datetime.now().isoformat(), "score": score, "tier": tier})
    history = history[-50:]
    with history_path.open("w", encoding="utf-8") as f:
        json.dump(history, f, indent=4)
    return history


# ============================================================
# SECTION 7 — FRAMEWORK AND REMEDIATION MAPS
# (ported from Vaqas, extended with Ahsan's detail)
# ============================================================

FRAMEWORK_MAP = {
    "Privileged Group Membership":    ["CIS 5.4", "NIST PR.AC-4", "ISO 27001 A.8.2"],
    "Stale Account Detection":        ["CIS 5.3", "NIST PR.AC-6", "ISO 27001 A.5.16"],
    "Log Accessibility":              ["CISA Logging Made Easy", "NIST DE.CM-1", "CIS 8.2"],
    "Disabled Account Hygiene":       ["CIS 6.2", "ISO 27001 A.5.18", "NIST PR.AC-1"],
    "Failed Logon Detection":         ["NIST DE.CM-3", "CIS 8.11", "ISO 27001 A.8.5"],
    "Event ID Coverage":              ["CISA Logging Made Easy", "CIS 8.5", "NIST DE.AE-2"],
    "Audit Policy Validation":        ["NIST DE.AE-2", "CIS 8.5", "ISO 27001 A.8.15"],
    "Brute Force Detection":          ["NIST DE.CM-3", "CIS 8.11", "ISO 27001 A.8.5"],
    "Privileged Group Change":        ["CIS 5.4", "NIST PR.AC-4", "ISO 27001 A.8.2"],
}

REMEDIATION_MAP = {
    "Privileged Group Membership":    "Reduce Domain Admins membership to threshold. Remove service accounts. Use dedicated admin accounts.",
    "Stale Account Detection":        "Disable accounts inactive beyond threshold. Confirm with HR/manager, then remove after review.",
    "Log Accessibility":              "Run as Administrator. Enable Security log collection. Verify Event Viewer permissions.",
    "Disabled Account Hygiene":       "Remove disabled accounts from privileged groups immediately. Confirm access was fully revoked.",
    "Failed Logon Detection":         "Enable failed logon auditing. Review 4625 events for patterns. Enforce account lockout policy.",
    "Event ID Coverage":              "Enable events 4624, 4625, 4648, 4720, 4728, and 4776 via Group Policy audit settings.",
    "Audit Policy Validation":        "Enable required audit policies via auditpol. Run gpupdate /force to apply.",
    "Brute Force Detection":          "Investigate flagged accounts. Review source workstation and IP. Enforce account lockout policy.",
    "Privileged Group Change":        "Review Domain Admins for unauthorized additions. Confirm all changes were authorized.",
}

MITRE_MAP = {
    "privileged_groups":   "T1078 - Valid Accounts",
    "stale_accounts":      "T1078.002 - Domain Accounts",
    "disabled_accounts":   "T1098 - Account Manipulation",
    "log_validation":      "T1562.002 - Disable Windows Event Logging",
    "brute_force":         "T1110 - Brute Force",
    "priv_group_change":   "T1098 - Account Manipulation",
}


def ai_explanation(score: float, tier: str, maturity: str, findings: dict) -> str:
    failed = [k for k, v in findings.items() if isinstance(v, dict) and not v.get("passed", True)]
    high = [k for k in ("privileged_groups", "disabled_accounts") if k in failed]
    return (
        f"SOCProbe assessed this environment at {score}/100 with a {tier} rating. "
        f"The SOC maturity level is {maturity}. "
        f"{len(failed)} control(s) failed. "
        f"{'High-severity issues include: ' + ', '.join(high) + '. ' if high else ''}"
        f"The assessment covers identity, logging, audit, and detection controls mapped to "
        f"NIST CSF 2.0, CIS Controls v8, ISO 27001:2022, and CISA Logging Made Easy."
    )


# ============================================================
# SECTION 8 — REPORT GENERATOR
# ============================================================

def _escape_pdf(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap_text(text: str, max_chars: int) -> list[str]:
    if not text:
        return [""]
    words = str(text).split()
    lines, current = [], ""
    for word in words:
        candidate = word if not current else f"{current} {word}"
        if len(candidate) <= max_chars:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines or [""]


class PdfCanvas:
    PAGE_W, PAGE_H = 612, 792
    LM, RM, TM, BM = 48, 48, 54, 48
    CW = PAGE_W - LM - RM
    LH = 14

    def __init__(self):
        self.pages: list[list[str]] = [[]]
        self.page = self.pages[0]
        self.y = self.PAGE_H - self.TM

    def _new_page(self):
        self.pages.append([])
        self.page = self.pages[-1]
        self.y = self.PAGE_H - self.TM

    def _ensure(self, h: float):
        if self.y - h < self.BM:
            self._new_page()

    def _rect(self, x, y, w, h, stroke=(0.16, 0.30, 0.41), fill=None, lw=1):
        cmds = [f"{lw} w", f"{stroke[0]:.3f} {stroke[1]:.3f} {stroke[2]:.3f} RG"]
        if fill:
            cmds += [f"{fill[0]:.3f} {fill[1]:.3f} {fill[2]:.3f} rg",
                     f"{x:.2f} {y:.2f} {w:.2f} {h:.2f} re B"]
        else:
            cmds.append(f"{x:.2f} {y:.2f} {w:.2f} {h:.2f} re S")
        self.page.extend(cmds)

    def _line(self, x1, y1, x2, y2, color=(0.16, 0.30, 0.41), lw=1):
        self.page.extend([f"{lw} w", f"{color[0]:.3f} {color[1]:.3f} {color[2]:.3f} RG",
                           f"{x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S"])

    def _text(self, x, y, text, size=10, color=(0.1, 0.12, 0.16), font="Helvetica"):
        self.page.extend(["BT", f"/{font} {size} Tf",
                           f"{color[0]:.3f} {color[1]:.3f} {color[2]:.3f} rg",
                           f"{x:.2f} {y:.2f} Td", f"({_escape_pdf(text)}) Tj", "ET"])

    def section(self, title: str):
        self._ensure(28)
        self._text(self.LM, self.y, title, size=13, color=(0.06, 0.23, 0.36), font="Helvetica-Bold")
        self.y -= 8
        self._line(self.LM, self.y, self.PAGE_W - self.RM, self.y, lw=1.2)
        self.y -= 16

    def para(self, text: str, size=10, color=(0.1, 0.12, 0.16), max_chars=88):
        lines = _wrap_text(text, max_chars)
        self._ensure(len(lines) * self.LH + 4)
        for line in lines:
            self._text(self.LM, self.y, line, size=size, color=color)
            self.y -= self.LH
        self.y -= 4

    def kv_block(self, pairs: list[tuple[str, str]], cols=2):
        rh = 22
        rows = (len(pairs) + cols - 1) // cols
        bh = rows * rh + 14
        cw = self.CW / cols
        self._ensure(bh)
        self._rect(self.LM, self.y - bh + 10, self.CW, bh, fill=(0.94, 0.97, 0.99))
        sy = self.y - 10
        for i, (label, value) in enumerate(pairs):
            x = self.LM + (i % cols) * cw + 10
            y = sy - (i // cols) * rh
            self._text(x, y, label, size=9, color=(0.28, 0.40, 0.49), font="Helvetica-Bold")
            self._text(x + 132, y, str(value), size=9)
        self.y -= bh + 8

    def table(self, headers, rows, widths, row_max_chars=None):
        rmc = row_max_chars or [24] * len(headers)
        hh = 24
        self._ensure(hh + 8)
        self._rect(self.LM, self.y - hh + 6, self.CW, hh, fill=(0.13, 0.28, 0.40), stroke=(0.13, 0.28, 0.40))
        x = self.LM
        for i, h in enumerate(headers):
            self._text(x + 6, self.y - 12, h, size=9, color=(1, 1, 1), font="Helvetica-Bold")
            x += widths[i]
        self.y -= hh
        for row in rows:
            wrapped = [_wrap_text(str(cell), rmc[i]) for i, cell in enumerate(row)]
            max_lines = max(len(w) for w in wrapped)
            rh = max(22, max_lines * 12 + 8)
            self._ensure(rh + 2)
            self._rect(self.LM, self.y - rh + 2, self.CW, rh, fill=(0.97, 0.98, 0.99),
                       stroke=(0.84, 0.89, 0.93), lw=0.7)
            x = self.LM
            for i, cell_lines in enumerate(wrapped):
                ly = self.y - 12
                for line in cell_lines:
                    self._text(x + 6, ly, line, size=8)
                    ly -= 11
                x += widths[i]
            self.y -= rh
        self.y -= 12

    def build(self, path: Path):
        objects = []
        page_ids, content_ids = [], []
        next_id = 3
        for page_cmds in self.pages:
            stream = "\n".join(page_cmds).encode("latin-1", errors="replace")
            cid, pid = next_id, next_id + 1
            next_id += 2
            content_ids.append(cid)
            page_ids.append(pid)
            objects.append((cid, f"<< /Length {len(stream)} >> stream\n".encode() + stream + b"\nendstream"))
        pages_id, catalog_id = next_id, next_id + 1
        for i, pid in enumerate(page_ids):
            objects.append((pid, (f"<< /Type /Page /Parent {pages_id} 0 R "
                                  f"/MediaBox [0 0 {self.PAGE_W} {self.PAGE_H}] "
                                  f"/Resources << /Font << /Helvetica 1 0 R /Helvetica-Bold 2 0 R >> >> "
                                  f"/Contents {content_ids[i]} 0 R >>").encode("latin-1")))
        kids = " ".join(f"{pid} 0 R" for pid in page_ids)
        objects += [
            (1, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"),
            (2, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"),
            (pages_id, f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("latin-1")),
            (catalog_id, f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("latin-1")),
        ]
        objects.sort(key=lambda o: o[0])
        pdf = bytearray(b"%PDF-1.4\n")
        offsets = [0]
        for oid, data in objects:
            offsets.append(len(pdf))
            pdf.extend(f"{oid} 0 obj\n".encode())
            pdf.extend(data)
            pdf.extend(b"\nendobj\n")
        xref_pos = len(pdf)
        pdf.extend(f"xref\n0 {len(offsets)}\n".encode())
        pdf.extend(b"0000000000 65535 f \n")
        for off in offsets[1:]:
            pdf.extend(f"{off:010d} 00000 n \n".encode())
        pdf.extend(f"trailer << /Size {len(offsets)} /Root {catalog_id} 0 R >>\nstartxref\n{xref_pos}\n%%EOF".encode())
        path.write_bytes(pdf)


def generate_pdf(path: Path, result: dict):
    c = PdfCanvas()
    c._rect(c.LM, c.PAGE_H - 112, c.CW, 60, fill=(0.10, 0.25, 0.38), stroke=(0.10, 0.25, 0.38))
    c._text(c.LM + 16, c.PAGE_H - 78, "SOCProbe Assessment Report", size=20, color=(1, 1, 1), font="Helvetica-Bold")
    c._text(c.LM + 16, c.PAGE_H - 96, result["organization"].get("name", ""), size=10, color=(0.85, 0.94, 0.99))
    c.y = c.PAGE_H - 132
    c.kv_block([
        ("Timestamp", result.get("assessment_timestamp", "")),
        ("Domain", result.get("domain", {}).get("fqdn", "")),
        ("Score", f"{result.get('soc_readiness_score', 0)}/100"),
        ("Risk Tier", result.get("risk_level", "")),
    ])
    sb = result.get("score_breakdown", {})
    c.section("Control Breakdown")
    rows = [[ctrl.replace("_", " ").title(), str(d["weight"]),
             "PASS" if d["passed"] else "FAIL",
             result.get("findings", {}).get(ctrl, {}).get("finding", "")]
            for ctrl, d in sb.get("controls", {}).items()]
    c.table(["Control", "Weight", "Status", "Finding"], rows,
            widths=[145, 60, 60, c.CW - 265], row_max_chars=[22, 8, 8, 44])
    c.section("Remediation Actions")
    for action in result.get("remediation_summary", {}).get("recommended_actions", []):
        c.para(f"[{action.get('priority', '').upper()}] {action.get('recommendation', '')}")
    c.build(path)


def generate_html_report(result: dict, html_path: Path):
    findings = result.get("findings", {})
    rows = ""
    for ctrl, f in findings.items():
        if not isinstance(f, dict):
            continue
        status = "PASS" if f.get("passed", False) else "FAIL"
        color = "#22c55e" if f.get("passed", False) else "#ef4444"
        rows += f"""
        <tr>
          <td>{ctrl.replace('_', ' ').title()}</td>
          <td style="color:{color};font-weight:bold">{status}</td>
          <td>{f.get('finding', '')}</td>
          <td>{f.get('mitre_attack', 'N/A')}</td>
          <td>{', '.join(f.get('frameworks', []))}</td>
          <td>{f.get('remediation', '')}</td>
        </tr>"""
    html = f"""<!DOCTYPE html>
<html>
<head>
  <title>SOCProbe Report - {result['organization'].get('name', '')}</title>
  <style>
    body {{background:#0f172a;color:#f1f5f9;font-family:Segoe UI,Arial;padding:32px;}}
    .card {{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:24px;margin-bottom:20px;}}
    h1 {{color:#38bdf8;}} h2 {{color:#94a3b8;font-size:14px;text-transform:uppercase;letter-spacing:1px;}}
    .score {{font-size:52px;font-weight:700;color:#22c55e;}}
    .tier {{font-size:22px;font-weight:600;color:#facc15;margin-top:8px;}}
    table {{width:100%;border-collapse:collapse;}}
    th {{background:#1d4ed8;color:#fff;padding:12px 10px;text-align:left;font-size:12px;}}
    td {{padding:12px 10px;border-bottom:1px solid #334155;font-size:12px;color:#cbd5e1;vertical-align:top;}}
    tr:hover td {{background:#1e3a5f;}}
  </style>
</head>
<body>
  <div class="card">
    <h1>SOCProbe Assessment Report</h1>
    <p>{result['organization'].get('name', '')} | {result.get('assessment_timestamp', '')}</p>
    <div class="score">{result.get('soc_readiness_score', 0)}/100</div>
    <div class="tier">{result.get('risk_level', '')}</div>
    <p style="color:#94a3b8;margin-top:12px">{result.get('executive_summary', '')}</p>
  </div>
  <div class="card">
    <h2>Control Findings</h2>
    <table>
      <tr><th>Control</th><th>Status</th><th>Finding</th><th>MITRE</th><th>Frameworks</th><th>Remediation</th></tr>
      {rows}
    </table>
  </div>
</body>
</html>"""
    html_path.write_text(html, encoding="utf-8")


def build_remediation_summary(findings: dict, config: dict) -> dict:
    actions = []
    priority_map = {"privileged_groups": "high", "disabled_accounts": "high",
                    "stale_accounts": "medium", "log_validation": "medium",
                    "brute_force": "high", "priv_group_change": "high"}
    recommendation_map = {
        "privileged_groups": "Reduce Domain Admins membership to configured threshold.",
        "disabled_accounts": "Remove disabled accounts from privileged groups.",
        "stale_accounts": f"Disable accounts inactive beyond {config['thresholds'].get('stale_account_days', 45)} days.",
        "log_validation": "Run as Administrator and verify audit policy is enabled.",
        "brute_force": "Investigate flagged accounts and enforce account lockout policy.",
        "priv_group_change": "Review Domain Admins for unauthorized changes.",
    }
    for ctrl, f in findings.items():
        if not isinstance(f, dict):
            continue
        if not f.get("passed", True) or f.get("detected", False):
            actions.append({
                "priority": priority_map.get(ctrl, "medium"),
                "control": ctrl,
                "issue": f.get("finding", f.get("flagged_accounts", "")),
                "recommendation": recommendation_map.get(ctrl, "Review and remediate."),
            })
    return {"recommended_actions": actions, "action_count": len(actions)}


def generate_report(findings: dict, score: float, tier: str, config: dict) -> dict:
    maturity = calculate_soc_maturity(score, findings)
    summary_text = ai_explanation(score, tier, maturity, findings)
    remediation = build_remediation_summary(findings, config)
    event_summary = findings.get("log_validation", {}).get("summary", {})

    result = {
        "tool": "SOCProbe",
        "version": "1.0",
        "organization": config["organization"],
        "domain": {
            "fqdn": config.get("domain", {}).get("fqdn", ""),
            "server": config.get("domain", {}).get("server", ""),
            "port": config.get("domain", {}).get("port", 389),
            "base_dn": config.get("domain", {}).get("base_dn", ""),
        },
        "assessment_timestamp": datetime.datetime.now().astimezone().isoformat(),
        "assessment_scope": "single-company local Windows Server deployment",
        "soc_readiness_score": score,
        "risk_level": tier,
        "soc_maturity": maturity,
        "executive_summary": summary_text,
        "score_breakdown": build_score_breakdown(findings, config),
        "findings": findings,
        "event_log_overview": {
            "lookback_days": event_summary.get("lookback_days", 0),
            "total_relevant_events": event_summary.get("total_relevant_events", 0),
            "telemetry_quality": event_summary.get("telemetry_quality", "unavailable"),
            "activity_breakdown": event_summary.get("activity_breakdown", {}),
            "categories": event_summary.get("categories", {}),
        },
        "remediation_summary": remediation,
        "report_paths": {
            "json": config["output"]["report_path"],
            "pdf": config["output"]["pdf_report_path"],
            "html": config["output"]["html_report_path"],
        },
    }

    json_path = Path(config["output"]["report_path"])
    pdf_path = Path(config["output"]["pdf_report_path"])
    html_path = Path(config["output"]["html_report_path"])
    json_path.parent.mkdir(parents=True, exist_ok=True)

    with json_path.open("w", encoding="utf-8") as f:
        json.dump(result, f, indent=4)

    generate_pdf(pdf_path, result)
    generate_html_report(result, html_path)
    save_score_history(score, tier, config)

    return result
# ============================================================
# SECTION 9 — THEME CONSTANTS (Vaqas purple scheme)
# ============================================================

BG          = "#121018"
PANEL       = "#1d1826"
PANEL_2     = "#241b33"
PURPLE      = "#7e22ce"
PURPLE_DARK = "#4c1d95"
PURPLE_SOFT = "#a855f7"
TEXT        = "#f8fafc"
MUTED       = "#c4b5fd"
YELLOW      = "#facc15"
GREEN       = "#a3e635"
RED         = "#f87171"
BORDER      = "#5b21b6"

# aliases used by backend functions
APP_BG   = BG
PANEL_BG = PANEL
CARD_BG  = PANEL_2
ACCENT   = PURPLE_SOFT
SUCCESS  = GREEN
WARNING  = YELLOW
FAIL     = RED

CONTROL_ORDER = [
    ("privileged_groups", "Privileged Group Membership", "T1078"),
    ("stale_accounts",    "Stale Account Detection",     "T1078.002"),
    ("disabled_accounts", "Disabled Account Hygiene",    "T1098"),
    ("log_validation",    "Log Accessibility",           "T1562.002"),
]

DEMO_SCENARIOS = {
    "Clean Environment": {
        "score": 95, "tier": "HIGH READINESS",
        "maturity": "Level 5 - Optimized SOC",
        "findings": [],
        "summary": "Demo: Clean environment. SOCProbe found no high-severity indicators.",
    },
    "Stale Accounts": {
        "score": 78, "tier": "MODERATE",
        "maturity": "Level 3 - Detection Capable",
        "findings": [{"category": "Account Security", "control": "Stale Account Detection",
                      "description": "Simulated: enabled accounts inactive >45 days.",
                      "severity": "Medium", "frameworks": ["CIS 5.3", "NIST PR.AC-6"],
                      "mitre_attack": "IOE",
                      "issue": "stale_user01 and stale_user02 appear inactive."}],
        "summary": "Demo: Stale accounts reduce score. Inactive enabled accounts can become unauthorized access points.",
    },
    "Brute Force": {
        "score": 55, "tier": "LOW",
        "maturity": "Level 2 - Basic Monitoring",
        "findings": [{"category": "Account Security", "control": "Brute Force Detection",
                      "description": "Simulated: repeated failed logons detected.",
                      "severity": "High", "frameworks": ["NIST DE.CM-3", "CIS 8.11"],
                      "mitre_attack": "T1110 - Brute Force",
                      "issue": "demo_user: 10 failed logons in 24 hours."}],
        "summary": "Demo: Active credential attack detected. Score penalized by brute force detection.",
    },
    "Privileged Change": {
        "score": 60, "tier": "LOW",
        "maturity": "Level 2 - Basic Monitoring",
        "findings": [{"category": "AD Delegation", "control": "Privileged Group Change Detection",
                      "description": "Simulated: user added to privileged group.",
                      "severity": "High", "frameworks": ["CIS 5.4", "NIST PR.AC-4"],
                      "mitre_attack": "T1098 - Account Manipulation",
                      "issue": "demo_admin_user was added to Domain Admins."}],
        "summary": "Demo: Privileged group change detected. May indicate privilege escalation.",
    },
    "Multiple Risks": {
        "score": 35, "tier": "POOR",
        "maturity": "Level 1 - Initial / Limited Visibility",
        "findings": [
            {"category": "Account Security", "control": "Stale Account Detection",
             "description": "Simulated: multiple stale accounts.", "severity": "Medium",
             "frameworks": ["CIS 5.3"], "mitre_attack": "IOE", "issue": "Multiple stale accounts found."},
            {"category": "Account Security", "control": "Brute Force Detection",
             "description": "Simulated: repeated failed logons.", "severity": "High",
             "frameworks": ["NIST DE.CM-3", "CIS 8.11"], "mitre_attack": "T1110 - Brute Force",
             "issue": "demo_user generated repeated failed logons."},
            {"category": "AD Delegation", "control": "Privileged Group Change Detection",
             "description": "Simulated: privileged group membership changed.", "severity": "High",
             "frameworks": ["CIS 5.4", "NIST PR.AC-4"], "mitre_attack": "T1098 - Account Manipulation",
             "issue": "demo_admin_user added to Domain Admins."},
        ],
        "summary": "Demo: Multiple findings significantly reduce the SOC readiness score.",
    },
}


def score_color(score) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return TEXT
    if s >= 80: return GREEN
    if s >= 60: return PURPLE_SOFT
    if s >= 40: return YELLOW
    return RED


# ============================================================
# SECTION 10 — MAIN APPLICATION CLASS
# Matches Vaqas UI layout exactly, uses real backend
# ============================================================

import customtkinter as ctk

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


class SOCProbeApp:

    def __init__(self, root: ctk.CTk):
        self.root = root
        self.root.title("SOCProbe v1.0 - IAM Compliance Auditor")
        self.root.geometry("1500x930")
        self.root.minsize(1250, 820)
        self.root.configure(fg_color=BG)

        self.config = load_config()
        self.report_json_path = Path(self.config["output"]["report_path"])
        self.report_pdf_path  = Path(self.config["output"]["pdf_report_path"])
        self.report_html_path = Path(self.config["output"]["html_report_path"])
        self.current_report   = None
        self.scanning         = False
        self.monitoring_enabled = False

        # scope vars
        self.scan_ad_var        = ctk.BooleanVar(value=True)
        self.scan_logs_var      = ctk.BooleanVar(value=True)
        self.scan_audit_var     = ctk.BooleanVar(value=True)
        self.scan_detection_var = ctk.BooleanVar(value=True)

        # framework vars
        self.fw_nist_var  = ctk.BooleanVar(value=True)
        self.fw_cis_var   = ctk.BooleanVar(value=True)
        self.fw_iso_var   = ctk.BooleanVar(value=True)
        self.fw_mitre_var = ctk.BooleanVar(value=True)

        self._apply_treeview_style()
        self._build_ui()
        self._log("SOCProbe loaded. Ready.", "info")
        self.root.after(200, self._run_startup_checks)

    # ------------------------------------------------------------------
    # TREEVIEW STYLE
    # ------------------------------------------------------------------

    def _apply_treeview_style(self):
        style = ttk.Style()
        try:
            style.theme_use("default")
        except Exception:
            pass
        style.configure("Purple.Treeview",
            background=PANEL, foreground="#e5e7eb",
            fieldbackground=PANEL, rowheight=58,
            borderwidth=0, font=("Segoe UI", 10))
        style.configure("Purple.Treeview.Heading",
            background=PURPLE_DARK, foreground="white",
            font=("Segoe UI", 10, "bold"), padding=10)
        style.map("Purple.Treeview",
            background=[("selected", PURPLE)],
            foreground=[("selected", TEXT)])

    # ------------------------------------------------------------------
    # UI BUILD  (mirrors Vaqas layout top-to-bottom)
    # ------------------------------------------------------------------

    def _build_ui(self):
        outer = ctk.CTkFrame(self.root, fg_color=BG)
        outer.pack(fill="both", expand=True, padx=24, pady=(16, 8))

        self._build_header(outer)
        self._build_nav_tabs(outer)
        self._build_scope_row(outer)
        self._build_kpi_cards(outer)
        self._build_action_buttons(outer)
        self._build_demo_panel(outer)
        self._build_main_content(outer)
        self._build_footer(outer)

    # ------------------------------------------------------------------
    # HEADER  (SOCProbe title + subtitle)
    # ------------------------------------------------------------------

    def _build_header(self, parent):
        hdr = ctk.CTkFrame(parent, fg_color=BG)
        hdr.pack(fill="x", pady=(0, 8))
        org  = self.config["organization"]
        dom  = self.config["domain"]
        ctk.CTkLabel(hdr, text="SOCProbe",
                     font=("Segoe UI", 32, "bold"),
                     text_color=TEXT, fg_color=BG).pack(anchor="w")
        ctk.CTkLabel(hdr,
                     text=f"{org['name']}  |  {dom.get('fqdn','')}  |  {dom.get('server','')}:{dom.get('port',389)}",
                     font=("Segoe UI", 10), text_color=MUTED, fg_color=BG).pack(anchor="w", pady=(2, 0))
        ctk.CTkLabel(hdr,
                     text="IAM Compliance Auditor  |  Active Directory + Windows Security Logs",
                     font=("Segoe UI", 9), text_color="#9ca3af", fg_color=BG).pack(anchor="w", pady=(2, 0))

    # ------------------------------------------------------------------
    # NAV TABS  (Account Security | Entra ID)
    # ------------------------------------------------------------------

    def _build_nav_tabs(self, parent):
        nav = ctk.CTkFrame(parent, fg_color=PANEL, corner_radius=8,
                           border_color=BORDER, border_width=1)
        nav.pack(fill="x", pady=(0, 8))
        tabs = [("Account Security", True), ("Entra ID", False)]
        for name, active in tabs:
            ctk.CTkLabel(nav, text=name,
                         font=("Segoe UI", 9, "bold"),
                         text_color="white",
                         fg_color=PURPLE if active else PANEL,
                         corner_radius=6,
                         padx=18, pady=8).pack(side="left", padx=2, pady=4)

    # ------------------------------------------------------------------
    # SCOPE + FRAMEWORK ROW
    # ------------------------------------------------------------------

    def _build_scope_row(self, parent):
        row = ctk.CTkFrame(parent, fg_color=BG)
        row.pack(fill="x", pady=(0, 8))

        ctk.CTkLabel(row, text="Scan Scope and Frameworks",
                     font=("Segoe UI", 10, "bold"),
                     text_color=TEXT, fg_color=BG).pack(anchor="w", pady=(0, 4))

        checks = ctk.CTkFrame(row, fg_color=BG)
        checks.pack(fill="x")

        ctk.CTkLabel(checks, text="Scope:", font=("Segoe UI", 9, "bold"),
                     text_color=YELLOW, fg_color=BG).pack(side="left", padx=(0, 6))
        for text, var in [
            ("Active Directory",  self.scan_ad_var),
            ("Security Logs",     self.scan_logs_var),
            ("Audit Policy",      self.scan_audit_var),
            ("Detection Rules",   self.scan_detection_var),
        ]:
            ctk.CTkCheckBox(checks, text=text, variable=var,
                            font=("Segoe UI", 9), text_color=TEXT,
                            fg_color=PURPLE, hover_color=PURPLE_SOFT,
                            checkmark_color=TEXT, border_color=PURPLE_SOFT,
                            width=18, height=18).pack(side="left", padx=8)

        ctk.CTkLabel(checks, text="Frameworks:", font=("Segoe UI", 9, "bold"),
                     text_color=YELLOW, fg_color=BG).pack(side="left", padx=(24, 6))
        for text, var in [
            ("NIST",     self.fw_nist_var),
            ("CIS",      self.fw_cis_var),
            ("ISO 27001", self.fw_iso_var),
            ("MITRE",    self.fw_mitre_var),
        ]:
            ctk.CTkCheckBox(checks, text=text, variable=var,
                            font=("Segoe UI", 9), text_color=TEXT,
                            fg_color=PURPLE, hover_color=PURPLE_SOFT,
                            checkmark_color=TEXT, border_color=PURPLE_SOFT,
                            width=18, height=18).pack(side="left", padx=8)

    # ------------------------------------------------------------------
    # KPI CARDS  (Score | Risk Tier | SOC Maturity | Startup status)
    # ------------------------------------------------------------------

    def _build_kpi_cards(self, parent):
        row = ctk.CTkFrame(parent, fg_color=BG)
        row.pack(fill="x", pady=(0, 8))

        # Score
        sc = self._kpi_card(row, "SOC Readiness Score", "-- / 100", GREEN)
        self.score_label = sc

        # Risk tier
        tc = self._kpi_card(row, "Risk Tier", "Not scanned", YELLOW)
        self.tier_label = tc

        # Maturity
        mc = self._kpi_card(row, "SOC Maturity", "Not scanned", PURPLE_SOFT, width=360)
        self.maturity_label = mc

        # AD + Log status (right side)
        status_card = ctk.CTkFrame(row, fg_color=PANEL, corner_radius=8,
                                   border_color=BORDER, border_width=1)
        status_card.pack(side="left", fill="y", padx=(10, 0), ipady=6, ipadx=12)
        ctk.CTkLabel(status_card, text="CONNECTIONS",
                     font=("Segoe UI", 8, "bold"), text_color=MUTED,
                     fg_color=PANEL).pack(anchor="w", padx=10, pady=(8, 2))
        self.ad_status    = self._conn_pill(status_card, "Active Directory")
        self.event_status = self._conn_pill(status_card, "Security Log")

    def _kpi_card(self, parent, title, value, accent, width=240):
        frame = ctk.CTkFrame(parent, fg_color=PANEL, corner_radius=8,
                             border_color=accent, border_width=1,
                             width=width)
        frame.pack(side="left", padx=(0, 10), ipady=10, ipadx=14)
        frame.pack_propagate(False)
        ctk.CTkLabel(frame, text=title, font=("Segoe UI", 9, "bold"),
                     text_color=MUTED, fg_color=PANEL).pack(anchor="w", padx=14, pady=(10, 0))
        lbl = ctk.CTkLabel(frame, text=value, font=("Segoe UI", 18, "bold"),
                           text_color=TEXT, fg_color=PANEL)
        lbl.pack(anchor="w", padx=14, pady=(4, 10))
        return lbl

    def _conn_pill(self, parent, label) -> dict:
        row = ctk.CTkFrame(parent, fg_color=PANEL)
        row.pack(fill="x", padx=10, pady=2)
        ctk.CTkLabel(row, text=label, font=("Segoe UI", 9),
                     text_color=TEXT, fg_color=PANEL).pack(side="left")
        badge = ctk.CTkLabel(row, text=" Checking ",
                             font=("Segoe UI", 8, "bold"),
                             text_color=TEXT, fg_color=PURPLE_DARK, corner_radius=6)
        badge.pack(side="right")
        detail = ctk.CTkLabel(parent, text="",
                              font=("Segoe UI", 8), text_color=MUTED,
                              fg_color=PANEL, wraplength=200, justify="left")
        detail.pack(anchor="w", padx=10)
        return {"badge": badge, "detail": detail}

    # ------------------------------------------------------------------
    # ACTION BUTTONS
    # ------------------------------------------------------------------

    def _build_action_buttons(self, parent):
        row = ctk.CTkFrame(parent, fg_color=BG)
        row.pack(fill="x", pady=(0, 8))

        self.run_btn = ctk.CTkButton(row, text="Run Real SOC Assessment",
                                     command=self._start_assessment,
                                     fg_color=PURPLE, hover_color=PURPLE_SOFT,
                                     text_color=TEXT, font=("Segoe UI", 9, "bold"),
                                     height=36, corner_radius=6)
        self.run_btn.pack(side="left", padx=(0, 6))

        self.monitor_btn = ctk.CTkButton(row, text="Start Monitoring",
                                         command=self._toggle_monitoring,
                                         fg_color="#15803d", hover_color="#166534",
                                         text_color=TEXT, font=("Segoe UI", 9, "bold"),
                                         height=36, corner_radius=6)
        self.monitor_btn.pack(side="left", padx=6)

        for text, cmd in [
            ("Open JSON Report",      lambda: self._open_path(self.report_json_path)),
            ("Open Executive Report", lambda: self._open_path(self.report_html_path)),
            ("Open Score History",    self._open_history),
        ]:
            btn = ctk.CTkButton(row, text=text, command=cmd,
                                fg_color=PANEL_2, hover_color=PANEL,
                                text_color=TEXT, font=("Segoe UI", 9),
                                height=36, corner_radius=6)
            btn.pack(side="left", padx=6)

        self.monitor_status = ctk.CTkLabel(row, text="Monitoring: OFF",
                                           font=("Segoe UI", 10, "bold"),
                                           text_color=RED, fg_color=BG)
        self.monitor_status.pack(side="left", padx=14)

    # ------------------------------------------------------------------
    # PROFESSOR DEMO PANEL
    # ------------------------------------------------------------------

    def _build_demo_panel(self, parent):
        demo = ctk.CTkFrame(parent, fg_color=BG, corner_radius=8,
                            border_color=YELLOW, border_width=1)
        demo.pack(fill="x", pady=(0, 8))
        inner = ctk.CTkFrame(demo, fg_color=BG)
        inner.pack(fill="x", padx=10, pady=8)

        ctk.CTkLabel(inner,
                     text="Professor Demo Mode - Simulated Scenarios Only",
                     font=("Segoe UI", 10, "bold"), text_color=YELLOW,
                     fg_color=BG).pack(side="left", padx=(0, 12))

        self.scenario_label = ctk.CTkLabel(inner, text="Active Scenario: None",
                                           font=("Segoe UI", 9, "bold"),
                                           text_color=MUTED, fg_color=BG)
        self.scenario_label.pack(side="left", padx=(0, 14))

        scenarios = [
            ("Clean",            "Clean Environment",  "#166534"),
            ("Stale Accounts",   "Stale Accounts",     PURPLE_DARK),
            ("Brute Force",      "Brute Force",        "#b45309"),
            ("Privileged Change","Privileged Change",  "#b91c1c"),
            ("Multiple Risks",   "Multiple Risks",     "#7f1d1d"),
            ("Clear Demo",       "Clear Demo",         PANEL_2),
        ]
        for btn_label, key, color in scenarios:
            ctk.CTkButton(inner, text=btn_label, width=110, height=32,
                          fg_color=color, hover_color=PURPLE,
                          text_color=TEXT, font=("Segoe UI", 9, "bold"),
                          corner_radius=6,
                          command=lambda k=key: self._run_demo(k)
                          ).pack(side="left", padx=4)

        ctk.CTkLabel(inner,
                     text="No users are created or modified in demo mode.",
                     font=("Segoe UI", 8), text_color="#9ca3af",
                     fg_color=BG).pack(side="right", padx=8)

    # ------------------------------------------------------------------
    # MAIN CONTENT  (left col: alerts + summary | right col: table)
    # ------------------------------------------------------------------

    def _build_main_content(self, parent):
        content = ctk.CTkFrame(parent, fg_color=BG)
        content.pack(fill="both", expand=True, pady=(0, 4))

        # Left column
        left = ctk.CTkFrame(content, fg_color=BG, width=380)
        left.pack(side="left", fill="y", padx=(0, 10))
        left.pack_propagate(False)

        # Active Alert Panel
        alert_outer = ctk.CTkFrame(left, fg_color=BG, corner_radius=8,
                                   border_color=MUTED, border_width=1)
        alert_outer.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(alert_outer, text="Active Alert Panel",
                     font=("Segoe UI", 10, "bold"), text_color=MUTED,
                     fg_color=BG).pack(anchor="w", padx=10, pady=(8, 4))
        self.alert_box = ctk.CTkTextbox(alert_outer, fg_color=PANEL,
                                        text_color=YELLOW, font=("Consolas", 9),
                                        corner_radius=6, wrap="word",
                                        state="disabled", height=160)
        self.alert_box.pack(fill="x", padx=10, pady=(0, 10))
        self._write_box(self.alert_box, "No scan has been run yet.")

        # Executive Summary
        summ_outer = ctk.CTkFrame(left, fg_color=BG, corner_radius=8,
                                  border_color=MUTED, border_width=1)
        summ_outer.pack(fill="both", expand=True)
        ctk.CTkLabel(summ_outer, text="Executive Summary",
                     font=("Segoe UI", 10, "bold"), text_color=MUTED,
                     fg_color=BG).pack(anchor="w", padx=10, pady=(8, 4))
        self.summary_box = ctk.CTkTextbox(summ_outer, fg_color=PANEL,
                                          text_color="#e5e7eb", font=("Consolas", 9),
                                          corner_radius=6, wrap="word",
                                          state="disabled")
        self.summary_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self._write_box(self.summary_box, "Run an assessment to generate the executive summary.")

        # Right column - findings table
        right = ctk.CTkFrame(content, fg_color=BG)
        right.pack(side="left", fill="both", expand=True)

        # Table header
        thdr = ctk.CTkFrame(right, fg_color=BG)
        thdr.pack(fill="x", pady=(0, 6))
        ctk.CTkLabel(thdr, text="Threat Indicator Findings",
                     font=("Segoe UI", 14, "bold"), text_color=TEXT,
                     fg_color=BG).pack(side="left")
        ctk.CTkLabel(thdr, text="Double-click a finding for investigation guidance",
                     font=("Segoe UI", 9), text_color="#9ca3af",
                     fg_color=BG).pack(side="right")

        # Treeview
        table_wrap = ctk.CTkFrame(right, fg_color=PANEL, corner_radius=8,
                                  border_color=BORDER, border_width=1)
        table_wrap.pack(fill="both", expand=True)

        cols = ("Category", "Indicator Name", "Description", "Severity", "Framework", "IOE/IOC")
        self.findings_table = ttk.Treeview(table_wrap, columns=cols,
                                            show="headings", height=14,
                                            style="Purple.Treeview")
        for col in cols:
            self.findings_table.heading(col, text=col)
        self.findings_table.column("Category",       width=140)
        self.findings_table.column("Indicator Name", width=200)
        self.findings_table.column("Description",    width=460)
        self.findings_table.column("Severity",       width=100)
        self.findings_table.column("Framework",      width=230)
        self.findings_table.column("IOE/IOC",        width=160)

        self.findings_table.tag_configure("high",
            background="#3b1022", foreground="#fecaca")
        self.findings_table.tag_configure("medium",
            background="#2e163f", foreground="#f5d0fe")

        sb = ttk.Scrollbar(table_wrap, orient="vertical",
                           command=self.findings_table.yview)
        self.findings_table.configure(yscrollcommand=sb.set)
        self.findings_table.pack(side="left", fill="both", expand=True, padx=8, pady=8)
        sb.pack(side="right", fill="y", pady=8)
        self.findings_table.bind("<Double-1>", self._on_finding_click)

        # Activity log below table
        log_outer = ctk.CTkFrame(right, fg_color=BG, corner_radius=8,
                                 border_color=MUTED, border_width=1, height=100)
        log_outer.pack(fill="x", pady=(8, 0))
        log_outer.pack_propagate(False)
        ctk.CTkLabel(log_outer, text="Activity Log",
                     font=("Segoe UI", 9, "bold"), text_color=MUTED,
                     fg_color=BG).pack(anchor="w", padx=10, pady=(6, 2))
        self.log_box = ctk.CTkTextbox(log_outer, fg_color=PANEL,
                                      text_color=TEXT, font=("Consolas", 9),
                                      corner_radius=6, wrap="word", state="disabled")
        self.log_box.pack(fill="both", expand=True, padx=10, pady=(0, 8))
        self.log_box._textbox.tag_config("info",    foreground=PURPLE_SOFT)
        self.log_box._textbox.tag_config("success", foreground=GREEN)
        self.log_box._textbox.tag_config("warn",    foreground=YELLOW)
        self.log_box._textbox.tag_config("fail",    foreground=RED)
        self.log_box._textbox.tag_config("muted",   foreground=MUTED)

    # ------------------------------------------------------------------
    # FOOTER
    # ------------------------------------------------------------------

    def _build_footer(self, parent):
        ctk.CTkLabel(parent,
            text="SOCProbe Capstone Prototype  |  Real scan mode + professor-safe simulation mode  |  Read-only assessment output",
            font=("Segoe UI", 9), text_color="#9ca3af", fg_color=BG
        ).pack(pady=(4, 0))

    # ------------------------------------------------------------------
    # HELPERS
    # ------------------------------------------------------------------

    def _write_box(self, box, value: str):
        box.configure(state="normal")
        box.delete("1.0", "end")
        box.insert("end", value)
        box.configure(state="disabled")

    def _log(self, message: str, tag: str = "info"):
        self.log_box.configure(state="normal")
        self.log_box._textbox.insert("end", f"{message}\n", tag)
        self.log_box._textbox.see("end")
        self.log_box.configure(state="disabled")

    def _set_conn_status(self, widget: dict, label: str, color: str, detail: str):
        widget["badge"].configure(text=f" {label} ", fg_color=color)
        widget["detail"].configure(text=detail)

    def _update_findings_table(self, findings: list):
        for item in self.findings_table.get_children():
            self.findings_table.delete(item)
        alerts = []
        for f in findings:
            sev  = f.get("severity", "Medium")
            tag  = "high" if sev == "High" else "medium"
            fws  = f.get("frameworks", [])
            fw_str = ", ".join(fws) if isinstance(fws, list) else str(fws)
            self.findings_table.insert("", "end", values=(
                f.get("category", ""),
                f.get("control", ""),
                f.get("description", f.get("finding", "")),
                sev,
                fw_str,
                f.get("mitre_attack", "N/A"),
            ), tags=(tag,))
            if sev == "High":
                alerts.append(
                    f"ACTIVE ALERT: {f.get('control','')} | {f.get('issue', f.get('finding',''))} | {f.get('mitre_attack','N/A')}")
        self._write_box(self.alert_box,
                        "\n".join(alerts) if alerts else "No active high-severity alerts detected.")

    def _on_finding_click(self, event):
        sel = self.findings_table.focus()
        if not sel:
            return
        vals = self.findings_table.item(sel, "values")
        if not vals:
            return
        messagebox.showinfo("Indicator Drill-Down",
            f"Category: {vals[0]}\nIndicator: {vals[1]}\nDescription: {vals[2]}\n"
            f"Severity: {vals[3]}\nFramework: {vals[4]}\nIOE/IOC: {vals[5]}\n\n"
            "Suggested investigation:\n"
            "- Review related Windows Security events.\n"
            "- Validate whether the activity was expected.\n"
            "- Confirm affected account, source machine, and timestamp.\n"
            "- Apply remediation from the generated executive report.")

    # ------------------------------------------------------------------
    # STARTUP CHECKS
    # ------------------------------------------------------------------

    def _run_startup_checks(self):
        threading.Thread(target=self._startup_worker, daemon=True).start()

    def _startup_worker(self):
        ad  = test_ad_connection(self.config)
        evl = get_event_log_status("Security")
        self.root.after(0, lambda: self._apply_startup(ad, evl))

    def _apply_startup(self, ad, evl):
        if ad["connected"]:
            self._set_conn_status(self.ad_status, "Connected", "#166534", ad["message"])
            self._log("Active Directory connection verified.", "success")
        else:
            self._set_conn_status(self.ad_status, "Failed", "#7f1d1d", ad["message"])
            self._log("Active Directory connection failed.", "fail")
        if evl["accessible"]:
            self._set_conn_status(self.event_status, "Connected", "#166534",
                                  f"Security log: {evl['record_count']} records.")
            self._log("Windows Security Log access verified.", "success")
        else:
            self._set_conn_status(self.event_status, "Failed", "#7f1d1d",
                                  evl.get("error", "Unavailable"))
            self._log("Windows Security Log access failed.", "fail")

    # ------------------------------------------------------------------
    # ASSESSMENT
    # ------------------------------------------------------------------

    def _start_assessment(self):
        if self.scanning:
            return
        self.scanning = True
        self.run_btn.configure(state="disabled")
        self._log("Starting SOC assessment...", "info")
        threading.Thread(target=self._assessment_worker, daemon=True).start()

    def _assessment_worker(self):
        conn = None
        try:
            config = self.config

            # Read scope selections from checkboxes (captured on the calling thread)
            run_ad        = self.scan_ad_var.get()
            run_logs      = self.scan_logs_var.get()
            run_detection = self.scan_detection_var.get()

            if not run_ad and not run_logs and not run_detection:
                self.root.after(0, lambda: self._apply_error(
                    Exception("No scan scope selected. Tick at least one scope checkbox.")))
                return

            findings_dict = {}

            # --- Active Directory scope ---
            if run_ad:
                self._progress("Connecting to Active Directory")
                conn = connect_to_ad(config)

                self._progress("Checking privileged groups")
                findings_dict["privileged_groups"] = check_privileged_groups(conn, config)

                self._progress("Checking stale accounts")
                findings_dict["stale_accounts"] = check_stale_accounts(conn, config)

                self._progress("Checking disabled accounts")
                findings_dict["disabled_accounts"] = check_disabled_accounts(conn, config)
            else:
                self._progress("Skipping Active Directory scan (unchecked)")

            # --- Security Logs scope ---
            if run_logs:
                self._progress("Validating Security Log")
                evl = get_event_log_status("Security")
                self.root.after(0, lambda: self._set_conn_status(
                    self.event_status,
                    "Connected" if evl["accessible"] else "Failed",
                    "#166534" if evl["accessible"] else "#7f1d1d",
                    f"Security log: {evl.get('record_count', 0)} records." if evl["accessible"]
                    else evl.get("error", "Unavailable")))
                self._progress("Reading security events")
                findings_dict["log_validation"] = read_security_events(config)
            else:
                self._progress("Skipping Security Log scan (unchecked)")

            # --- Detection Rules scope ---
            if run_detection:
                self._progress("Detecting brute force activity")
                findings_dict["brute_force"] = detect_bruteforce(config)

                self._progress("Detecting privileged group changes")
                findings_dict["priv_group_change"] = detect_privileged_group_change(config)
            else:
                self._progress("Skipping detection rules (unchecked)")

            self._progress("Calculating score and generating reports")
            score, tier = calculate_score(findings_dict, config)
            result = generate_report(findings_dict, score, tier, config)

            self.root.after(0, lambda: self._apply_results(findings_dict, score, tier, result))

        except Exception as exc:
            self.root.after(0, lambda: self._apply_error(exc))
        finally:
            if conn is not None and conn.bound:
                conn.unbind()

    def _progress(self, msg: str):
        self.root.after(0, lambda: self._log(msg, "muted"))
        time.sleep(0.06)

    def _apply_results(self, findings_dict, score, tier, result):
        self.scanning = False
        self.run_btn.configure(state="normal")

        self.score_label.configure(text=f"{score:.1f} / 100",
                                   text_color=score_color(score))
        self.tier_label.configure(text=tier, text_color=score_color(score))
        maturity = result.get("soc_maturity", "")
        self.maturity_label.configure(text=maturity)
        self.scenario_label.configure(text="Active Scenario: Real Scan")
        self._write_box(self.summary_box, result.get("executive_summary", ""))

        # Convert findings_dict to list format matching Vaqas's display structure
        findings_list = []
        category_map = {
            "privileged_groups": "Account Security",
            "stale_accounts":    "Account Security",
            "disabled_accounts": "Account Security",
            "log_validation":    "AD Infrastructure",
            "brute_force":       "Account Security",
            "priv_group_change": "AD Delegation",
        }
        for key, _, mitre_label in CONTROL_ORDER:
            f = findings_dict.get(key, {})
            if not isinstance(f, dict):
                continue
            findings_list.append({
                "category":    category_map.get(key, "Account Security"),
                "control":     key.replace("_", " ").title(),
                "description": f.get("finding", ""),
                "severity":    "Medium" if not f.get("passed", True) else "Pass",
                "frameworks":  f.get("frameworks", []),
                "mitre_attack": f.get("mitre_attack", mitre_label),
                "issue":       f.get("finding", ""),
            })
        bf = findings_dict.get("brute_force", {})
        if bf.get("detected"):
            findings_list.append({
                "category": "Account Security", "control": "Brute Force Detection",
                "description": f"Flagged accounts: {bf.get('flagged_accounts',{})}",
                "severity": "High", "frameworks": ["NIST DE.CM-3", "CIS 8.11"],
                "mitre_attack": "T1110 - Brute Force",
                "issue": str(bf.get("flagged_accounts", {})),
            })
        pgc = findings_dict.get("priv_group_change", {})
        if pgc.get("detected"):
            findings_list.append({
                "category": "AD Delegation", "control": "Privileged Group Change",
                "description": f"Event ID 4728 detected {pgc.get('count',0)} time(s).",
                "severity": "High", "frameworks": ["CIS 5.4", "NIST PR.AC-4"],
                "mitre_attack": "T1098 - Account Manipulation",
                "issue": f"4728 count: {pgc.get('count',0)}",
            })

        self._update_findings_table(findings_list)
        self._log(f"Assessment complete: {score:.1f}/100 ({tier}).", "success")
        if bf.get("detected"):
            self._log("Brute force detected. -10 score penalty applied.", "warn")
        if pgc.get("detected"):
            self._log("Privileged group change detected. -5 penalty applied.", "warn")

        high = [f for f in findings_list if f["severity"] == "High"]
        if high:
            messagebox.showwarning("High Risk Detected",
                                   "High severity indicators detected.\nReview the indicator table.")

    def _apply_error(self, exc: Exception):
        self.scanning = False
        self.run_btn.configure(state="normal")
        self._log(f"Assessment failed: {exc}", "fail")

    # ------------------------------------------------------------------
    # MONITORING
    # ------------------------------------------------------------------

    def _toggle_monitoring(self):
        if self.monitoring_enabled:
            self.monitoring_enabled = False
            self.monitor_btn.configure(text="Start Monitoring", fg_color="#15803d")
            self.monitor_status.configure(text="Monitoring: OFF", text_color=RED)
            self._log("Monitoring stopped.", "muted")
        else:
            self.monitoring_enabled = True
            self.monitor_btn.configure(text="Stop Monitoring", fg_color="#b91c1c")
            self.monitor_status.configure(text="Monitoring: ON", text_color=GREEN)
            self._log("Monitoring started. Re-running every 15 seconds.", "info")
            self._monitor_loop()

    def _monitor_loop(self):
        if self.monitoring_enabled and not self.scanning:
            self._start_assessment()
        if self.monitoring_enabled:
            self.root.after(15000, self._monitor_loop)

    # ------------------------------------------------------------------
    # DEMO MODE
    # ------------------------------------------------------------------

    def _run_demo(self, scenario_name: str):
        if scenario_name == "Clear Demo":
            self.scenario_label.configure(text="Active Scenario: None")
            self.score_label.configure(text="-- / 100", text_color=TEXT)
            self.tier_label.configure(text="Not scanned", text_color=YELLOW)
            self.maturity_label.configure(text="Not scanned")
            self._write_box(self.summary_box,
                "Demo cleared. Click Run Real SOC Assessment or select a scenario.")
            self._write_box(self.alert_box, "No active alerts.")
            for item in self.findings_table.get_children():
                self.findings_table.delete(item)
            return

        scenario = DEMO_SCENARIOS.get(scenario_name)
        if not scenario:
            return

        self.scenario_label.configure(text=f"Active Scenario: {scenario_name}")
        score = scenario["score"]
        tier  = scenario["tier"]
        self.score_label.configure(text=f"{score} / 100", text_color=score_color(score))
        self.tier_label.configure(text=tier, text_color=score_color(score))
        self.maturity_label.configure(text=scenario["maturity"])
        self._write_box(self.summary_box, scenario["summary"])
        self._update_findings_table(scenario["findings"])
        self._log(f"Demo scenario loaded: {scenario_name} ({score}/100 {tier})", "info")

    # ------------------------------------------------------------------
    # FILE OPS
    # ------------------------------------------------------------------

    def _open_path(self, path: Path):
        if not path.exists():
            self._log(f"Report not found: {path}", "fail")
            messagebox.showerror("File Not Found", f"Report not found:\n{path}")
            return
        os.startfile(str(path))

    def _open_history(self):
        hp = Path(self.config["output"]["history_path"])
        if hp.exists():
            os.startfile(str(hp))
        else:
            messagebox.showinfo("No History", "No score history file exists yet.")


# ============================================================
# SECTION 11 — ENTRY POINT
# ============================================================

def launch_app():
    try:
        import customtkinter  # noqa
    except ImportError:
        import tkinter.messagebox as mb
        mb.showerror("Missing dependency",
                     "customtkinter is not installed.\n\nRun: python.exe -m pip install customtkinter")
        return

    root = ctk.CTk()
    try:
        SOCProbeApp(root)
        root.mainloop()
    except ConfigLoadError as exc:
        root.withdraw()
        messagebox.showerror(
            "SOCProbe - Configuration Missing",
            f"config.json not found.\n\nExpected: {exc.expected_path}\n\n"
            "Copy config.template.json to config.json and fill in your AD credentials.",
            parent=root,
        )
        root.destroy()


if __name__ == "__main__":
    launch_app()