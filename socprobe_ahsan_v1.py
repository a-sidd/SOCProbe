# ============================================================
# SOCProbe v1.0
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
from tkinter import filedialog, font as tkfont, messagebox, ttk
import tkinter as tk

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
# SECTION 9 — UI THEME AND CONSTANTS
# ============================================================

APP_BG    = "#09131E"
PANEL_BG  = "#112436"
CARD_BG   = "#173149"
CARD_ALT  = "#1D405E"
SURFACE   = "#214761"
SURFACE2  = "#2B5978"
TEXT      = "#E8F4FF"
MUTED     = "#93ACC2"
ACCENT    = "#28C7FF"
SUCCESS   = "#53D48E"
WARNING   = "#F2B94B"
FAIL      = "#FF6A7F"
BORDER    = "#2A4D68"

CONTROL_ORDER = [
    ("privileged_groups",  "Privileged Group Analysis",         "T1078"),
    ("stale_accounts",     "Stale Account Detection",           "T1078.002"),
    ("disabled_accounts",  "Disabled Privileged Accounts",      "T1098"),
    ("log_validation",     "Windows Security Log Analysis",     "T1562.002"),
]

TIER_MAP = [
    ("80-100", "HIGH READINESS"),
    ("60-79",  "MODERATE"),
    ("40-59",  "LOW"),
    ("Below 40", "POOR"),
]

PROGRESS_STEPS = [
    "Loading configuration",
    "Validating environment",
    "Connecting to Active Directory",
    "Validating Windows Security Log",
    "Enumerating privileged groups",
    "Checking stale accounts",
    "Checking disabled privileged accounts",
    "Reading security events",
    "Detecting brute force activity",
    "Detecting privileged group changes",
    "Calculating score",
    "Generating JSON report",
    "Generating PDF report",
    "Generating HTML report",
    "Finalizing assessment",
]

DEMO_SCENARIOS = {
    "Clean Environment": {
        "score": 95, "tier": "HIGH READINESS",
        "findings": [],
        "summary": "Demo: Clean environment. No high-severity indicators detected.",
    },
    "Stale Accounts": {
        "score": 78, "tier": "MODERATE",
        "findings": [{"control": "Stale Account Detection", "severity": "Medium",
                      "issue": "stale_user01 and stale_user02 inactive >45 days.",
                      "mitre": "IOE", "frameworks": ["CIS 5.3", "NIST PR.AC-6"]}],
        "summary": "Demo: Stale accounts reduce score. Inactive accounts can become unauthorized access points.",
    },
    "Brute Force": {
        "score": 55, "tier": "LOW",
        "findings": [{"control": "Brute Force Detection", "severity": "High",
                      "issue": "demo_user: 10 failed logons in 24 hours.",
                      "mitre": "T1110 - Brute Force", "frameworks": ["NIST DE.CM-3", "CIS 8.11"]}],
        "summary": "Demo: Active credential attack detected. Score penalized by brute force detection.",
    },
    "Privileged Change": {
        "score": 60, "tier": "MODERATE",
        "findings": [{"control": "Privileged Group Change Detection", "severity": "High",
                      "issue": "demo_admin_user added to Domain Admins.",
                      "mitre": "T1098 - Account Manipulation", "frameworks": ["CIS 5.4", "NIST PR.AC-4"]}],
        "summary": "Demo: Privileged group change detected. May indicate privilege escalation.",
    },
    "Multiple Risks": {
        "score": 35, "tier": "POOR",
        "findings": [
            {"control": "Stale Account Detection", "severity": "Medium",
             "issue": "Multiple stale accounts found.", "mitre": "IOE", "frameworks": ["CIS 5.3"]},
            {"control": "Brute Force Detection", "severity": "High",
             "issue": "demo_user: repeated failed logons.", "mitre": "T1110 - Brute Force", "frameworks": ["NIST DE.CM-3"]},
            {"control": "Privileged Group Change", "severity": "High",
             "issue": "demo_admin_user added to Domain Admins.", "mitre": "T1098", "frameworks": ["CIS 5.4"]},
        ],
        "summary": "Demo: Multiple findings significantly reduce the SOC readiness score.",
    },
}


def score_color(score) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return TEXT
    if s >= 80:
        return SUCCESS
    if s >= 60:
        return ACCENT
    if s >= 40:
        return WARNING
    return FAIL


# ============================================================
# SECTION 10 — MAIN APPLICATION CLASS
# ============================================================

class SOCProbeApp:

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SOCProbe v1.0")
        self.root.geometry("1400x960")
        self.root.minsize(1200, 820)
        self.root.configure(bg=APP_BG)

        self.config = load_config()
        self.report_json_path = Path(self.config["output"]["report_path"])
        self.report_pdf_path  = Path(self.config["output"]["pdf_report_path"])
        self.report_html_path = Path(self.config["output"]["html_report_path"])
        self.current_report = None
        self.scanning = False
        self.monitoring_enabled = False
        self.last_scan_summary = "No scan run yet"

        # Fonts
        self.f_title  = tkfont.Font(family="Segoe UI Semibold", size=26)
        self.f_h2     = tkfont.Font(family="Segoe UI Semibold", size=14)
        self.f_h3     = tkfont.Font(family="Segoe UI Semibold", size=11)
        self.f_body   = tkfont.Font(family="Segoe UI", size=10)
        self.f_small  = tkfont.Font(family="Segoe UI", size=9)
        self.f_score  = tkfont.Font(family="Segoe UI Semibold", size=52)
        self.f_mono   = tkfont.Font(family="Consolas", size=10)
        self.f_mono_s = tkfont.Font(family="Consolas", size=9)

        self.control_widgets = {}
        self.scoring_rows = {}

        self._build_ui()
        self._update_scoring_tab()
        self._log("SOCProbe loaded.", "info")
        self.root.after(200, self._run_startup_checks)

    # ---- UI BUILD ----

    def _build_ui(self):
        shell = tk.Frame(self.root, bg=APP_BG)
        shell.pack(fill="both", expand=True, padx=18, pady=18)
        self._build_header(shell)
        content = tk.Frame(shell, bg=APP_BG)
        content.pack(fill="both", expand=True, pady=(14, 0))
        left = tk.Frame(content, bg=APP_BG)
        left.pack(side="left", fill="both", expand=True, padx=(0, 10))
        right = tk.Frame(content, bg=APP_BG, width=370)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)
        self._build_notebook(left)
        self._build_side_panel(right)

    def _build_header(self, parent):
        frame = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        frame.pack(fill="x")
        tk.Frame(frame, bg=ACCENT, height=3).pack(fill="x")
        inner = tk.Frame(frame, bg=PANEL_BG)
        inner.pack(fill="x", padx=20, pady=16)
        left = tk.Frame(inner, bg=PANEL_BG)
        left.pack(side="left", fill="x", expand=True)
        tk.Label(left, text="SOCProbe", bg=PANEL_BG, fg=TEXT, font=self.f_title).pack(anchor="w")
        domain = self.config["domain"]
        org = self.config["organization"]
        tk.Label(left, text="IAM Compliance Auditor for Active Directory and Windows Security Logs",
                 bg=PANEL_BG, fg=MUTED, font=self.f_body).pack(anchor="w", pady=(4, 0))
        tk.Label(left, text=f"{org['name']} | {domain.get('fqdn', '')} | {domain.get('server', '')}:{domain.get('port', 389)}",
                 bg=PANEL_BG, fg=MUTED, font=self.f_small).pack(anchor="w", pady=(6, 0))
        right = tk.Frame(inner, bg=PANEL_BG)
        right.pack(side="right")
        self.status_frame = tk.Frame(right, bg=SURFACE, highlightbackground=ACCENT, highlightthickness=1)
        self.status_frame.pack(anchor="e")
        self.status_dot   = tk.Label(self.status_frame, text="●", bg=SURFACE, fg=ACCENT, font=self.f_body)
        self.status_dot.pack(side="left", padx=(10, 4), pady=8)
        self.status_label = tk.Label(self.status_frame, text="READY", bg=SURFACE, fg=TEXT, font=self.f_h3)
        self.status_label.pack(side="left", padx=(0, 12), pady=8)
        self.last_scan_lbl = tk.Label(right, text=self.last_scan_summary, bg=PANEL_BG, fg=MUTED, font=self.f_small)
        self.last_scan_lbl.pack(anchor="e", pady=(8, 0))

    def _build_notebook(self, parent):
        self.nb = ttk.Notebook(parent)
        self.nb.pack(fill="both", expand=True)
        tab_overview  = tk.Frame(self.nb, bg=APP_BG)
        tab_findings  = tk.Frame(self.nb, bg=APP_BG)
        tab_reports   = tk.Frame(self.nb, bg=APP_BG)
        tab_scoring   = tk.Frame(self.nb, bg=APP_BG)
        tab_demo      = tk.Frame(self.nb, bg=APP_BG)
        self.nb.add(tab_overview, text="Overview")
        self.nb.add(tab_findings, text="Findings")
        self.nb.add(tab_reports,  text="Reports")
        self.nb.add(tab_scoring,  text="Scoring Methodology")
        self.nb.add(tab_demo,     text="Demo Mode")
        self._build_overview_tab(tab_overview)
        self._build_findings_tab(tab_findings)
        self._build_reports_tab(tab_reports)
        self._build_scoring_tab(tab_scoring)
        self._build_demo_tab(tab_demo)

    # ---- OVERVIEW TAB ----

    def _build_overview_tab(self, parent):
        # Score + startup status row
        top = tk.Frame(parent, bg=APP_BG)
        top.pack(fill="x")
        score_card = tk.Frame(top, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        score_card.pack(side="left", fill="both", expand=True, padx=(0, 8))
        score_inner = tk.Frame(score_card, bg=PANEL_BG)
        score_inner.pack(fill="both", expand=True, padx=18, pady=18)
        tk.Label(score_inner, text="SOC READINESS SCORE", bg=PANEL_BG, fg=MUTED, font=self.f_small).pack(anchor="w")
        self.score_label = tk.Label(score_inner, text="--", bg=PANEL_BG, fg=TEXT, font=self.f_score)
        self.score_label.pack(anchor="w", pady=(4, 0))
        self.tier_label = tk.Label(score_inner, text="Awaiting assessment", bg=SURFACE, fg=MUTED, font=self.f_h3, padx=10, pady=6)
        self.tier_label.pack(anchor="w", pady=(6, 0))
        self.maturity_label = tk.Label(score_inner, text="", bg=PANEL_BG, fg=MUTED, font=self.f_body)
        self.maturity_label.pack(anchor="w", pady=(4, 0))
        self.summary_label = tk.Label(score_inner,
            text="Run the assessment to generate findings, remediation guidance, and JSON/PDF/HTML reports.",
            bg=PANEL_BG, fg=MUTED, font=self.f_body, wraplength=480, justify="left")
        self.summary_label.pack(anchor="w", pady=(10, 0))

        status_card = tk.Frame(top, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1, width=320)
        status_card.pack(side="right", fill="y")
        status_card.pack_propagate(False)
        si = tk.Frame(status_card, bg=PANEL_BG)
        si.pack(fill="both", expand=True, padx=18, pady=18)
        tk.Label(si, text="STARTUP STATUS", bg=PANEL_BG, fg=MUTED, font=self.f_small).pack(anchor="w")
        self.ad_status    = self._status_row(si, "Active Directory")
        self.event_status = self._status_row(si, "Security Event Log")

        # Controls
        ctrl_frame = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        ctrl_frame.pack(fill="x", pady=(12, 0))
        tk.Label(ctrl_frame, text="Assessment Controls", bg=PANEL_BG, fg=TEXT, font=self.f_h2).pack(anchor="w", padx=18, pady=(14, 6))
        weights = get_control_weights(self.config)
        for key, label, mitre in CONTROL_ORDER:
            card = tk.Frame(ctrl_frame, bg=CARD_BG, highlightbackground=BORDER, highlightthickness=1)
            card.pack(fill="x", padx=18, pady=6)
            inner = tk.Frame(card, bg=CARD_BG)
            inner.pack(fill="x", padx=14, pady=10)
            lft = tk.Frame(inner, bg=CARD_BG)
            lft.pack(side="left", fill="x", expand=True)
            tk.Label(lft, text=label, bg=CARD_BG, fg=TEXT, font=self.f_h3).pack(anchor="w")
            det = tk.Label(lft, text=f"MITRE: {mitre} | Waiting for scan",
                           bg=CARD_BG, fg=MUTED, font=self.f_body, wraplength=580, justify="left")
            det.pack(anchor="w", pady=(3, 0))
            rgt = tk.Frame(inner, bg=CARD_BG)
            rgt.pack(side="right")
            tk.Label(rgt, text=f"Weight {weights.get(key, 0)}", bg=SURFACE, fg=ACCENT,
                     font=self.f_small, padx=10, pady=4).pack(side="right", padx=(8, 0))
            badge = tk.Label(rgt, text="PENDING", bg=SURFACE, fg=MUTED, font=self.f_small, padx=10, pady=4)
            badge.pack(side="right")
            self.control_widgets[key] = {"badge": badge, "detail": det}

        # Text panels
        grid = tk.Frame(parent, bg=APP_BG)
        grid.pack(fill="both", expand=True, pady=(12, 0))
        row1 = tk.Frame(grid, bg=APP_BG)
        row1.pack(fill="both", expand=True)
        self.event_log_text   = self._text_card(row1, "Event Log Summary",    10, side="left")
        self.remediation_text = self._text_card(row1, "Recommended Actions",  10, side="right")

    def _status_row(self, parent, label: str) -> dict:
        row = tk.Frame(parent, bg=PANEL_BG)
        row.pack(fill="x", pady=(10, 0))
        tk.Label(row, text=label, bg=PANEL_BG, fg=TEXT, font=self.f_body).pack(side="left")
        badge = tk.Label(row, text="Checking", bg=SURFACE, fg=WARNING, font=self.f_small, padx=10, pady=4)
        badge.pack(side="right")
        detail = tk.Label(parent, text="", bg=PANEL_BG, fg=MUTED, font=self.f_small, wraplength=270, justify="left")
        detail.pack(anchor="w", pady=(2, 0))
        return {"badge": badge, "detail": detail}

    def _text_card(self, parent, title: str, height: int, side="left") -> tk.Text:
        frame = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        frame.pack(side=side, fill="both", expand=True, padx=(0, 8) if side == "left" else 0, pady=(0, 12))
        tk.Label(frame, text=title, bg=PANEL_BG, fg=TEXT, font=self.f_h2).pack(anchor="w", padx=18, pady=(14, 6))
        text = tk.Text(frame, bg=CARD_BG, fg=TEXT, font=self.f_mono, relief="flat",
                       wrap="word", state="disabled", height=height, padx=10, pady=10)
        text.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        return text

    # ---- FINDINGS TAB ----

    def _build_findings_tab(self, parent):
        frame = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        frame.pack(fill="both", expand=True)
        hdr = tk.Frame(frame, bg=PANEL_BG)
        hdr.pack(fill="x", padx=18, pady=(14, 8))
        tk.Label(hdr, text="Threat Indicator Findings", bg=PANEL_BG, fg=TEXT, font=self.f_h2).pack(side="left")
        tk.Label(hdr, text="Double-click a row for details", bg=PANEL_BG, fg=MUTED, font=self.f_small).pack(side="right")

        cols = ("Control", "Status", "Finding", "MITRE ATT&CK", "Frameworks")
        self.findings_table = ttk.Treeview(frame, columns=cols, show="headings", height=14)
        for col in cols:
            self.findings_table.heading(col, text=col)
        self.findings_table.column("Control",    width=160)
        self.findings_table.column("Status",     width=80)
        self.findings_table.column("Finding",    width=440)
        self.findings_table.column("MITRE ATT&CK", width=220)
        self.findings_table.column("Frameworks", width=220)
        self.findings_table.tag_configure("pass", foreground="#86efac")
        self.findings_table.tag_configure("fail", foreground="#fca5a5", background="#1a0a0a")
        self.findings_table.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        self.findings_table.bind("<Double-1>", self._on_finding_click)

        # Alert panel below
        alert_frame = tk.Frame(parent, bg=PANEL_BG, highlightbackground=FAIL, highlightthickness=1)
        alert_frame.pack(fill="x", pady=(8, 0))
        tk.Label(alert_frame, text="Active Alert Panel", bg=PANEL_BG, fg=FAIL, font=self.f_h3).pack(anchor="w", padx=18, pady=(12, 6))
        self.alert_text = tk.Text(alert_frame, bg=CARD_BG, fg=WARNING, font=self.f_mono_s,
                                  relief="flat", wrap="word", state="disabled", height=5, padx=10, pady=8)
        self.alert_text.pack(fill="x", padx=18, pady=(0, 14))
        self._write_text(self.alert_text, "No scan has been run yet.")

    def _on_finding_click(self, event):
        sel = self.findings_table.focus()
        if not sel:
            return
        vals = self.findings_table.item(sel, "values")
        if not vals:
            return
        detail = (f"Control: {vals[0]}\nStatus: {vals[1]}\n\nFinding: {vals[2]}\n\n"
                  f"MITRE ATT&CK: {vals[3]}\nFrameworks: {vals[4]}\n\n"
                  f"Investigation steps:\n"
                  f"- Review related Windows Security events\n"
                  f"- Validate whether the activity was expected\n"
                  f"- Confirm affected account, source machine, and timestamp\n"
                  f"- Apply remediation from the generated report")
        messagebox.showinfo("Finding Detail", detail)

    # ---- REPORTS TAB ----

    def _build_reports_tab(self, parent):
        frame = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        frame.pack(fill="both", expand=True)
        tk.Label(frame, text="In-App Report View", bg=PANEL_BG, fg=TEXT, font=self.f_h2).pack(anchor="w", padx=18, pady=(14, 8))
        self.report_nb = ttk.Notebook(frame)
        self.report_nb.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        summary_tab = tk.Frame(self.report_nb, bg=CARD_BG)
        json_tab    = tk.Frame(self.report_nb, bg=CARD_BG)
        self.report_nb.add(summary_tab, text="Summary")
        self.report_nb.add(json_tab,    text="JSON")
        self.summary_text = tk.Text(summary_tab, bg=CARD_BG, fg=TEXT, font=self.f_mono,
                                    relief="flat", wrap="word", state="disabled", padx=12, pady=12)
        self.summary_text.pack(fill="both", expand=True)
        self.json_text = tk.Text(json_tab, bg=CARD_BG, fg=TEXT, font=self.f_mono_s,
                                 relief="flat", wrap="none", state="disabled", padx=12, pady=12)
        self.json_text.pack(fill="both", expand=True)

    # ---- SCORING TAB ----

    def _build_scoring_tab(self, parent):
        top = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        top.pack(fill="x")
        ti = tk.Frame(top, bg=PANEL_BG)
        ti.pack(fill="x", padx=18, pady=18)
        tk.Label(ti, text="Scoring Methodology", bg=PANEL_BG, fg=TEXT, font=self.f_h2).pack(anchor="w")
        tk.Label(ti, text="Readiness Score = (Passed Control Weight / Total Control Weight) x 100",
                 bg=PANEL_BG, fg=ACCENT, font=self.f_mono).pack(anchor="w", pady=(8, 0))
        tk.Label(ti, text="Framework-informed weighted rule-based scoring. Transparent and auditable.",
                 bg=PANEL_BG, fg=MUTED, font=self.f_body).pack(anchor="w", pady=(6, 0))

        metrics_row = tk.Frame(parent, bg=APP_BG)
        metrics_row.pack(fill="x", pady=(12, 0))
        self.scoring_metrics = {}
        weights = get_control_weights(self.config)
        for i, (key, title, val) in enumerate([
            ("passed_weight", "Passed Control Weight", "0"),
            ("total_weight",  "Total Control Weight",  str(sum(weights.values()))),
            ("score",         "Current Score",         "--"),
            ("tier",          "Current Tier",          "Awaiting assessment"),
        ]):
            card = tk.Frame(metrics_row, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
            card.pack(side="left", fill="both", expand=True, padx=(0, 8) if i < 3 else 0)
            ci = tk.Frame(card, bg=PANEL_BG)
            ci.pack(fill="both", expand=True, padx=14, pady=14)
            tk.Label(ci, text=title.upper(), bg=PANEL_BG, fg=MUTED, font=self.f_small).pack(anchor="w")
            lbl = tk.Label(ci, text=val, bg=PANEL_BG, fg=TEXT, font=self.f_h2)
            lbl.pack(anchor="w", pady=(6, 0))
            self.scoring_metrics[key] = lbl

        lower = tk.Frame(parent, bg=APP_BG)
        lower.pack(fill="both", expand=True, pady=(12, 0))
        ctrl_card = tk.Frame(lower, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        ctrl_card.pack(side="left", fill="both", expand=True, padx=(0, 8))
        tk.Label(ctrl_card, text="Control Weights and Status", bg=PANEL_BG, fg=TEXT, font=self.f_h2).pack(anchor="w", padx=18, pady=(14, 10))
        table = tk.Frame(ctrl_card, bg=CARD_BG)
        table.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        for col, text in enumerate(["Control", "MITRE", "Weight", "Status"]):
            tk.Label(table, text=text, bg=CARD_ALT, fg=TEXT, font=self.f_small, padx=10, pady=8
                     ).grid(row=0, column=col, sticky="ew", padx=1, pady=1)
            table.grid_columnconfigure(col, weight=1)
        for row_i, (key, label, mitre) in enumerate(CONTROL_ORDER, start=1):
            tk.Label(table, text=label, bg=CARD_BG, fg=TEXT, font=self.f_body, anchor="w", padx=10, pady=8
                     ).grid(row=row_i, column=0, sticky="ew", padx=1, pady=1)
            tk.Label(table, text=mitre, bg=CARD_BG, fg=MUTED, font=self.f_body, padx=10, pady=8
                     ).grid(row=row_i, column=1, sticky="ew", padx=1, pady=1)
            tk.Label(table, text=str(weights.get(key, 0)), bg=CARD_BG, fg=ACCENT, font=self.f_body, padx=10, pady=8
                     ).grid(row=row_i, column=2, sticky="ew", padx=1, pady=1)
            sl = tk.Label(table, text="Pending", bg=CARD_BG, fg=MUTED, font=self.f_body, padx=10, pady=8)
            sl.grid(row=row_i, column=3, sticky="ew", padx=1, pady=1)
            self.scoring_rows[key] = sl

        tier_card = tk.Frame(lower, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1, width=300)
        tier_card.pack(side="right", fill="y")
        tier_card.pack_propagate(False)
        tk.Label(tier_card, text="Risk Tier Mapping", bg=PANEL_BG, fg=TEXT, font=self.f_h2).pack(anchor="w", padx=18, pady=(14, 10))
        for threshold, label in TIER_MAP:
            row = tk.Frame(tier_card, bg=PANEL_BG)
            row.pack(fill="x", padx=18, pady=4)
            tk.Label(row, text=threshold, bg=PANEL_BG, fg=ACCENT, font=self.f_mono).pack(side="left")
            tk.Label(row, text=label, bg=PANEL_BG, fg=TEXT, font=self.f_body).pack(side="right")
        tk.Label(tier_card, text="Brute force: -10 pts penalty\nPriv group change: -5 pts penalty",
                 bg=PANEL_BG, fg=WARNING, font=self.f_small, justify="left").pack(anchor="w", padx=18, pady=(16, 0))

    # ---- DEMO TAB ----

    def _build_demo_tab(self, parent):
        top = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        top.pack(fill="x")
        ti = tk.Frame(top, bg=PANEL_BG)
        ti.pack(fill="x", padx=18, pady=14)
        tk.Label(ti, text="Professor Demo Mode", bg=PANEL_BG, fg=TEXT, font=self.f_h2).pack(anchor="w")
        tk.Label(ti, text="Simulated scenarios only. No AD changes. Safe for classroom use.",
                 bg=PANEL_BG, fg=MUTED, font=self.f_body).pack(anchor="w", pady=(4, 0))
        self.scenario_label = tk.Label(ti, text="Active Scenario: None", bg=PANEL_BG, fg=WARNING, font=self.f_h3)
        self.scenario_label.pack(anchor="w", pady=(8, 0))

        btn_frame = tk.Frame(parent, bg=APP_BG)
        btn_frame.pack(fill="x", pady=14, padx=18)
        for name, color in [
            ("Clean Environment", SUCCESS),
            ("Stale Accounts", ACCENT),
            ("Brute Force", WARNING),
            ("Privileged Change", FAIL),
            ("Multiple Risks", "#7f1d1d"),
            ("Clear Demo", MUTED),
        ]:
            tk.Button(btn_frame, text=name, command=lambda n=name: self._run_demo(n),
                      bg=color if name != "Clear Demo" else SURFACE, fg=APP_BG if name != "Clear Demo" else TEXT,
                      font=self.f_body, padx=12, pady=8, relief="flat", cursor="hand2"
                      ).pack(side="left", padx=(0, 8))

        self.demo_findings_frame = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        self.demo_findings_frame.pack(fill="both", expand=True)
        tk.Label(self.demo_findings_frame, text="Simulated Findings", bg=PANEL_BG, fg=TEXT, font=self.f_h2
                 ).pack(anchor="w", padx=18, pady=(14, 6))
        self.demo_text = tk.Text(self.demo_findings_frame, bg=CARD_BG, fg=TEXT, font=self.f_mono,
                                 relief="flat", wrap="word", state="disabled", height=18, padx=12, pady=12)
        self.demo_text.pack(fill="both", expand=True, padx=18, pady=(0, 18))

    # ---- SIDE PANEL ----

    def _build_side_panel(self, parent):
        ops = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        ops.pack(fill="x")
        inner = tk.Frame(ops, bg=PANEL_BG)
        inner.pack(fill="x", padx=18, pady=18)
        tk.Label(inner, text="Operations", bg=PANEL_BG, fg=TEXT, font=self.f_h2).pack(anchor="w")
        self.state_label = tk.Label(inner, text="Ready", bg=PANEL_BG, fg=MUTED, font=self.f_body)
        self.state_label.pack(anchor="w", pady=(4, 12))
        self.run_btn = tk.Button(inner, text="Run Assessment", command=self._start_assessment,
                                 bg=ACCENT, fg=APP_BG, activebackground="#5FD9FF",
                                 font=self.f_body, padx=12, pady=12, relief="flat", cursor="hand2")
        self.run_btn.pack(fill="x")

        self.monitor_btn = tk.Button(inner, text="Start Monitoring (15s)",
                                     command=self._toggle_monitoring,
                                     bg=SUCCESS, fg=APP_BG, font=self.f_body,
                                     padx=12, pady=10, relief="flat", cursor="hand2")
        self.monitor_btn.pack(fill="x", pady=(8, 0))
        self.monitor_status = tk.Label(inner, text="Monitoring: OFF", bg=PANEL_BG, fg=FAIL, font=self.f_small)
        self.monitor_status.pack(anchor="w", pady=(4, 8))

        for text, cmd, en in [
            ("Open JSON Report",  lambda: self._open_path(self.report_json_path), "disabled"),
            ("Open PDF Report",   lambda: self._open_path(self.report_pdf_path),  "disabled"),
            ("Open HTML Report",  lambda: self._open_path(self.report_html_path), "disabled"),
            ("Open Reports Folder", self._open_reports_folder, "normal"),
        ]:
            btn = tk.Button(inner, text=text, command=cmd, state=en,
                            bg=SURFACE, fg=TEXT if en == "normal" else MUTED,
                            font=self.f_small, padx=12, pady=8, relief="flat", cursor="hand2")
            btn.pack(fill="x", pady=(6, 0))
            setattr(self, f"btn_{text.lower().replace(' ', '_')}", btn)

        log_frame = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        log_frame.pack(fill="both", expand=True, pady=(12, 0))
        tk.Label(log_frame, text="Activity Log", bg=PANEL_BG, fg=TEXT, font=self.f_h3).pack(anchor="w", padx=18, pady=(14, 6))
        self.log_text = tk.Text(log_frame, bg=CARD_BG, fg=TEXT, font=self.f_mono,
                                relief="flat", wrap="word", state="disabled", padx=10, pady=10)
        self.log_text.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        for tag, fg in [("info", ACCENT), ("success", SUCCESS), ("warn", WARNING), ("fail", FAIL), ("muted", MUTED)]:
            self.log_text.tag_config(tag, foreground=fg)

    # ---- HELPER METHODS ----

    def _set_status(self, label: str, color: str):
        self.status_label.configure(text=label)
        self.status_dot.configure(fg=color)
        self.status_frame.configure(highlightbackground=color)

    def _set_conn_status(self, widget: dict, label: str, color: str, detail: str):
        widget["badge"].configure(text=label, fg=color)
        widget["detail"].configure(text=detail)

    def _set_control(self, key: str, label: str, color: str, detail: str):
        w = self.control_widgets.get(key)
        if w:
            w["badge"].configure(text=label, fg=color)
            mitre = next((m for k, _, m in CONTROL_ORDER if k == key), "")
            w["detail"].configure(text=f"MITRE: {mitre} | {detail}")
        if key in self.scoring_rows:
            self.scoring_rows[key].configure(text=label, fg=color)

    def _write_text(self, widget: tk.Text, value: str):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", value)
        widget.configure(state="disabled")

    def _log(self, message: str, tag: str = "info"):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"{message}\n", tag)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _update_scoring_tab(self, report: dict | None = None):
        sb = (report or {}).get("score_breakdown", {})
        weights = get_control_weights(self.config)
        self.scoring_metrics["passed_weight"].configure(text=str(sb.get("passed_control_weight", 0)))
        self.scoring_metrics["total_weight"].configure(text=str(sb.get("total_control_weight", sum(weights.values()))))
        s = sb.get("score", "--")
        self.scoring_metrics["score"].configure(text=str(s))
        t = sb.get("tier", "Awaiting assessment")
        self.scoring_metrics["tier"].configure(text=str(t), fg=score_color(s) if s != "--" else TEXT)
        for key, _, _ in CONTROL_ORDER:
            ctrl_data = sb.get("controls", {}).get(key)
            if ctrl_data:
                passed = ctrl_data.get("passed", False)
                self.scoring_rows[key].configure(text="PASS" if passed else "FAIL",
                                                  fg=SUCCESS if passed else FAIL)
            else:
                self.scoring_rows[key].configure(text="Pending", fg=MUTED)

    def _update_findings_table(self, findings: dict):
        for item in self.findings_table.get_children():
            self.findings_table.delete(item)
        alerts = []
        for key, _, _ in CONTROL_ORDER:
            f = findings.get(key, {})
            if not isinstance(f, dict):
                continue
            passed = f.get("passed", False)
            tag = "pass" if passed else "fail"
            self.findings_table.insert("", "end", values=(
                key.replace("_", " ").title(),
                "PASS" if passed else "FAIL",
                f.get("finding", ""),
                f.get("mitre_attack", "N/A"),
                ", ".join(f.get("frameworks", [])),
            ), tags=(tag,))
            if not passed:
                alerts.append(f"ALERT: {key.replace('_', ' ').title()} | {f.get('finding', '')}")

        # Brute force row
        bf = findings.get("brute_force", {})
        if bf.get("detected", False):
            self.findings_table.insert("", "end", values=(
                "Brute Force Detection", "FAIL",
                f"Brute force detected: {bf.get('flagged_accounts', {})}",
                "T1110 - Brute Force",
                "NIST DE.CM-3, CIS 8.11",
            ), tags=("fail",))
            alerts.append(f"ALERT: Brute Force Detected | {bf.get('flagged_accounts', {})}")

        # Privileged group change row
        pgc = findings.get("priv_group_change", {})
        if pgc.get("detected", False):
            self.findings_table.insert("", "end", values=(
                "Privileged Group Change", "WARN",
                f"Event ID 4728 detected {pgc.get('count', 0)} time(s) in last 24h.",
                "T1098 - Account Manipulation",
                "CIS 5.4, NIST PR.AC-4",
            ), tags=("fail",))
            alerts.append(f"ALERT: Privileged Group Change | 4728 count: {pgc.get('count', 0)}")

        alert_text = "\n".join(alerts) if alerts else "No active high-severity alerts."
        self._write_text(self.alert_text, alert_text)

    # ---- STARTUP CHECKS ----

    def _run_startup_checks(self):
        threading.Thread(target=self._startup_worker, daemon=True).start()

    def _startup_worker(self):
        ad_result    = test_ad_connection(self.config)
        event_result = get_event_log_status("Security")
        self.root.after(0, lambda: self._apply_startup(ad_result, event_result))

    def _apply_startup(self, ad_result: dict, event_result: dict):
        if ad_result["connected"]:
            self._set_conn_status(self.ad_status, "Connected", SUCCESS, ad_result["message"])
            self._log("Active Directory connection verified.", "success")
        else:
            self._set_conn_status(self.ad_status, "Failed", FAIL, ad_result["message"])
            self._log("Active Directory connection failed.", "fail")
        if event_result["accessible"]:
            self._set_conn_status(self.event_status, "Connected", SUCCESS,
                                  f"Security log: {event_result['record_count']} records.")
            self._log("Windows Security Log access verified.", "success")
        else:
            self._set_conn_status(self.event_status, "Failed", FAIL, event_result.get("error", "Unavailable"))
            self._log("Windows Security Log access failed.", "fail")
        self._update_scoring_tab()

    # ---- ASSESSMENT ----

    def _start_assessment(self):
        if self.scanning:
            return
        self.scanning = True
        self._set_status("RUNNING", WARNING)
        self.state_label.configure(text="Assessment in progress")
        self.run_btn.configure(state="disabled")
        for key, _, _ in CONTROL_ORDER:
            self._set_control(key, "RUNNING", WARNING, "Assessment in progress")
        self._log("Starting SOC assessment.", "info")
        threading.Thread(target=self._assessment_worker, daemon=True).start()

    def _assessment_worker(self):
        conn = None
        try:
            self._progress("1. Loading configuration")
            config = self.config

            self._progress("2. Connecting to Active Directory")
            conn = connect_to_ad(config)

            self._progress("3. Validating Security Log access")
            event_status = get_event_log_status("Security")
            self.root.after(0, lambda: self._set_conn_status(
                self.event_status,
                "Connected" if event_status["accessible"] else "Failed",
                SUCCESS if event_status["accessible"] else FAIL,
                f"Security log: {event_status.get('record_count', 0)} records." if event_status["accessible"]
                else event_status.get("error", "Unavailable"),
            ))

            findings = {}

            self._progress("4. Enumerating privileged groups")
            findings["privileged_groups"] = check_privileged_groups(conn, config)
            self.root.after(0, lambda: self._set_control(
                "privileged_groups",
                "PASS" if findings["privileged_groups"]["passed"] else "FAIL",
                SUCCESS if findings["privileged_groups"]["passed"] else FAIL,
                findings["privileged_groups"]["finding"]))

            self._progress("5. Checking stale accounts")
            findings["stale_accounts"] = check_stale_accounts(conn, config)
            self.root.after(0, lambda: self._set_control(
                "stale_accounts",
                "PASS" if findings["stale_accounts"]["passed"] else "FAIL",
                SUCCESS if findings["stale_accounts"]["passed"] else FAIL,
                findings["stale_accounts"]["finding"]))

            self._progress("6. Checking disabled privileged accounts")
            findings["disabled_accounts"] = check_disabled_accounts(conn, config)
            self.root.after(0, lambda: self._set_control(
                "disabled_accounts",
                "PASS" if findings["disabled_accounts"]["passed"] else "FAIL",
                SUCCESS if findings["disabled_accounts"]["passed"] else FAIL,
                findings["disabled_accounts"]["finding"]))

            self._progress("7. Reading security events")
            findings["log_validation"] = read_security_events(config)
            self.root.after(0, lambda: self._set_control(
                "log_validation",
                "PASS" if findings["log_validation"]["passed"] else "FAIL",
                SUCCESS if findings["log_validation"]["passed"] else FAIL,
                findings["log_validation"]["finding"]))

            self._progress("8. Detecting brute force activity")
            findings["brute_force"] = detect_bruteforce(config)

            self._progress("9. Detecting privileged group changes")
            findings["priv_group_change"] = detect_privileged_group_change(config)

            self._progress("10. Calculating score")
            score, tier = calculate_score(findings, config)

            self._progress("11. Generating JSON report")
            self._progress("12. Generating PDF report")
            self._progress("13. Generating HTML report")
            result = generate_report(findings, score, tier, config)

            self._progress("14. Finalizing assessment")
            self.root.after(0, lambda: self._apply_results(findings, score, tier, result))

        except Exception as exc:
            self.root.after(0, lambda: self._apply_error(exc))
        finally:
            if conn is not None and conn.bound:
                conn.unbind()

    def _progress(self, message: str):
        self.root.after(0, lambda: self._log(message, "muted"))
        time.sleep(0.06)

    def _apply_results(self, findings: dict, score: float, tier: str, result: dict):
        self.scanning = False
        self.current_report = result
        self._set_status("COMPLETE", SUCCESS)
        self.state_label.configure(text="Assessment complete")
        self.run_btn.configure(state="normal")

        ts = result.get("assessment_timestamp", "")
        self.last_scan_summary = f"Last scan: {ts}"
        self.last_scan_lbl.configure(text=self.last_scan_summary)

        for attr_name in ("open_json_report", "open_pdf_report", "open_html_report"):
            btn = getattr(self, f"btn_{attr_name}", None)
            if btn:
                btn.configure(state="normal", fg=TEXT)

        self.score_label.configure(text=f"{score:.1f}", fg=score_color(score))
        self.tier_label.configure(text=tier, fg=score_color(score))
        maturity = result.get("soc_maturity", "")
        self.maturity_label.configure(text=f"SOC Maturity: {maturity}", fg=MUTED)
        self.summary_label.configure(text=result.get("executive_summary", ""))

        self._update_findings_table(findings)
        self._update_scoring_tab(result)

        # Event log summary
        elo = result.get("event_log_overview", {})
        cats = elo.get("categories", {})
        ab = elo.get("activity_breakdown", {})
        event_lines = [
            f"Telemetry quality: {elo.get('telemetry_quality', 'unavailable')}",
            f"Lookback: {elo.get('lookback_days', 0)} day(s)",
            f"Total relevant events: {elo.get('total_relevant_events', 0)}",
            f"Human logons: {ab.get('human_successful_logons', 0)}",
            f"Service logons: {ab.get('service_or_machine_successful_logons', 0)}",
            "",
        ]
        for cat_name, meta in cats.items():
            event_lines.append(f"{meta.get('label', cat_name)}: {meta.get('count', 0)}")
        self._write_text(self.event_log_text, "\n".join(event_lines))

        # Remediation
        actions = result.get("remediation_summary", {}).get("recommended_actions", [])
        rem_lines = []
        for a in actions:
            rem_lines.append(f"[{a.get('priority', '').upper()}] {a.get('recommendation', '')}")
        self._write_text(self.remediation_text, "\n".join(rem_lines) if rem_lines else "No actions required.")

        # Reports tab
        summary_lines = [
            f"Organization: {result['organization'].get('name', '')}",
            f"Score: {result['soc_readiness_score']}/100",
            f"Tier: {result['risk_level']}",
            f"Maturity: {result.get('soc_maturity', '')}",
            "",
            result.get("executive_summary", ""),
            "",
            "Control findings:",
        ]
        for key, _, _ in CONTROL_ORDER:
            f = findings.get(key, {})
            summary_lines.append(f"- {f.get('finding', '')}")
        self._write_text(self.summary_text, "\n".join(summary_lines))
        self._write_text(self.json_text, json.dumps(result, indent=4))

        self._log(f"Assessment complete: {score:.1f}/100 ({tier}).", "success")
        if findings.get("brute_force", {}).get("detected"):
            self._log("Brute force activity detected. -10 score penalty applied.", "warn")
        if findings.get("priv_group_change", {}).get("detected"):
            self._log("Privileged group change detected. -5 score penalty applied.", "warn")

    def _apply_error(self, exc: Exception):
        self.scanning = False
        self._set_status("ERROR", FAIL)
        self.state_label.configure(text="Assessment failed")
        self.run_btn.configure(state="normal")
        for key, _, _ in CONTROL_ORDER:
            self._set_control(key, "ERROR", FAIL, "Assessment aborted")
        self._log(f"Assessment failed: {exc}", "fail")

    # ---- MONITORING ----

    def _toggle_monitoring(self):
        if self.monitoring_enabled:
            self.monitoring_enabled = False
            self.monitor_btn.configure(text="Start Monitoring (15s)", bg=SUCCESS)
            self.monitor_status.configure(text="Monitoring: OFF", fg=FAIL)
            self._log("Monitoring stopped.", "muted")
        else:
            self.monitoring_enabled = True
            self.monitor_btn.configure(text="Stop Monitoring", bg=FAIL)
            self.monitor_status.configure(text="Monitoring: ON", fg=SUCCESS)
            self._log("Monitoring started. Re-running every 15 seconds.", "info")
            self._monitor_loop()

    def _monitor_loop(self):
        if self.monitoring_enabled and not self.scanning:
            self._start_assessment()
        if self.monitoring_enabled:
            self.root.after(15000, self._monitor_loop)

    # ---- DEMO MODE ----

    def _run_demo(self, scenario_name: str):
        if scenario_name == "Clear Demo":
            self.scenario_label.configure(text="Active Scenario: None")
            self.score_label.configure(text="--", fg=TEXT)
            self.tier_label.configure(text="Demo cleared", fg=MUTED)
            self.maturity_label.configure(text="")
            self.summary_label.configure(text="Demo cleared. Run a real scan or select a demo scenario.")
            self._write_text(self.demo_text, "Demo cleared.")
            for item in self.findings_table.get_children():
                self.findings_table.delete(item)
            self._write_text(self.alert_text, "No active alerts.")
            return

        scenario = DEMO_SCENARIOS.get(scenario_name)
        if not scenario:
            return

        self.scenario_label.configure(text=f"Active Scenario: {scenario_name}")
        score = scenario["score"]
        tier  = scenario["tier"]
        self.score_label.configure(text=str(score), fg=score_color(score))
        self.tier_label.configure(text=tier, fg=score_color(score))
        self.maturity_label.configure(text=f"SOC Maturity: {calculate_soc_maturity(score, {})}")
        self.summary_label.configure(text=scenario["summary"])

        for item in self.findings_table.get_children():
            self.findings_table.delete(item)
        alerts = []
        for f in scenario["findings"]:
            sev = f.get("severity", "Medium")
            tag = "fail" if sev == "High" else "pass"
            self.findings_table.insert("", "end", values=(
                f["control"], sev, f["issue"], f.get("mitre", "N/A"),
                ", ".join(f.get("frameworks", [])),
            ), tags=(tag,))
            if sev == "High":
                alerts.append(f"ALERT [{sev}]: {f['control']} | {f['issue']}")

        self._write_text(self.alert_text, "\n".join(alerts) if alerts else "No high-severity alerts in this scenario.")

        demo_lines = [f"=== {scenario_name} ===", "", scenario["summary"], "", "Findings:"]
        for f in scenario["findings"]:
            demo_lines.append(f"[{f.get('severity', 'Medium')}] {f['control']}: {f['issue']}")
            demo_lines.append(f"  MITRE: {f.get('mitre', 'N/A')}")
            demo_lines.append(f"  Frameworks: {', '.join(f.get('frameworks', []))}")
            demo_lines.append("")
        self._write_text(self.demo_text, "\n".join(demo_lines))
        self._log(f"Demo scenario loaded: {scenario_name} ({score}/100 {tier})", "info")

    # ---- FILE OPERATIONS ----

    def _open_path(self, path: Path):
        if not path.exists():
            self._log(f"Report not found: {path}", "fail")
            messagebox.showerror("File Not Found", f"Report not found:\n{path}")
            return
        os.startfile(str(path))

    def _open_reports_folder(self):
        folder = self.report_json_path.parent
        folder.mkdir(parents=True, exist_ok=True)
        os.startfile(str(folder))


# ============================================================
# SECTION 11 — ENTRY POINT
# ============================================================

def launch_app():
    root = tk.Tk()
    try:
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background=APP_BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL_BG, foreground=MUTED,
                        padding=[14, 8], font=("Segoe UI", 10))
        style.map("TNotebook.Tab",
                  background=[("selected", CARD_BG)],
                  foreground=[("selected", ACCENT)])
        style.configure("Treeview", background=CARD_BG, foreground=TEXT,
                        fieldbackground=CARD_BG, rowheight=50, borderwidth=0,
                        font=("Segoe UI", 10))
        style.configure("Treeview.Heading", background=SURFACE, foreground=TEXT,
                        font=("Segoe UI Semibold", 10))
        style.map("Treeview", background=[("selected", SURFACE2)])
    except Exception:
        pass

    try:
        SOCProbeApp(root)
        root.mainloop()
    except ConfigLoadError as exc:
        root.withdraw()
        messagebox.showerror(
            "SOCProbe - Configuration Missing",
            f"config.json not found.\n\nExpected: {exc.expected_path}\n\n"
            f"Copy config.template.json to config.json and fill in your AD credentials.",
            parent=root,
        )
        root.destroy()


if __name__ == "__main__":
    launch_app()
