from __future__ import annotations

from collections import Counter
from datetime import datetime
import xml.etree.ElementTree as ET

import win32evtlog


NS = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}

CATEGORY_MAP = {
    "successful_logons": {
        "label": "Successful logons",
        "event_ids": {4624},
    },
    "failed_logons": {
        "label": "Failed logons",
        "event_ids": {4625},
    },
    "lockouts": {
        "label": "Account lockouts",
        "event_ids": {4740},
    },
    "account_changes": {
        "label": "Account created or state changes",
        "event_ids": {4720, 4722, 4725},
    },
    "group_membership_changes": {
        "label": "Group membership changes",
        "event_ids": {4728, 4729, 4732, 4733, 4756, 4757},
    },
}

WELL_KNOWN_NON_HUMAN_SUBJECTS = {
    "SYSTEM",
    "LOCAL SERVICE",
    "NETWORK SERVICE",
    "ANONYMOUS LOGON",
    "DWM-1",
    "UMFD-0",
}


def get_event_log_status(log_name: str = "Security") -> dict:
    try:
        handle = win32evtlog.OpenEventLog(None, log_name)
        record_count = win32evtlog.GetNumberOfEventLogRecords(handle)
        win32evtlog.CloseEventLog(handle)
        return {
            "accessible": True,
            "log_name": log_name,
            "record_count": record_count,
        }
    except Exception as exc:
        return {
            "accessible": False,
            "log_name": log_name,
            "record_count": 0,
            "error": str(exc),
        }


def _build_query(lookback_days: int) -> str:
    event_ids = sorted({event_id for meta in CATEGORY_MAP.values() for event_id in meta["event_ids"]})
    event_filter = " or ".join(f"EventID={event_id}" for event_id in event_ids)
    milliseconds = max(1, int(lookback_days)) * 24 * 60 * 60 * 1000
    return (
        "*[System[("
        f"{event_filter}"
        f") and TimeCreated[timediff(@SystemTime) <= {milliseconds}]]]"
    )


def _parse_xml_event(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)
    system = root.find("evt:System", NS)
    event_data_nodes = root.findall("evt:EventData/evt:Data", NS)

    data = {}
    for node in event_data_nodes:
        data[node.attrib.get("Name", f"field_{len(data) + 1}")] = (node.text or "").strip()

    event_id = int(system.findtext("evt:EventID", default="0", namespaces=NS))
    provider = system.find("evt:Provider", NS)
    provider_name = provider.attrib.get("Name", "") if provider is not None else ""
    time_node = system.find("evt:TimeCreated", NS)
    raw_time = time_node.attrib.get("SystemTime") if time_node is not None else ""
    timestamp = raw_time
    if raw_time:
        try:
            timestamp = datetime.fromisoformat(raw_time.replace("Z", "+00:00")).astimezone().isoformat()
        except ValueError:
            timestamp = raw_time

    return {
        "event_id": event_id,
        "provider": provider_name,
        "timestamp": timestamp,
        "computer": system.findtext("evt:Computer", default="", namespaces=NS),
        "subject": (
            data.get("TargetUserName")
            or data.get("MemberName")
            or data.get("SubjectUserName")
            or data.get("SamAccountName")
            or "Unknown"
        ),
        "secondary": (
            data.get("IpAddress")
            or data.get("TargetDomainName")
            or data.get("GroupName")
            or ""
        ),
    }


def _category_for_event(event_id: int) -> str | None:
    for category_name, meta in CATEGORY_MAP.items():
        if event_id in meta["event_ids"]:
            return category_name
    return None


def _activity_type(subject: str) -> str:
    normalized = (subject or "").strip().upper()
    if not normalized or normalized in WELL_KNOWN_NON_HUMAN_SUBJECTS:
        return "service_or_machine"
    if normalized.endswith("$"):
        return "service_or_machine"
    if normalized.startswith("SVC ") or normalized.startswith("SVC_") or normalized.startswith("SVC"):
        return "service_or_machine"
    return "human"


def read_security_events(config: dict) -> dict:
    lookback_days = int(config["thresholds"].get("security_log_lookback_days", 7))
    max_events = int(config["thresholds"].get("security_log_max_events", 250))
    status = get_event_log_status("Security")

    summary = {
        "accessible": status["accessible"],
        "record_count": status["record_count"],
        "lookback_days": lookback_days,
        "total_relevant_events": 0,
        "telemetry_quality": "unavailable",
        "activity_breakdown": {
            "human_successful_logons": 0,
            "service_or_machine_successful_logons": 0,
        },
        "categories": {
            key: {
                "label": meta["label"],
                "event_ids": sorted(meta["event_ids"]),
                "count": 0,
                "top_subjects": [],
                "sample_events": [],
            }
            for key, meta in CATEGORY_MAP.items()
        },
    }

    if not status["accessible"]:
        return {
            "passed": False,
            "finding": "FAIL - Windows Security log is not accessible.",
            "connection": status,
            "summary": summary,
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
            category = _category_for_event(parsed["event_id"])
            if category is None:
                continue
            events[category].append(parsed)
            counters[category][parsed["subject"]] += 1
            if category == "successful_logons":
                activity_breakdown[_activity_type(parsed["subject"])] += 1
            fetched += 1
            if fetched >= max_events:
                break

    categories_seen = 0
    for category_name, category_summary in summary["categories"].items():
        category_events = events[category_name]
        category_summary["count"] = len(category_events)
        category_summary["top_subjects"] = [
            {"subject": subject, "count": count}
            for subject, count in counters[category_name].most_common(5)
        ]
        category_summary["sample_events"] = [
            {
                "timestamp": event["timestamp"],
                "event_id": event["event_id"],
                "subject": event["subject"],
                "secondary": event["secondary"],
                "computer": event["computer"],
            }
            for event in category_events[:5]
        ]
        if category_events:
            categories_seen += 1

    summary["total_relevant_events"] = sum(
        category_summary["count"] for category_summary in summary["categories"].values()
    )
    summary["activity_breakdown"] = {
        "human_successful_logons": activity_breakdown.get("human", 0),
        "service_or_machine_successful_logons": activity_breakdown.get("service_or_machine", 0),
    }

    human_signal_present = summary["activity_breakdown"]["human_successful_logons"] > 0
    security_event_signal_present = any(
        summary["categories"][category_name]["count"] > 0
        for category_name in (
            "failed_logons",
            "lockouts",
            "account_changes",
            "group_membership_changes",
        )
    )
    baseline_signal_present = summary["total_relevant_events"] > 0

    if security_event_signal_present or (human_signal_present and categories_seen >= 1):
        summary["telemetry_quality"] = "strong"
        passed = True
        finding = (
            f"PASS - Security log is accessible and produced useful recent telemetry with "
            f"{summary['total_relevant_events']} relevant events over the last {lookback_days} day(s)."
        )
    elif baseline_signal_present:
        summary["telemetry_quality"] = "baseline"
        passed = True
        finding = (
            f"PASS - Security log is accessible and producing baseline telemetry for a quiet lab. "
            f"Recent activity is mostly service or machine logon noise, so human-driven signal is limited."
        )
    else:
        summary["telemetry_quality"] = "limited"
        passed = False
        finding = (
            f"FAIL - Security log is accessible but no monitored security events were observed in the last "
            f"{lookback_days} day(s)."
        )

    return {
        "passed": passed,
        "finding": finding,
        "connection": status,
        "summary": summary,
    }
