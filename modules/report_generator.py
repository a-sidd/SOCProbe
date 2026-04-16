import datetime
import json
from pathlib import Path

from modules.ad_connector import get_ad_connection_details
from modules.scoring_engine import build_score_breakdown


def _escape_pdf_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _write_simple_pdf(path: Path, lines: list[str]) -> None:
    content_lines = ["BT", "/F1 10 Tf", "50 800 Td"]
    first = True
    remaining_lines = 0
    for line in lines:
        safe_line = _escape_pdf_text(line[:140])
        if first:
            content_lines.append(f"({safe_line}) Tj")
            first = False
        else:
            content_lines.append(f"0 -14 Td ({safe_line}) Tj")
        remaining_lines += 1
        if remaining_lines >= 50:
            break
    content_lines.append("ET")
    content_stream = "\n".join(content_lines).encode("latin-1", errors="replace")

    objects = []
    objects.append(b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n")
    objects.append(b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n")
    objects.append(
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n"
    )
    objects.append(b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n")
    objects.append(
        f"5 0 obj << /Length {len(content_stream)} >> stream\n".encode("latin-1")
        + content_stream
        + b"\nendstream endobj\n"
    )

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(pdf))
        pdf.extend(obj)
    xref_position = len(pdf)
    pdf.extend(f"xref\n0 {len(offsets)}\n".encode("latin-1"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("latin-1"))
    pdf.extend(
        (
            f"trailer << /Size {len(offsets)} /Root 1 0 R >>\n"
            f"startxref\n{xref_position}\n%%EOF"
        ).encode("latin-1")
    )
    path.write_bytes(pdf)


def build_assessment_result(findings, score, tier, config):
    score_breakdown = build_score_breakdown(findings, config)
    event_summary = findings.get("log_validation", {}).get("summary", {})
    return {
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
        "assessment_scope": "single-company local Windows Server capstone deployment",
        "soc_readiness_score": score,
        "risk_level": tier,
        "score_breakdown": score_breakdown,
        "connection_summary": {
            "active_directory": get_ad_connection_details(config),
            "windows_security_log": findings.get("log_validation", {}).get("connection", {}),
        },
        "findings": findings,
        "event_log_overview": {
            "lookback_days": event_summary.get("lookback_days", 0),
            "total_relevant_events": event_summary.get("total_relevant_events", 0),
            "telemetry_quality": event_summary.get("telemetry_quality", "unavailable"),
            "activity_breakdown": event_summary.get("activity_breakdown", {}),
            "categories": event_summary.get("categories", {}),
        },
        "remediation_summary": build_remediation_summary(findings, config),
        "report_paths": {
            "json": config["output"]["report_path"],
            "pdf": config["output"]["pdf_report_path"],
        },
    }


def build_remediation_summary(findings, config) -> dict:
    actions = []

    privileged = findings.get("privileged_groups", {})
    if not privileged.get("passed", False):
        actions.append(
            {
                "priority": "high",
                "control": "privileged_groups",
                "issue": privileged.get("finding", ""),
                "recommendation": (
                    f"Reduce Domain Admin membership to the configured threshold of "
                    f"{privileged.get('max_allowed', config['thresholds'].get('max_domain_admins', 0))} "
                    "and review standing privileged access."
                ),
            }
        )

    disabled = findings.get("disabled_accounts", {})
    if not disabled.get("passed", False):
        actions.append(
            {
                "priority": "high",
                "control": "disabled_accounts",
                "issue": disabled.get("finding", ""),
                "recommendation": "Remove disabled identities from privileged groups and confirm access was fully revoked.",
            }
        )

    stale = findings.get("stale_accounts", {})
    if not stale.get("passed", False):
        actions.append(
            {
                "priority": "medium",
                "control": "stale_accounts",
                "issue": stale.get("finding", ""),
                "recommendation": (
                    f"Review enabled accounts inactive for more than {stale.get('threshold_days', 0)} days "
                    "and disable or justify any exceptions."
                ),
            }
        )

    log_validation = findings.get("log_validation", {})
    if not log_validation.get("passed", False):
        connection = log_validation.get("connection", {})
        if not connection.get("accessible", False):
            recommendation = "Run the tool with permission to read the Windows Security log and verify local audit policy is enabled."
        else:
            recommendation = "Generate additional human-user and account-management activity in the lab so Security Log validation has richer signal."
        actions.append(
            {
                "priority": "medium",
                "control": "log_validation",
                "issue": log_validation.get("finding", ""),
                "recommendation": recommendation,
            }
        )
    else:
        telemetry_quality = log_validation.get("summary", {}).get("telemetry_quality", "unavailable")
        if telemetry_quality == "baseline":
            actions.append(
                {
                    "priority": "low",
                    "control": "log_validation",
                    "issue": "Security log telemetry is present but dominated by service or machine activity.",
                    "recommendation": "For richer demos, create a small amount of human-user logon and account-management activity before running the assessment.",
                }
            )

    return {
        "recommended_actions": actions,
        "action_count": len(actions),
    }


def _build_pdf_lines(result: dict) -> list[str]:
    lines = [
        "SOCProbe Assessment Report",
        f"Organization: {result['organization'].get('name', '')}",
        f"Industry: {result['organization'].get('industry', '')}",
        f"Environment: {result['organization'].get('environment', '')}",
        f"Domain: {result['domain'].get('fqdn', '')}",
        f"Assessment time: {result['assessment_timestamp']}",
        "",
        f"Readiness score: {result['soc_readiness_score']}/100",
        f"Risk tier: {result['risk_level']}",
        "",
        "Control findings:",
    ]
    for key, finding in result["findings"].items():
        lines.append(f"- {key}: {finding.get('finding', '')}")
    lines.append("")
    lines.append("Security log summary:")
    event_overview = result.get("event_log_overview", {})
    lines.append(f"- Lookback days: {event_overview.get('lookback_days', 0)}")
    lines.append(f"- Total relevant events: {event_overview.get('total_relevant_events', 0)}")
    for category_name, meta in event_overview.get("categories", {}).items():
        lines.append(f"- {meta.get('label', category_name)}: {meta.get('count', 0)}")
    activity_breakdown = event_overview.get("activity_breakdown", {})
    if activity_breakdown:
        lines.append(f"- Human successful logons: {activity_breakdown.get('human_successful_logons', 0)}")
        lines.append(
            f"- Service or machine successful logons: "
            f"{activity_breakdown.get('service_or_machine_successful_logons', 0)}"
        )
    lines.append("")
    lines.append("Recommended next actions:")
    for action in result.get("remediation_summary", {}).get("recommended_actions", []):
        lines.append(f"- [{action.get('priority', '').upper()}] {action.get('recommendation', '')}")
    lines.append("")
    lines.append(f"JSON report: {result['report_paths']['json']}")
    lines.append(f"PDF report: {result['report_paths']['pdf']}")
    return lines


def generate_report(findings, score, tier, config):
    result = build_assessment_result(findings, score, tier, config)

    json_path = Path(config["output"]["report_path"])
    pdf_path = Path(config["output"]["pdf_report_path"])
    json_path.parent.mkdir(parents=True, exist_ok=True)
    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=4)

    _write_simple_pdf(pdf_path, _build_pdf_lines(result))
    return result
