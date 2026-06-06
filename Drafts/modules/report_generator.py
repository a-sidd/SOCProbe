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


PAGE_WIDTH = 612
PAGE_HEIGHT = 792
LEFT_MARGIN = 48
RIGHT_MARGIN = 48
TOP_MARGIN = 54
BOTTOM_MARGIN = 48
CONTENT_WIDTH = PAGE_WIDTH - LEFT_MARGIN - RIGHT_MARGIN
LINE_HEIGHT = 14


def _wrap_text(text: str, max_chars: int) -> list[str]:
    if not text:
        return [""]
    words = str(text).split()
    lines = []
    current = ""
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
    def __init__(self):
        self.pages: list[list[str]] = [[]]
        self.page = self.pages[0]
        self.y = PAGE_HEIGHT - TOP_MARGIN

    def new_page(self):
        self.pages.append([])
        self.page = self.pages[-1]
        self.y = PAGE_HEIGHT - TOP_MARGIN

    def ensure_space(self, height: float):
        if self.y - height < BOTTOM_MARGIN:
            self.new_page()

    def rect(self, x: float, y: float, width: float, height: float, stroke=(0.16, 0.30, 0.41), fill=None, line_width: float = 1):
        commands = [f"{line_width} w", f"{stroke[0]:.3f} {stroke[1]:.3f} {stroke[2]:.3f} RG"]
        if fill is not None:
            commands.append(f"{fill[0]:.3f} {fill[1]:.3f} {fill[2]:.3f} rg")
            commands.append(f"{x:.2f} {y:.2f} {width:.2f} {height:.2f} re B")
        else:
            commands.append(f"{x:.2f} {y:.2f} {width:.2f} {height:.2f} re S")
        self.page.extend(commands)

    def line(self, x1: float, y1: float, x2: float, y2: float, color=(0.16, 0.30, 0.41), line_width: float = 1):
        self.page.extend(
            [
                f"{line_width} w",
                f"{color[0]:.3f} {color[1]:.3f} {color[2]:.3f} RG",
                f"{x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S",
            ]
        )

    def text(self, x: float, y: float, text: str, size: int = 10, color=(0.10, 0.12, 0.16), font="Helvetica"):
        safe = _escape_pdf_text(text)
        self.page.extend(
            [
                "BT",
                f"/{font} {size} Tf",
                f"{color[0]:.3f} {color[1]:.3f} {color[2]:.3f} rg",
                f"{x:.2f} {y:.2f} Td",
                f"({safe}) Tj",
                "ET",
            ]
        )

    def draw_section_title(self, title: str):
        self.ensure_space(28)
        self.text(LEFT_MARGIN, self.y, title, size=14, color=(0.06, 0.23, 0.36), font="Helvetica-Bold")
        self.y -= 8
        self.line(LEFT_MARGIN, self.y, PAGE_WIDTH - RIGHT_MARGIN, self.y, color=(0.16, 0.30, 0.41), line_width=1.2)
        self.y -= 18

    def draw_paragraph(self, text: str, size: int = 10, color=(0.10, 0.12, 0.16), max_chars: int = 88):
        lines = _wrap_text(text, max_chars)
        self.ensure_space(len(lines) * LINE_HEIGHT + 4)
        for line in lines:
            self.text(LEFT_MARGIN, self.y, line, size=size, color=color)
            self.y -= LINE_HEIGHT
        self.y -= 4

    def draw_key_values(self, pairs: list[tuple[str, str]], columns: int = 2):
        row_height = 22
        total_rows = (len(pairs) + columns - 1) // columns
        block_height = total_rows * row_height + 14
        col_width = CONTENT_WIDTH / columns
        self.ensure_space(block_height)
        self.rect(LEFT_MARGIN, self.y - block_height + 10, CONTENT_WIDTH, block_height, fill=(0.94, 0.97, 0.99))
        start_y = self.y - 10
        for index, (label, value) in enumerate(pairs):
            row = index // columns
            col = index % columns
            x = LEFT_MARGIN + col * col_width + 10
            y = start_y - row * row_height
            self.text(x, y, label, size=9, color=(0.28, 0.40, 0.49), font="Helvetica-Bold")
            self.text(x + 132, y, value, size=9, color=(0.10, 0.12, 0.16))
        self.y -= block_height + 8

    def draw_table(self, headers: list[str], rows: list[list[str]], widths: list[float], title: str | None = None, row_max_chars: list[int] | None = None):
        if title:
            self.draw_section_title(title)
        row_max_chars = row_max_chars or [24] * len(headers)
        header_height = 24
        self.ensure_space(header_height + 8)
        self.rect(LEFT_MARGIN, self.y - header_height + 6, CONTENT_WIDTH, header_height, fill=(0.13, 0.28, 0.40), stroke=(0.13, 0.28, 0.40))
        x = LEFT_MARGIN
        for idx, header in enumerate(headers):
            self.text(x + 6, self.y - 12, header, size=9, color=(1, 1, 1), font="Helvetica-Bold")
            x += widths[idx]
        self.y -= header_height

        for row in rows:
            wrapped = []
            max_lines = 1
            for idx, cell in enumerate(row):
                cell_lines = _wrap_text(str(cell), row_max_chars[idx])
                wrapped.append(cell_lines)
                max_lines = max(max_lines, len(cell_lines))
            row_height = max(22, max_lines * 12 + 8)
            self.ensure_space(row_height + 2)
            self.rect(LEFT_MARGIN, self.y - row_height + 2, CONTENT_WIDTH, row_height, fill=(0.97, 0.98, 0.99), stroke=(0.84, 0.89, 0.93), line_width=0.7)
            x = LEFT_MARGIN
            for idx, cell_lines in enumerate(wrapped):
                line_y = self.y - 12
                for line in cell_lines:
                    self.text(x + 6, line_y, line, size=8, color=(0.10, 0.12, 0.16))
                    line_y -= 11
                if idx < len(widths) - 1:
                    self.line(x + widths[idx], self.y - row_height + 2, x + widths[idx], self.y + 2, color=(0.86, 0.90, 0.94), line_width=0.5)
                x += widths[idx]
            self.y -= row_height
        self.y -= 12

    def build_pdf(self, path: Path):
        objects = []
        page_ids = []
        font_regular_id = 1
        font_bold_id = 2
        next_id = 3
        content_ids = []

        for page_commands in self.pages:
            content_stream = "\n".join(page_commands).encode("latin-1", errors="replace")
            content_id = next_id
            next_id += 1
            page_id = next_id
            next_id += 1
            content_ids.append(content_id)
            page_ids.append(page_id)
            objects.append((content_id, f"<< /Length {len(content_stream)} >> stream\n".encode("latin-1") + content_stream + b"\nendstream"))

        pages_id = next_id
        next_id += 1
        catalog_id = next_id

        for index, page_id in enumerate(page_ids):
            page_dict = (
                f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
                f"/Resources << /Font << /Helvetica {font_regular_id} 0 R /Helvetica-Bold {font_bold_id} 0 R >> >> "
                f"/Contents {content_ids[index]} 0 R >>"
            ).encode("latin-1")
            objects.append((page_id, page_dict))

        kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
        objects.extend(
            [
                (font_regular_id, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"),
                (font_bold_id, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"),
                (pages_id, f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("latin-1")),
                (catalog_id, f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("latin-1")),
            ]
        )

        objects.sort(key=lambda item: item[0])
        pdf = bytearray(b"%PDF-1.4\n")
        offsets = [0]
        for obj_id, data in objects:
            offsets.append(len(pdf))
            pdf.extend(f"{obj_id} 0 obj\n".encode("latin-1"))
            pdf.extend(data)
            pdf.extend(b"\nendobj\n")

        xref_position = len(pdf)
        pdf.extend(f"xref\n0 {len(offsets)}\n".encode("latin-1"))
        pdf.extend(b"0000000000 65535 f \n")
        for offset in offsets[1:]:
            pdf.extend(f"{offset:010d} 00000 n \n".encode("latin-1"))
        pdf.extend(
            (
                f"trailer << /Size {len(offsets)} /Root {catalog_id} 0 R >>\n"
                f"startxref\n{xref_position}\n%%EOF"
            ).encode("latin-1")
        )
        path.write_bytes(pdf)


def _generate_professional_pdf(path: Path, result: dict):
    canvas = PdfCanvas()
    canvas.rect(LEFT_MARGIN, PAGE_HEIGHT - 112, CONTENT_WIDTH, 60, fill=(0.10, 0.25, 0.38), stroke=(0.10, 0.25, 0.38))
    canvas.text(LEFT_MARGIN + 16, PAGE_HEIGHT - 78, "SOCProbe Assessment Report", size=20, color=(1, 1, 1), font="Helvetica-Bold")
    canvas.text(LEFT_MARGIN + 16, PAGE_HEIGHT - 96, result["organization"].get("name", ""), size=10, color=(0.85, 0.94, 0.99))
    canvas.y = PAGE_HEIGHT - 132

    canvas.draw_key_values(
        [
            ("Assessment Timestamp", result.get("assessment_timestamp", "")),
            ("Assessment Scope", result.get("assessment_scope", "")),
            ("Domain", result.get("domain", {}).get("fqdn", "")),
            ("Server", f"{result.get('domain', {}).get('server', '')}:{result.get('domain', {}).get('port', 389)}"),
        ],
        columns=2,
    )

    score_breakdown = result.get("score_breakdown", {})
    canvas.draw_section_title("Score Summary")
    canvas.draw_key_values(
        [
            ("Readiness Score", f"{result.get('soc_readiness_score', 0)}/100"),
            ("Risk Tier", result.get("risk_level", "")),
            ("Passed Control Weight", str(score_breakdown.get("passed_control_weight", 0))),
            ("Total Control Weight", str(score_breakdown.get("total_control_weight", 0))),
        ],
        columns=2,
    )

    control_rows = []
    for control, details in score_breakdown.get("controls", {}).items():
        control_rows.append(
            [
                control.replace("_", " ").title(),
                str(details.get("weight", 0)),
                "PASS" if details.get("passed", False) else "FAIL",
                result.get("findings", {}).get(control, {}).get("finding", ""),
            ]
        )
    canvas.draw_table(
        ["Control", "Weight", "Status", "Finding"],
        control_rows,
        widths=[145, 60, 60, CONTENT_WIDTH - 265],
        title="Control Breakdown",
        row_max_chars=[22, 8, 8, 44],
    )

    categories = result.get("event_log_overview", {}).get("categories", {})
    event_rows = [
        ["Successful logons", str(categories.get("successful_logons", {}).get("count", 0))],
        ["Failed logons", str(categories.get("failed_logons", {}).get("count", 0))],
        ["Lockouts", str(categories.get("lockouts", {}).get("count", 0))],
        ["Account changes", str(categories.get("account_changes", {}).get("count", 0))],
        ["Group membership changes", str(categories.get("group_membership_changes", {}).get("count", 0))],
    ]
    canvas.draw_table(
        ["Event Category", "Count"],
        event_rows,
        widths=[CONTENT_WIDTH - 110, 110],
        title="Event Log Summary",
        row_max_chars=[30, 10],
    )

    canvas.draw_section_title("Top Risks")
    top_risks = result.get("top_risks", [])
    if top_risks:
        for risk in top_risks:
            canvas.draw_paragraph(f"[{risk.get('severity', '').upper()}] {risk.get('summary', '')}")
    else:
        canvas.draw_paragraph("No top risks were recorded for this assessment.")

    canvas.draw_section_title("Recommended Actions")
    actions = result.get("remediation_summary", {}).get("recommended_actions", [])
    if actions:
        for action in actions:
            canvas.draw_paragraph(f"[{action.get('priority', '').upper()}] {action.get('recommendation', '')}")
    else:
        canvas.draw_paragraph("No recommended actions were generated for this assessment.")

    canvas.build_pdf(path)


def generate_report(findings, score, tier, config):
    result = build_assessment_result(findings, score, tier, config)
    json_path = Path(config["output"]["report_path"])
    pdf_path = Path(config["output"]["pdf_report_path"])
    json_path.parent.mkdir(parents=True, exist_ok=True)
    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=4)

    _generate_professional_pdf(pdf_path, result)
    return result


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


def build_top_risks(findings: dict, remediation_summary: dict) -> list[dict]:
    risks = []
    for control_name, finding in findings.items():
        if finding.get("passed", False):
            continue
        risks.append(
            {
                "control": control_name,
                "severity": "high" if control_name in {"privileged_groups", "disabled_accounts"} else "medium",
                "summary": finding.get("finding", ""),
            }
        )
    if not risks:
        for action in remediation_summary.get("recommended_actions", [])[:2]:
            risks.append(
                {
                    "control": action.get("control", "general"),
                    "severity": action.get("priority", "low"),
                    "summary": action.get("issue", ""),
                }
            )
    return risks[:3]


def build_assessment_result(findings, score, tier, config):
    score_breakdown = build_score_breakdown(findings, config)
    event_summary = findings.get("log_validation", {}).get("summary", {})
    remediation = build_remediation_summary(findings, config)
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
        "remediation_summary": remediation,
        "top_risks": build_top_risks(findings, remediation),
        "report_paths": {
            "json": config["output"]["report_path"],
            "pdf": config["output"]["pdf_report_path"],
        },
    }


def generate_report(findings, score, tier, config):
    result = build_assessment_result(findings, score, tier, config)

    json_path = Path(config["output"]["report_path"])
    pdf_path = Path(config["output"]["pdf_report_path"])
    json_path.parent.mkdir(parents=True, exist_ok=True)
    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with json_path.open("a", encoding="utf-8"):
            pass
    except PermissionError:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = json_path.with_name(f"{json_path.stem}_{timestamp}{json_path.suffix}")

    try:
        with pdf_path.open("ab"):
            pass
    except PermissionError:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_path = pdf_path.with_name(f"{pdf_path.stem}_{timestamp}{pdf_path.suffix}")

    result["report_paths"]["json"] = str(json_path)
    result["report_paths"]["pdf"] = str(pdf_path)

    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=4)

    _generate_professional_pdf(pdf_path, result)
    return result
