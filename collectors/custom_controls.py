
import json
from typing import Any, Dict, Optional, Tuple

from collectors.windows_local import run_ps


ALLOWED_COLLECTOR_TYPES = {
    "windows_service",
    "registry_value",
    "event_id",
    "local_group_member_count",
    "powershell_boolean",
}


def _compare(actual, operator, expected):
    if operator == "equals":
        return str(actual).strip().lower() == str(expected).strip().lower()
    if operator == "not_equals":
        return str(actual).strip().lower() != str(expected).strip().lower()
    if operator == "greater_than":
        return float(actual) > float(expected)
    if operator == "greater_or_equal":
        return float(actual) >= float(expected)
    if operator == "less_than":
        return float(actual) < float(expected)
    if operator == "less_or_equal":
        return float(actual) <= float(expected)
    if operator == "contains":
        return str(expected).lower() in str(actual).lower()
    raise ValueError(f"Unsupported operator: {operator}")


def evaluate_custom_control(control: Dict[str, Any], thresholds=None) -> Tuple[Optional[bool], str]:
    collector_type = control["collector_type"]
    config = control.get("collector_config", {})
    thresholds = thresholds or {}

    if collector_type not in ALLOWED_COLLECTOR_TYPES:
        return None, f"Unsupported custom collector type: {collector_type}"

    if collector_type == "windows_service":
        service_name = config.get("service_name", "").strip()
        expected_status = config.get("expected_status", "Running")
        if not service_name:
            return False, "Service name is missing."
        out, err, rc = run_ps(
            f"(Get-Service -Name '{service_name}' -ErrorAction SilentlyContinue).Status"
        )
        if not out.strip():
            return False, f"Service '{service_name}' was not found."
        passed = str(out).strip().lower() == str(expected_status).strip().lower()
        return passed, f"Service {service_name} status: {out.strip()}. Expected: {expected_status}."

    if collector_type == "registry_value":
        path = config.get("path", "").strip()
        name = config.get("name", "").strip()
        operator = config.get("operator", "equals")
        expected = config.get("expected")
        if not path or not name:
            return False, "Registry path or value name is missing."
        command = (
            f"(Get-ItemProperty -Path '{path}' -Name '{name}' "
            f"-ErrorAction SilentlyContinue).'{name}'"
        )
        out, err, rc = run_ps(command)
        if out.strip() == "":
            return False, f"Registry value {path}\\{name} was not available."
        passed = _compare(out.strip(), operator, expected)
        return passed, (
            f"Registry value {path}\\{name}: {out.strip()}. "
            f"Rule: {operator} {expected}."
        )

    if collector_type == "event_id":
        event_id = int(config.get("event_id", 0))
        log_name = config.get("log_name", "Security")
        minimum_count = int(config.get("minimum_count", 1))
        out, err, rc = run_ps(
            f"(Get-WinEvent -FilterHashtable @{{LogName='{log_name}'; ID={event_id}}} "
            f"-MaxEvents 500 -ErrorAction SilentlyContinue).Count"
        )
        try:
            count = int(out.strip())
        except ValueError:
            count = 0
        return count >= minimum_count, (
            f"Event ID {event_id} count in {log_name}: {count}. "
            f"Minimum required: {minimum_count}."
        )

    if collector_type == "local_group_member_count":
        group_name = config.get("group_name", "Administrators")
        maximum = int(config.get("maximum_members", 5))
        out, err, rc = run_ps(f"net localgroup \"{group_name}\"")
        members = []
        capture = False
        for line in out.splitlines():
            line = line.strip()
            if "---" in line:
                capture = True
                continue
            if "command completed" in line.lower():
                capture = False
                continue
            if capture and line:
                members.append(line)
        return len(members) <= maximum, (
            f"Local group '{group_name}' member count: {len(members)}. "
            f"Maximum allowed: {maximum}. Members: {', '.join(members[:15])}."
        )

    if collector_type == "powershell_boolean":
        # Restricted to expressions explicitly marked read-only by the administrator.
        expression = config.get("expression", "").strip()
        if not expression:
            return False, "PowerShell boolean expression is missing."

        blocked_tokens = [
            "set-", "new-", "remove-", "delete", "clear-", "stop-",
            "start-", "restart-", "add-", "disable-", "enable-",
            "invoke-expression", "iex", "out-file", "set-content",
            "add-content", "remove-item", "set-itemproperty",
            "new-item", "reg add", "net user", "net localgroup",
        ]
        lowered = expression.lower()
        if any(token in lowered for token in blocked_tokens):
            return None, "The custom PowerShell expression was blocked because it may modify the system."

        out, err, rc = run_ps(f"[bool]({expression})")
        if out.strip().lower() not in {"true", "false"}:
            return False, f"Boolean expression did not return True or False. Output: {out.strip()}"
        passed = out.strip().lower() == "true"
        return passed, f"Read-only PowerShell boolean result: {out.strip()}."

    return None, "No evaluator was available."
