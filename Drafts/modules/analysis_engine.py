from __future__ import annotations

from modules.disabled_account_checker import check_disabled_accounts
from modules.log_validation import check_event_logs
from modules.privileged_group_analyzer import check_privileged_groups
from modules.stale_account_detector import check_stale_accounts


def run_assessment(conn, config: dict) -> dict:
    findings = {}
    findings["privileged_groups"] = check_privileged_groups(conn, config)
    findings["stale_accounts"] = check_stale_accounts(conn, config)
    findings["disabled_accounts"] = check_disabled_accounts(conn, config)
    findings["log_validation"] = check_event_logs(config)
    return findings
