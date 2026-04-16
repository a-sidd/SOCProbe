from __future__ import annotations

from modules.event_log_reader import read_security_events


def check_event_logs(config: dict) -> dict:
    return read_security_events(config)
