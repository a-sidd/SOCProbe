from __future__ import annotations

import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent


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
            (
                "config.json is missing. Place config.json next to the executable when running a packaged build, "
                "or in the project root when running from source."
            ),
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

    thresholds.setdefault("stale_account_days", 90)
    thresholds.setdefault("max_domain_admins", 3)
    thresholds.setdefault("security_log_lookback_days", 7)
    thresholds.setdefault("security_log_max_events", 250)

    weights.setdefault("privileged_groups", 30)
    weights.setdefault("stale_accounts", 25)
    weights.setdefault("disabled_accounts", 15)
    weights.setdefault("log_validation", 30)

    report_path = _resolve_output_path(runtime_root, output.get("report_path"), "reports\\soc_report.json")
    pdf_report_path = _resolve_output_path(runtime_root, output.get("pdf_report_path"), "reports\\soc_report.pdf")
    report_path.parent.mkdir(parents=True, exist_ok=True)

    output["report_path"] = str(report_path)
    output["pdf_report_path"] = str(pdf_report_path)
    output["report_directory"] = str(report_path.parent)
    output["project_root"] = str(PROJECT_ROOT)
    output["runtime_root"] = str(runtime_root)
    output["config_path"] = str(path)

    return config
