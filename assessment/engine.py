
from datetime import datetime

from framework.saf_controls import SAF_CONTROLS
from database.repository import get_active_profile, list_controls, save_assessment_run
from collectors.windows_local import COLLECTORS, get_system_context, run_ps
from collectors.active_directory import (
    check_domain_admins,
    check_enterprise_admins,
    check_stale_ad_users,
    check_disabled_privileged_users,
    check_password_never_expires,
    check_spn_accounts,
    check_domain_controllers,
    check_fsmo_roles,
)
from collectors.custom_controls import evaluate_custom_control
from collectors.entra_id import (
    load_entra_config,
    check_entra_connection,
    check_entra_user_inventory,
    check_entra_global_admins,
    check_entra_guest_accounts,
    check_entra_disabled_accounts,
    check_entra_mfa_coverage,
    check_entra_conditional_access,
    check_entra_role_visibility,
)

COLLECTORS.update({
    "domain_admins": check_domain_admins,
    "enterprise_admins": check_enterprise_admins,
    "stale_ad_users": check_stale_ad_users,
    "disabled_privileged_users": check_disabled_privileged_users,
    "password_never_expires": check_password_never_expires,
    "spn_accounts": check_spn_accounts,
    "domain_controllers": check_domain_controllers,
    "fsmo_roles": check_fsmo_roles,
    "entra_connection": check_entra_connection,
    "entra_user_inventory": check_entra_user_inventory,
    "entra_global_admins": check_entra_global_admins,
    "entra_guest_accounts": check_entra_guest_accounts,
    "entra_disabled_accounts": check_entra_disabled_accounts,
    "entra_mfa_coverage": check_entra_mfa_coverage,
    "entra_conditional_access": check_entra_conditional_access,
    "entra_role_visibility": check_entra_role_visibility,
})



def detect_assessment_environment(context):
    """Return non-sensitive facts used to decide which controls are applicable."""
    part_of_domain = bool(context.get("PartOfDomain", False))

    try:
        domain_role = int(context.get("DomainRole", -1))
    except (TypeError, ValueError):
        domain_role = -1

    # Win32_ComputerSystem DomainRole values 4 and 5 represent domain controllers.
    is_domain_controller = domain_role in (4, 5)

    module_output, _, module_rc = run_ps(
        "[bool](Get-Module -ListAvailable -Name ActiveDirectory)"
    )
    ad_module_available = (
        module_rc == 0 and module_output.strip().lower() == "true"
    )

    try:
        entra_configured = load_entra_config() is not None
        entra_config_error = ""
    except Exception as exc:
        entra_configured = False
        entra_config_error = str(exc)

    return {
        "is_windows": True,
        "domain_joined": part_of_domain,
        "domain_controller": is_domain_controller,
        "ad_module_available": ad_module_available,
        "ad_assessment_available": part_of_domain and ad_module_available,
        "entra_configured": entra_configured,
        "entra_config_error": entra_config_error,
        "detected_domain": context.get("Domain", "Unknown"),
        "machine_role": (
            "Domain Controller"
            if is_domain_controller
            else "Domain-Joined Windows Host"
            if part_of_domain
            else "Standalone Windows Host"
        ),
    }


def get_control_applicability(control, environment):
    """Return (applicable, reason) for a control in the detected environment."""
    domain = control.get("domain", "")

    if domain == "Local Windows Security":
        if environment.get("is_windows"):
            return True, ""
        return False, "This control requires a Windows operating system."

    # Readiness controls intentionally run everywhere because they establish
    # whether Active Directory assessment prerequisites are present.
    if domain == "Active Directory Readiness":
        return True, ""

    if domain == "Active Directory Security":
        if not environment.get("domain_joined"):
            return False, (
                "This machine is not joined to an Active Directory domain."
            )
        if not environment.get("ad_module_available"):
            return False, (
                "The Active Directory PowerShell module is unavailable. "
                "Install RSAT AD tools or run SOCProbe on a domain controller."
            )
        return True, ""

    if domain == "Microsoft Entra Security":
        if not environment.get("entra_configured"):
            detail = environment.get("entra_config_error")
            reason = (
                "Microsoft Entra assessment is not configured. "
                "Create entra_config.json or set the SOCProbe Entra environment variables."
            )
            if detail:
                reason += f" Configuration detail: {detail}"
            return False, reason
        return True, ""

    # Custom controls remain applicable unless future metadata says otherwise.
    return True, ""


def get_grade(profile, score):
    for band in sorted(profile["grade_bands"], key=lambda x: x["minimum"], reverse=True):
        if score >= band["minimum"]:
            return band["grade"], band["label"]
    return "N/A", "Unrated"


def evaluate_controls(mode="real", scenario="balanced", progress_callback=None):
    profile = get_active_profile()
    context = get_system_context() if mode == "real" else {"DemoMode": True}
    environment = (
        detect_assessment_environment(context)
        if mode == "real"
        else {"demo_mode": True}
    )
    context["AssessmentEnvironment"] = environment
    results = []

    demo_failures = {
        "excellent": set(),
        "balanced": {"SAF-LW-06", "SAF-LW-08", "SAF-AD-05", "SAF-EN-04"},
        "logging_gap": {"SAF-LW-03", "SAF-LW-04", "SAF-LW-05", "SAF-LW-06"},
        "identity_risk": {"SAF-LW-12", "SAF-AD-03", "SAF-AD-05", "SAF-EN-03"},
        "cloud_gap": {"SAF-EN-03", "SAF-EN-04", "SAF-EN-06", "SAF-EN-07"},
        "critical": {
            "SAF-LW-01", "SAF-LW-02", "SAF-LW-03", "SAF-LW-05",
            "SAF-LW-07", "SAF-LW-08", "SAF-AD-03", "SAF-AD-05",
            "SAF-EN-03", "SAF-EN-06", "SAF-EN-07",
        },
    }
    failures = demo_failures.get(scenario, demo_failures["balanced"])

    control_library = list_controls(include_disabled=False)
    builtin_lookup = {control["id"]: control for control in SAF_CONTROLS}
    total_controls = len(control_library)

    for index, library_control in enumerate(control_library, start=1):
        if library_control["is_builtin"]:
            base_control = builtin_lookup.get(library_control["control_id"])
            if not base_control:
                continue
        else:
            base_control = {
                "id": library_control["control_id"],
                "domain": library_control["domain"],
                "name": library_control["name"],
                "objective": library_control["objective"],
                "collector": None,
                "weight": library_control["default_weight"],
                "risk": library_control["default_risk"],
                "recommendation": library_control["recommendation"],
            }
        settings = profile["controls"].get(base_control["id"], {
            "enabled": True,
            "weight": base_control.get("weight", 0),
            "risk": base_control.get("risk", "Medium"),
            "thresholds": {},
        })

        if progress_callback:
            progress_callback(
                index - 1,
                total_controls,
                f"Assessing {base_control['id']} — {base_control['name']}",
            )

        if not settings.get("enabled", False):
            status = "NOT ASSESSED"
            evidence = "Control disabled in the active methodology."
            earned = 0
            assessed_weight = 0
        elif mode == "real":
            applicable, reason = get_control_applicability(base_control, environment)
            if not applicable:
                status = "NOT APPLICABLE"
                evidence = reason
                earned = 0
                assessed_weight = 0
            else:
                if library_control["is_builtin"]:
                    collector = COLLECTORS.get(base_control.get("collector"))
                    if not collector:
                        outcome = None
                        evidence = "No evidence collector is mapped to this control."
                    else:
                        try:
                            outcome, evidence = collector(settings.get("thresholds", {}))
                        except Exception as exc:
                            outcome = False
                            evidence = f"Collector error: {exc}"
                else:
                    try:
                        outcome, evidence = evaluate_custom_control(
                            library_control,
                            settings.get("thresholds", {}),
                        )
                    except Exception as exc:
                        outcome = False
                        evidence = f"Custom collector error: {exc}"

                if outcome is True:
                    status = "PASS"
                    earned = settings["weight"]
                    assessed_weight = settings["weight"]
                elif outcome is False:
                    status = "FAIL"
                    earned = 0
                    assessed_weight = settings["weight"]
                else:
                    status = "NOT ASSESSED"
                    earned = 0
                    assessed_weight = 0
        elif mode == "demo":
            passed = base_control["id"] not in failures
            status = "PASS" if passed else "FAIL"
            earned = settings["weight"] if passed else 0
            assessed_weight = settings["weight"]
            evidence = (
                "Demo evidence meets the active methodology."
                if passed else
                "Demo evidence does not meet the active methodology."
            )

        results.append({
            **base_control,
            "weight": settings["weight"],
            "risk": settings["risk"],
            "thresholds": settings.get("thresholds", {}),
            "status": status,
            "earned": earned,
            "assessed_weight": assessed_weight,
            "evidence": evidence,
        })

    if progress_callback:
        progress_callback(total_controls, total_controls, "Calculating assessment score...")

    report = build_report(
        results,
        "real_assessment" if mode == "real" else f"demo_{scenario}",
        context,
        profile,
    )
    save_assessment_run(report)
    return report


def run_real_assessment(progress_callback=None):
    return evaluate_controls("real", progress_callback=progress_callback)


def run_demo_assessment(scenario="balanced", progress_callback=None):
    return evaluate_controls("demo", scenario=scenario, progress_callback=progress_callback)


def build_report(results, mode, context, profile):
    excluded_statuses = {"NOT ASSESSED", "NOT APPLICABLE"}
    assessed = [r for r in results if r["status"] not in excluded_statuses]
    total_weight = sum(r["assessed_weight"] for r in assessed)
    earned_weight = sum(r["earned"] for r in assessed)
    score = round((earned_weight / total_weight) * 100) if total_weight else 0
    grade, readiness = get_grade(profile, score)

    domains = {}
    for result in results:
        data = domains.setdefault(result["domain"], {
            "earned": 0,
            "total": 0,
            "passed": 0,
            "failed": 0,
            "not_assessed": 0,
            "not_applicable": 0,
            "total_controls": 0,
        })
        data["total_controls"] += 1

        if result["status"] == "NOT ASSESSED":
            data["not_assessed"] += 1
            continue
        if result["status"] == "NOT APPLICABLE":
            data["not_applicable"] += 1
            continue

        data["earned"] += result["earned"]
        data["total"] += result["assessed_weight"]
        if result["status"] == "PASS":
            data["passed"] += 1
        else:
            data["failed"] += 1

    for data in domains.values():
        data["score"] = round(data["earned"] / data["total"] * 100) if data["total"] else None

    findings = [r for r in results if r["status"] == "FAIL"]
    not_assessed = [r for r in results if r["status"] == "NOT ASSESSED"]
    not_applicable = [r for r in results if r["status"] == "NOT APPLICABLE"]

    return {
        "tool": "SOCProbe Enterprise",
        "version": "4.2.1",
        "assessment_time": str(datetime.now()),
        "assessment_mode": mode,
        "active_profile": profile["profile_name"],
        "profile_description": profile.get("description", ""),
        "system_context": context,
        "overall_score": score,
        "grade": grade,
        "readiness": readiness,
        "total_controls": len(results),
        "assessed_controls": len(assessed),
        "passed_controls": len([r for r in results if r["status"] == "PASS"]),
        "failed_controls": len(findings),
        "not_assessed_controls": len(not_assessed),
        "not_applicable_controls": len(not_applicable),
        "domain_scores": domains,
        "results": results,
        "findings": findings,
        "not_assessed": not_assessed,
        "not_applicable": not_applicable,
        "methodology": [
            "Evidence Collection",
            "Configurable Control Evaluation",
            "Risk Assessment",
            "Weighted Score Calculation",
            "Recommendation Generation",
        ],
        "summary": (
            f"SOCProbe used the '{profile['profile_name']}' methodology to evaluate "
            f"{len(assessed)} of {len(results)} controls. The assessed controls scored "
            f"{score}/100 with grade {grade} ({readiness}). {len(findings)} controls "
            f"failed, {len(not_assessed)} were not assessed, and "
            f"{len(not_applicable)} were not applicable to the detected environment."
        ),
    }
