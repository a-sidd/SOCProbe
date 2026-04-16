CONTROL_WEIGHTS = {
    "privileged_groups": 25,
    "stale_accounts": 20,
    "disabled_accounts": 10,
    "log_validation": 20,
}


def calculate_score(findings):
    total_weight = sum(CONTROL_WEIGHTS.values())
    passed_weight = 0

    for control, weight in CONTROL_WEIGHTS.items():
        if findings.get(control, {}).get("passed", False):
            passed_weight += weight

    score = round((passed_weight / total_weight) * 100, 1)

    if score >= 80:
        tier = "HIGH"
    elif score >= 60:
        tier = "MODERATE"
    elif score >= 40:
        tier = "LOW"
    else:
        tier = "POOR"

    print(f"[+] Score calculated: {score}/100 — {tier}")
    return score, tier


DEFAULT_CONTROL_WEIGHTS = {
    "privileged_groups": 30,
    "stale_accounts": 25,
    "disabled_accounts": 15,
    "log_validation": 30,
}

CONTROL_WEIGHTS = dict(DEFAULT_CONTROL_WEIGHTS)


def get_control_weights(config: dict | None = None) -> dict:
    weights = dict(DEFAULT_CONTROL_WEIGHTS)
    if config:
        weights.update(config.get("weights", {}))
    return weights


def calculate_score(findings: dict, config: dict | None = None):
    weights = get_control_weights(config)
    total_weight = sum(weights.values())
    passed_weight = 0

    for control, weight in weights.items():
        if findings.get(control, {}).get("passed", False):
            passed_weight += weight

    score = round((passed_weight / total_weight) * 100, 1) if total_weight else 0.0

    if score >= 80:
        tier = "HIGH"
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
    passed_weight = sum(
        weight for control, weight in weights.items() if findings.get(control, {}).get("passed", False)
    )
    score, tier = calculate_score(findings, config)
    return {
        "formula": "Readiness Score = (Passed Control Weight / Total Control Weight) x 100",
        "passed_control_weight": passed_weight,
        "total_control_weight": total_weight,
        "controls": {
            control: {
                "weight": weight,
                "passed": findings.get(control, {}).get("passed", False),
            }
            for control, weight in weights.items()
        },
        "score": score,
        "tier": tier,
    }
