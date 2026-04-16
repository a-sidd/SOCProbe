# ============================================================
# SOCProbe v1.0
# Local SOC Assessment Tool for SMBs
# Sheridan College — INFO36206 Capstone
# Team: Syed Ahmed, Ahsan Siddiq, Vaqas Mirza
# ============================================================

from modules.ad_connector import connect_to_ad
from modules.analysis_engine import run_assessment
from modules.config_loader import ConfigLoadError, load_config
from modules.scoring_engine import calculate_score
from modules.report_generator import generate_report

def main():
    print("=" * 55)
    print("  SOCProbe v1.0 — Local SOC Assessment Tool")
    print("  Sheridan College Capstone — INFO36206")
    print("=" * 55)

    try:
        config = load_config()
    except ConfigLoadError as exc:
        print("\n[!] Configuration missing")
        print(f"    config.json expected at: {exc.expected_path}")
        print(f"    reports folder: {exc.report_directory} (created automatically when needed)")
        raise SystemExit(1)

    conn = connect_to_ad(config)

    print("\n[*] Running checks...\n")
    findings = run_assessment(conn, config)

    score, tier = calculate_score(findings, config)

    result = generate_report(findings, score, tier, config)

    print("\n" + "=" * 55)
    print(f"  SOC Readiness Score : {score} / 100")
    print(f"  Risk Level          : {tier}")
    print(f"  Controls Passed     : {findings['privileged_groups']['passed']} Privileged Groups")
    print(f"                      : {findings['stale_accounts']['passed']} Stale Accounts")
    print(f"                      : {findings['disabled_accounts']['passed']} Disabled Accounts")
    print(f"                      : {findings['log_validation']['passed']} Log Validation")
    print(f"  Organization        : {config['organization']['name']}")
    print(f"  JSON Report         : {result['report_paths']['json']}")
    print(f"  PDF Report          : {result['report_paths']['pdf']}")
    print("=" * 55)

if __name__ == "__main__":
    main()
