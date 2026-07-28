
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

REPORT_JSON = str(BASE_DIR / "socprobe_saf_real_assessment.json")
REPORT_HTML = str(BASE_DIR / "socprobe_saf_real_report.html")

def score_color(score):
    if score >= 90:
        return "#22C55E"
    if score >= 80:
        return "#A3E635"
    if score >= 70:
        return "#FACC15"
    if score >= 60:
        return "#FB923C"
    return "#EF4444"

def save_reports(report):
    Path(REPORT_JSON).write_text(json.dumps(report, indent=4), encoding="utf-8")

    domain_rows = ""
    for domain, data in report["domain_scores"].items():
        domain_rows += f"<tr><td>{domain}</td><td>{'N/A' if data['score'] is None else str(data['score']) + '%'}</td><td>{data['passed']} / {data['total_controls']}</td></tr>"

    result_rows = ""
    for r in report["results"]:
        cls = "pass" if r["status"] == "PASS" else ("fail" if r["status"] == "FAIL" else "na")
        result_rows += f"""
        <tr class="{cls}">
            <td>{r['id']}</td>
            <td>{r['domain']}</td>
            <td>{r['name']}</td>
            <td>{r['status']}</td>
            <td>{r['risk']}</td>
            <td>{r['earned']} / {r['weight']}</td>
            <td>{r['evidence']}</td>
            <td>{r['recommendation']}</td>
        </tr>
        """

    html = f"""
    <html>
    <head>
        <title>SOCProbe SAF Assessment Report</title>
        <style>
            body {{ background:#0B1120; color:#F8FAFC; font-family:Segoe UI, Arial; padding:30px; }}
            .card {{ background:#111827; border:1px solid #263449; border-radius:16px; padding:22px; margin-bottom:22px; }}
            h1 {{ color:#38BDF8; }}
            .score {{ font-size:52px; font-weight:bold; color:{score_color(report['overall_score'])}; }}
            .grade {{ font-size:34px; font-weight:bold; color:#FACC15; }}
            table {{ width:100%; border-collapse:collapse; margin-top:12px; }}
            th {{ background:#0F172A; color:white; padding:12px; text-align:left; }}
            td {{ padding:10px; border-bottom:1px solid #263449; vertical-align:top; }}
            .pass {{ background:#052E16; }}
            .fail {{ background:#450A0A; }}
            .na {{ background:#1E293B; color:#CBD5E1; }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>SOCProbe Security Assessment Framework Report</h1>
            <p><b>Assessment Time:</b> {report['assessment_time']}</p>
            <p><b>Assessment Mode:</b> {report['assessment_mode']}</p>
            <div class="score">{report['overall_score']}/100</div>
            <div class="grade">Grade {report['grade']} - {report['readiness']}</div>
            <p>{report['summary']}</p>
        </div>

        <div class="card">
            <h2>System Context</h2>
            <pre>{json.dumps(report.get('system_context', {}), indent=4)}</pre>
        </div>

        <div class="card">
            <h2>Assessment Methodology</h2>
            <ol>
                <li>Evidence Collection</li>
                <li>Control Evaluation</li>
                <li>Risk Assessment</li>
                <li>Score Calculation</li>
                <li>Recommendation Generation</li>
            </ol>
        </div>

        <div class="card">
            <h2>Domain Scores</h2>
            <table>
                <tr><th>Domain</th><th>Score</th><th>Controls Passed</th></tr>
                {domain_rows}
            </table>
        </div>

        <div class="card">
            <h2>SAF Control Results</h2>
            <table>
                <tr>
                    <th>Control ID</th>
                    <th>Domain</th>
                    <th>Control</th>
                    <th>Status</th>
                    <th>Risk</th>
                    <th>Score</th>
                    <th>Evidence</th>
                    <th>Recommendation</th>
                </tr>
                {result_rows}
            </table>
        </div>
    </body>
    </html>
    """
    Path(REPORT_HTML).write_text(html, encoding="utf-8")
