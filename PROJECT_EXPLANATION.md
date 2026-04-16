# SOCProbe Project Explanation

## 1. Project purpose

SOCProbe is a local single-company SOC readiness assessment tool built for a Windows Server 2022 lab environment. It is designed for an academic capstone setting where the same server hosts:

- Active Directory Domain Services
- Windows Security Event Logs
- Python
- the SOCProbe application itself

The project assesses a small business style lab environment by checking directory hygiene, privileged access hygiene, and the availability and usefulness of Windows Security Log telemetry. It produces:

- assessment findings
- a weighted SOC readiness score
- a structured JSON report
- a presentation-ready PDF report

The project deliberately stays local, single-company, and desktop-based. It does not implement multi-company tenancy, a web dashboard, or enterprise orchestration.

## 2. Final architecture

The final backend remains modular and follows the capstone architecture:

- `Config Loader`
- `AD Connector`
- `Event Log Reader`
- `Analysis Engine`
- `Scoring Engine`
- `Report Generator`

The desktop layer consumes this backend and presents the results locally through a Tkinter application. A separate companion desktop utility is included to generate controlled lab activity for demos without changing the main product scope.

## 3. Final top-level files

### Main application files

- `main.py`
  - Console entry point for running the backend assessment directly.
- `ui.py`
  - Compatibility launcher for the desktop app.
  - The active launch path points to `socprobe_desktop.py`.
- `socprobe_desktop.py`
  - Final main desktop UI for SOCProbe.
- `launch_socprobe.pyw`
  - Windows launcher for the main desktop app.

### Companion demo utility files

- `socprobe_activity_simulator.py`
  - Separate desktop utility for generating controlled AD and Security Log activity in the lab.
- `launch_socprobe_activity_simulator.pyw`
  - Windows launcher for the simulator utility.

### Configuration and packaging

- `config.json`
  - Primary runtime configuration for the local environment.
- `config.template.json`
  - Template configuration for moving the project to another server.
- `requirements.txt`
  - Python package requirements.
- `SOCProbe.spec`
  - PyInstaller packaging specification.
- `build_socprobe_exe.bat`
  - Convenience batch file for local packaging.

### Outputs and documentation

- `reports/`
  - Generated JSON and PDF assessment reports.
- `PROJECT_EXPLANATION.md`
  - This full verification document.

## 4. Module-by-module breakdown

### `modules/config_loader.py`

Purpose:

- loads `config.json`
- resolves runtime-safe paths
- derives missing defaults
- keeps report output paths safe when launched from different entry points

Key responsibilities:

- locate `config.json` whether the app runs from source or a packaged executable
- derive domain FQDN from `base_dn` if needed
- normalize report paths into absolute local paths
- provide defaults for JSON and PDF report destinations

### `modules/ad_connector.py`

Purpose:

- establish and test LDAP connectivity to Active Directory

Key responsibilities:

- build the LDAP server object
- normalize NTLM usernames into `NETBIOS\username` form when needed
- attempt bind using `ldap3`
- expose connection details for reporting and UI startup checks

Important implementation detail:

- For NTLM in a Windows lab, the code normalizes usernames such as `Administrator` into the correct `SOCLAB\Administrator` style when the config contains the domain FQDN.

### `modules/event_log_reader.py`

Purpose:

- read and summarize recent Windows Security Log activity

Key responsibilities:

- read recent Security log entries
- classify important event categories
- separate likely human-user successful logons from service or machine activity
- produce structured event telemetry summaries for reporting and scoring

Current categories summarized:

- successful logons
- failed logons
- lockouts
- account created / enabled / disabled
- group membership changes

### `modules/log_validation.py`

Purpose:

- translate raw event telemetry into an assessment control result

Key responsibilities:

- determine whether the Windows Security Log is accessible
- evaluate whether the observed telemetry is strong, baseline, limited, or unavailable
- avoid over-penalizing a quiet lab where meaningful telemetry exists but event volume is low

### `modules/privileged_group_analyzer.py`

Purpose:

- inspect privileged group membership and identify excessive privileged access

Key responsibilities:

- enumerate configured privileged groups
- count Domain Admin membership
- compare against configured thresholds
- produce a finding and pass/fail state

### `modules/stale_account_detector.py`

Purpose:

- detect enabled accounts that have been inactive beyond the configured threshold

Key responsibilities:

- review last-logon style indicators available through LDAP
- identify stale enabled accounts
- produce a pass/fail assessment and summary

### `modules/disabled_account_checker.py`

Purpose:

- identify disabled accounts that still hold privileged group membership

Key responsibilities:

- inspect privileged group membership
- identify disabled user objects still present in privileged groups
- produce a pass/fail assessment and summary

### `modules/analysis_engine.py`

Purpose:

- orchestrate the full backend assessment

Key responsibilities:

- call each major control module
- combine the resulting findings into one shared structure

### `modules/scoring_engine.py`

Purpose:

- calculate the final weighted readiness score

Key responsibilities:

- read control weights from configuration
- calculate passed control weight
- compute the score using the capstone formula
- map the numeric score to the readiness tier
- return breakdown data for reports and UI

Formula used:

`Readiness Score = (Passed Control Weight / Total Control Weight) × 100`

Tier mapping:

- `80–100 = High`
- `60–79 = Moderate`
- `40–59 = Low`
- `Below 40 = Poor`

### `modules/report_generator.py`

Purpose:

- build one unified result structure for every output

Key responsibilities:

- assemble the final report object
- write structured JSON
- write the finished PDF
- include connection data, scoring breakdown, findings, event telemetry, top risks, and remediation guidance

Important design choice:

- JSON, PDF, and desktop UI all reuse the same unified result structure so the project does not fork its reporting logic across multiple parallel code paths.

### `modules/company_directory.py`

Purpose:

- legacy exploration module from an earlier iteration

Current status:

- no longer part of the active single-company launch path
- kept only because it was not necessary to remove it to preserve the finished capstone flow

## 5. Data flow from start to finish

### Main desktop or CLI run

1. The app loads configuration through `modules/config_loader.py`.
2. It validates connectivity to Active Directory using `modules/ad_connector.py`.
3. It validates and summarizes Windows Security Log telemetry through `modules/event_log_reader.py` and `modules/log_validation.py`.
4. It runs the AD-focused checks:
   - privileged group analysis
   - stale account detection
   - disabled privileged account checks
5. It collects all findings into a single result set in `modules/analysis_engine.py`.
6. It computes the weighted readiness score and tier through `modules/scoring_engine.py`.
7. It builds the unified report object in `modules/report_generator.py`.
8. It writes:
   - JSON report
   - PDF report
9. The desktop UI displays the same result object in tabs and panels.

## 6. How Active Directory integration works

SOCProbe uses `ldap3` to connect directly to the local or configured domain controller.

The AD connection flow is:

1. Read server, port, base DN, username, and password from config.
2. Derive the FQDN from `base_dn` if not explicitly present.
3. Normalize the configured username for NTLM when needed.
4. Create an LDAP `Server` object.
5. Bind using:
   - `NTLM` when the username is in `DOMAIN\user` format
   - fallback behavior where appropriate for simple binds
6. Return a live connection to the assessment modules.

AD is used for:

- privileged group membership review
- stale account detection
- disabled privileged account detection
- simulator helper actions through PowerShell AD cmdlets

## 7. How Windows Security Log integration works

SOCProbe reads recent Windows Security Log events locally and classifies the event mix into categories relevant to a small SOC readiness review.

The implementation is designed to go beyond a superficial accessibility check. It summarizes:

- successful logons
- failed logons
- lockouts
- account changes
- group membership changes

It also separates likely human-user logons from routine service or machine activity. This is important in small labs where event volume can be dominated by domain controllers, services, machine accounts, or scheduled tasks.

The log validation layer then evaluates:

- whether the Security log can be read at all
- whether telemetry quality is strong, baseline, limited, or unavailable
- whether the environment has enough meaningful signal to support a defendable readiness assessment

## 8. How scoring works

The project uses a configurable weighted rule-based scoring model stored in config.

Default control set:

- `privileged_groups`
- `stale_accounts`
- `disabled_accounts`
- `log_validation`

Default example weights:

- privileged groups: `30`
- stale accounts: `25`
- disabled accounts: `15`
- log validation: `30`

Score calculation:

- sum the weights of controls that passed
- divide by the total configured weight
- multiply by 100

This model is intentionally transparent and academically defendable:

- each control has a clear rule
- each rule has a clear weight
- the result is explainable during a presentation

## 9. How JSON and PDF reporting work

`modules/report_generator.py` builds a unified result object containing:

- organization metadata
- domain metadata
- timestamp
- scope
- readiness score
- risk tier
- score breakdown
- connection summary
- findings
- event log overview
- remediation summary
- top risks
- report paths

### JSON report

The JSON report is the authoritative structured output. It is designed to be:

- machine-readable
- easy to inspect during demos
- easy to reuse later if another frontend is built

### PDF report

The PDF report is locally generated and presentation-oriented. It includes:

- professional title area
- organization and assessment metadata
- score summary block
- control breakdown table
- event telemetry summary table
- top risks
- recommended actions

## 10. How the main desktop UI works

The final main desktop UI is implemented in `socprobe_desktop.py`.

It keeps the project local and simple while still being presentation-ready. The UI includes:

- startup connection checks for:
  - Active Directory
  - Windows Security Log
- clear assessment state:
  - ready
  - running
  - complete
- step-by-step scan progress
- score and risk tier display
- findings summary
- event log summary
- top risks
- recommended actions
- report actions
- scoring methodology tab

### Main tabs

- `Overview`
  - metadata, status, score, findings, risks, remediation, progress
- `Reports`
  - in-app summary and raw JSON display
- `Scoring Methodology`
  - formula, weights, control status, passed weight, total weight, score, tier, and tier mapping

### Scan progress behavior

During an assessment, the UI shows the real sequence of backend operations:

1. Loading configuration
2. Validating environment
3. Connecting to Active Directory
4. Validating Windows Security Log access
5. Enumerating privileged groups
6. Checking stale accounts
7. Checking disabled privileged accounts
8. Reading recent security events
9. Calculating weighted readiness score
10. Generating JSON report
11. Generating PDF report
12. Finalizing assessment

The UI remains responsive because the work runs in a background thread and only the UI updates are marshaled back to the Tkinter main thread.

## 11. How the lab/demo utility works

The companion simulator is implemented in `socprobe_activity_simulator.py`.

Purpose:

- generate controlled demo activity
- support live classroom or professor presentations
- remain clearly separate from the main assessment product

The simulator provides actions for:

- failed logon generation helper
- successful logon helper
- disable user
- enable user
- add user to demo group
- remove user from demo group
- add user to Domain Admins
- remove user from Domain Admins
- remove disabled privileged accounts from Domain Admins
- open Event Viewer
- open Active Directory Users and Computers
- launch the main SOCProbe app
- open the reports folder

### Simulator design choices

- it uses confirmation dialogs for impactful actions
- it uses real LDAP bind attempts for logon helpers
- it uses PowerShell AD cmdlets for account and group changes
- it keeps a live local activity log so the presenter can see what was triggered

This keeps lab activity generation practical without turning the main SOCProbe assessment app into a testing console.

## 12. Launch commands

### Main app

- `python ui.py`
- `python launch_socprobe.pyw`

### Backend only

- `python main.py`

### Lab/demo utility

- `python socprobe_activity_simulator.py`
- `python launch_socprobe_activity_simulator.pyw`

## 13. Setup required on another server

To run SOCProbe on another Windows Server lab:

1. Install Python.
2. Install the project requirements from `requirements.txt`.
3. Place the project folder locally on the server.
4. Copy `config.template.json` to `config.json`.
5. Update:
   - organization metadata
   - domain server
   - base DN
   - username
   - password
   - thresholds
   - weights
6. Ensure Active Directory is installed and reachable from the local machine.
7. Ensure the account used by SOCProbe can:
   - bind to LDAP
   - enumerate users and groups
   - read the Windows Security log
8. Launch the desktop app locally and run the assessment.

## 14. Capstone scope versus future scope

### In current capstone scope

- single-company local deployment
- Active Directory connectivity
- Windows Security Log analysis
- weighted readiness scoring
- JSON report generation
- PDF report generation
- local desktop UI
- separate demo/lab simulator

### Explicit future scope

- multi-company support
- enterprise dashboarding
- Flask or React frontend
- remote multi-server orchestration
- persistent historical trend database
- scheduled assessments and alerting
- broader control-library expansion

## 15. Remaining limitations

- Windows Security Log access still depends on local privileges.
  - If the process lacks permission, the tool reports that honestly instead of fabricating telemetry.
- The stale-account logic is designed for a controlled academic lab and may need tuning for larger production domains.
- The simulator assumes the ActiveDirectory PowerShell module is available for account and group actions.
- The simulator is intentionally minimal and presentation-oriented, not a full adversary emulation platform.

## 16. Files kept for compatibility or legacy reasons

The active final path is:

- `socprobe_desktop.py`
- `ui.py`
- `launch_socprobe.pyw`

Legacy or compatibility files still present in the workspace include:

- `modules/company_directory.py`

This file is not part of the active final launch path. It remains only as an older helper module from a previous directory-exploration iteration.

## 17. Lab environment assumptions

The project assumes a demonstration lab with:

- one company only
- one local Windows Server 2022 system hosting the assessment
- Active Directory running locally
- Event Viewer / Security Log available locally
- a small set of test users and groups
- a presenter who can trigger safe demo activity before running a scan

Recommended demo assumptions:

- use one or more known demo users rather than built-in administrator accounts
- create a benign demo group such as `VPN Users`
- keep any Domain Admin changes temporary and fully reversible
- use the simulator only in a lab, never in a production domain

## 18. Final deliverable summary

The finished project now consists of:

- a local SOC assessment backend
- a local desktop UI for running and presenting assessments
- structured JSON and PDF reporting
- a separate local activity simulator for live demos
- a documented single-company capstone architecture

That combination keeps the project academically defensible, practical to demonstrate, and clearly scoped to the capstone requirements.
