# SOCProbe Enterprise v4.2.1

SOCProbe is a Windows desktop security assessment prototype for small and medium-sized organizations. It collects evidence from a local Windows host, Active Directory, and Microsoft Entra ID, evaluates that evidence against the SOCProbe Security Assessment Framework (SAF), calculates weighted readiness scores, and exports detailed JSON and HTML reports.

This repository contains the final v4.2.1 source release of the Sheridan College Cybersecurity Capstone project by Group 23. It is an academic assessment tool, not a replacement for a SIEM, vulnerability scanner, penetration test, or formal compliance audit.

## Project status

- Version: 4.2.1
- Delivery type: Local Python/Tkinter desktop application
- Primary platform: Windows 10, Windows 11, and Windows Server
- Entry point: `SOCProbe.py`
- Built-in controls: 30
- Reports: JSON and HTML
- Persistence: Local SQLite database
- Cloud integration: Microsoft Graph through an Entra app registration

The repository currently provides a source-based installation. A signed installer or packaged executable is not included.

## What SOCProbe assesses

The built-in SAF library contains 30 controls across four domains:

| Domain | Controls | Examples |
| --- | ---: | --- |
| Local Windows Security | 12 | Firewall, Defender, Security log access and retention, audit policy, password policy, RDP, Windows Update, WDigest, local administrators |
| Active Directory Readiness | 2 | Domain membership and availability of the Active Directory PowerShell module |
| Active Directory Security | 8 | Domain and Enterprise Admin membership, stale users, disabled privileged users, non-expiring passwords, SPN accounts, domain controllers, FSMO roles |
| Microsoft Entra Security | 8 | Graph connectivity, user inventory, Global Administrators, guests, disabled users, MFA registration, Conditional Access, role visibility |

Control definitions are maintained in [`framework/saf_controls.py`](framework/saf_controls.py). Default thresholds and database initialization are maintained in [`database/repository.py`](database/repository.py).

## Main capabilities

- Runs real Windows, Active Directory, and Microsoft Entra evidence collectors
- Detects the assessment environment before evaluating controls
- Excludes controls that do not apply to the detected environment
- Provides safe demo scenarios for presentation and interface testing
- Supports multiple methodology profiles
- Allows control weights, risks, thresholds, grade bands, and enablement to be changed
- Supports custom read-only Windows controls through approved collector templates
- Stores profiles, control settings, grade bands, and assessment history in SQLite
- Produces overall and domain-level scores
- Distinguishes `PASS`, `FAIL`, `NOT ASSESSED`, and `NOT APPLICABLE`
- Exports human-readable HTML and structured JSON results

## Architecture

| Component | Responsibility |
| --- | --- |
| `SOCProbe.py` | Tkinter desktop interface, workflow controls, dashboard, result filtering, and report access |
| `assessment/engine.py` | Environment detection, applicability decisions, control orchestration, scoring, and report assembly |
| `framework/saf_controls.py` | Built-in SAF control definitions, objectives, collectors, risks, weights, and recommendations |
| `collectors/windows_local.py` | Local Windows and Active Directory readiness evidence collection through PowerShell |
| `collectors/active_directory.py` | Active Directory evidence collection through the RSAT AD PowerShell module |
| `collectors/entra_id.py` | Microsoft Graph authentication, paging, and Entra evidence collection |
| `collectors/custom_controls.py` | Evaluation of approved custom collector templates |
| `database/repository.py` | SQLite schema, seed data, profiles, controls, grade bands, and assessment history |
| `reports/report_generator.py` | JSON and HTML report generation |
| `ui/` | Profile Manager, Control Library, and Entra configuration windows |

## Environment-aware assessment

SOCProbe first gathers non-sensitive system context from `Win32_ComputerSystem`, checks for the Active Directory PowerShell module, and checks whether valid Entra configuration is present. It then determines which controls can be evaluated.

| Detected condition | Result |
| --- | --- |
| Windows host available | Local Windows controls run |
| Host is not domain joined | AD readiness controls run; AD security controls become `NOT APPLICABLE` |
| Host is domain joined but RSAT AD tools are unavailable | AD readiness controls run; AD security controls become `NOT APPLICABLE` with a prerequisite explanation |
| Host is domain joined and the AD module is available | AD security controls run |
| Entra credentials are absent or incomplete | Entra controls become `NOT APPLICABLE` |
| Entra credentials are present | Entra controls attempt Microsoft Graph collection |
| A control is disabled in the active profile | The control becomes `NOT ASSESSED` |

`NOT APPLICABLE` and `NOT ASSESSED` controls are excluded from the scoring denominator. Their status and reason remain visible in the results and reports.

## Scoring model

Each enabled and applicable control has a configurable weight. A passing control earns its full weight and a failing control earns zero. The score is normalized against the controls that were actually assessed:

```text
overall score = earned assessed weight / total assessed weight x 100
```

Domain scores use the same calculation within each domain. Grade bands are stored per methodology profile and can be edited in Profile Manager.

This score is an assessment indicator. It is not a certification or proof of compliance.

## Requirements

### Base requirements

- Windows 10, Windows 11, or Windows Server
- Python 3.12 or later recommended
- Tkinter, included with standard Windows Python installations
- Windows PowerShell 5.1 or a compatible `powershell.exe`
- Network access only when Entra assessment is used

### Active Directory requirements

- The assessment host must be domain joined for AD security controls to apply
- The Active Directory PowerShell module must be available
- The running account must have permission to read the assessed directory objects
- RSAT Active Directory Domain Services tools may be installed on a Windows client when required

Run PowerShell as Administrator to inspect and install the RSAT capability:

```powershell
Get-WindowsCapability -Online | Where-Object Name -like 'Rsat.ActiveDirectory*'
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

### Microsoft Entra requirements

SOCProbe uses the OAuth 2.0 client-credentials flow, so the app registration uses Microsoft Graph **application permissions** and requires tenant administrator consent. The least-privilege permissions required by the current collectors are:

| Collector need | Microsoft Graph application permission |
| --- | --- |
| User inventory, guest, and disabled-user checks | `User.Read.All` |
| Directory roles and role membership | `RoleManagement.Read.Directory` |
| MFA registration report | `AuditLog.Read.All` |
| Conditional Access policies | `Policy.Read.All` |

Tenant licensing and service configuration can affect the availability of specific Graph reports. Use a dedicated app registration, grant only the permissions required above, and remove or rotate the client secret when the assessment is complete.

## Installation

### 1. Download the repository

```powershell
git clone https://github.com/a-sidd/SOCProbe-Enterprise.git
cd SOCProbe-Enterprise
```

Alternatively, download the repository ZIP from GitHub and extract it to a local folder.

### 2. Create a virtual environment

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks the activation script, use Command Prompt instead:

```bat
.venv\Scripts\activate.bat
```

### 3. Install dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 4. Start SOCProbe

```powershell
python SOCProbe.py
```

Do not use `python main.py`; the final repository does not contain `main.py`.

For complete local Windows and Security log evidence, run the terminal with the permissions appropriate to the environment. Administrator privileges may be necessary for some evidence sources.

## First-run behavior

On first launch, SOCProbe creates `socprobe.db` in the project root. The database is seeded with:

- the 30 built-in SAF controls
- the `SOCProbe Default` profile
- the `Small Business` profile
- default thresholds and grade bands

The database is local runtime state and is intentionally excluded from Git.

## Using the application

### Run a real assessment

1. Start `SOCProbe.py` on the Windows system being assessed.
2. Open **Profile Manager** and confirm the active methodology.
3. Configure Entra only if cloud assessment is required.
4. Select **Run Real Windows/AD/Entra Assessment**.
5. Review the overall score, domain scores, status totals, and evidence table.
6. Open the generated JSON or HTML report from the interface.

### Run a demo assessment

Demo modes generate predictable presentation data without claiming that live evidence was collected. Available scenarios include excellent, balanced, logging gap, identity risk, cloud gap, and critical.

Demo output is clearly identified by its assessment mode in the report.

### Manage profiles

Open **Profile Manager** to:

- create, duplicate, activate, and delete profiles
- change control weights and risk ratings
- enable or disable controls
- edit threshold JSON
- edit grade bands

Changes are saved in `socprobe.db`.

### Manage the control library

Open **Control Library** to add, edit, duplicate, enable, disable, or delete custom controls. Built-in controls cannot be deleted and their collector mappings cannot be changed through the interface.

Approved custom collector templates are:

- `windows_service`
- `registry_value`
- `event_id`
- `local_group_member_count`
- `powershell_boolean`

The `powershell_boolean` template blocks common modification commands and is intended for simple read-only expressions. Custom controls should still be reviewed before use.

Example collector configuration:

```json
{
  "service_name": "Spooler",
  "expected_status": "Stopped"
}
```

## Entra configuration

### Option A: Application interface

1. Copy `entra_config.example.json` to `entra_config.json`, or open **Entra Config** in the application.
2. Enter the tenant ID, application/client ID, and client secret.
3. Test the connection.

The local file format is:

```json
{
  "tenant_id": "YOUR_TENANT_ID",
  "client_id": "YOUR_APPLICATION_CLIENT_ID",
  "client_secret": "YOUR_CLIENT_SECRET_VALUE"
}
```

### Option B: Environment variables

Environment variables take precedence over `entra_config.json`:

```powershell
$env:SOCPROBE_ENTRA_TENANT_ID = "your-tenant-id"
$env:SOCPROBE_ENTRA_CLIENT_ID = "your-client-id"
$env:SOCPROBE_ENTRA_CLIENT_SECRET = "your-client-secret"
python SOCProbe.py
```

Never commit `entra_config.json`, real client secrets, access tokens, customer data, the SQLite database, or generated assessment reports.

## Outputs

SOCProbe writes the following runtime files to the project root:

| File | Purpose | Tracked in Git |
| --- | --- | --- |
| `socprobe.db` | Profiles, controls, grade bands, and assessment history | No |
| `socprobe_saf_real_assessment.json` | Structured assessment report | No |
| `socprobe_saf_real_report.html` | Human-readable assessment report | No |
| `entra_config.json` | Optional local Entra credentials | No |

The JSON report contains the assessment mode, active profile, system context, score, grade, status totals, domain scores, per-control evidence, findings, exclusions, and methodology steps.

## Database structure

SQLite is sufficient for this application because SOCProbe is a local, single-user desktop assessment tool with low write volume and no requirement for concurrent remote access.

| Table | Purpose |
| --- | --- |
| `profiles` | Methodology names, descriptions, and active state |
| `controls` | Built-in and custom control definitions |
| `profile_controls` | Per-profile enablement, weight, risk, and thresholds |
| `grade_bands` | Per-profile score-to-grade mapping |
| `assessment_runs` | Historical report snapshots stored as JSON |

Foreign keys protect profile and control relationships. The database is created automatically and does not require a separate database server.

## Repository structure

```text
SOCProbe-Enterprise/
├── SOCProbe.py
├── README.md
├── CONTRIBUTIONS.md
├── requirements.txt
├── entra_config.example.json
├── assessment/
│   └── engine.py
├── collectors/
│   ├── active_directory.py
│   ├── custom_controls.py
│   ├── entra_id.py
│   └── windows_local.py
├── database/
│   └── repository.py
├── framework/
│   └── saf_controls.py
├── reports/
│   └── report_generator.py
└── ui/
    ├── control_library.py
    ├── entra_config.py
    └── profile_manager.py
```

Each Python package also contains an `__init__.py` file. Runtime files and generated caches are excluded through `.gitignore`.

## Security and data handling

- Local Windows and AD evidence is collected through read-only PowerShell commands
- Entra access uses a confidential client and read-only Graph permissions
- Graph paging is supported for multi-page responses
- Secrets are excluded from version control but are not encrypted when stored in `entra_config.json`
- Assessment history can contain sensitive evidence and is stored locally in plaintext SQLite
- Generated reports can contain usernames, group memberships, domain details, and security findings
- Custom collector definitions should be reviewed by an administrator before execution

Treat the database and reports as confidential security records. Store them in an access-controlled location and delete them according to the organization's retention policy.

## Known limitations

- SOCProbe is an academic prototype and has not undergone independent security certification
- It runs from source; no signed installer or auto-update mechanism is included
- The desktop interface and local collectors are Windows-specific
- Results depend on the permissions, visibility, logging, licensing, and services available to the assessment account
- The tool provides point-in-time evidence, not continuous monitoring or alerting
- It does not remediate findings automatically
- It does not replace manual validation, risk analysis, or a formal audit
- Entra uses a client secret stored in plaintext when file-based configuration is selected
- SQLite supports the intended local single-user workflow, not centralized multi-user deployment
- Automated unit and integration test suites are not included in the final repository

## Troubleshooting

### `python main.py` fails

Use the final entry point:

```powershell
python SOCProbe.py
```

### Active Directory controls are not applicable

Confirm that the computer is domain joined and that `Get-ADUser` is available:

```powershell
(Get-CimInstance Win32_ComputerSystem).PartOfDomain
Get-Command Get-ADUser
```

Install RSAT AD tools if required and rerun SOCProbe.

### Entra controls are not applicable

Confirm that all three Entra values are present, the app has administrator consent for the required application permissions, and the client secret has not expired.

### Microsoft Graph returns `403 Forbidden`

Review the exact collector evidence, verify the corresponding Graph application permission, grant administrator consent, and confirm any tenant licensing or role prerequisite for the requested report.

### Security log evidence cannot be collected

Run from a terminal with sufficient local permissions and confirm that the Windows Security log is enabled and readable.

### Reset local methodology data

Close SOCProbe, back up `socprobe.db` if its history is needed, and then remove the database. SOCProbe will recreate the default database on the next launch. This permanently removes local profiles, custom controls, and assessment history from that database.

## Version control and contribution record

- Repository: <https://github.com/a-sidd/SOCProbe-Enterprise>
- Commit history: <https://github.com/a-sidd/SOCProbe-Enterprise/commits/main/>
- Contributors: <https://github.com/a-sidd/SOCProbe-Enterprise/graphs/contributors>
- Team contribution record: [`CONTRIBUTIONS.md`](CONTRIBUTIONS.md)
- Final pre-release integration milestone: [`91adb60`](https://github.com/a-sidd/SOCProbe-Enterprise/commit/91adb60d01a2e42e3f130b246aaafb8443fd2aaf)

The commit history is retained because it documents the project's development from early prototypes through the modular v4.2.1 architecture. Historical drafts are not kept in the current tree.

## Academic project team

Sheridan College Cybersecurity Capstone, Group 23:

- Ahsan Siddiq
- Syed Ahmed
- Vaqas Mirza

Capstone advisor: Syed Tanbeer

## License

No open-source license has been granted in this repository. The source is publicly viewable for academic review, but reuse, modification, and redistribution require permission from the project owners unless a license is added later.

## Microsoft Graph references

- [List users](https://learn.microsoft.com/graph/api/user-list?view=graph-rest-1.0)
- [List directory roles](https://learn.microsoft.com/graph/api/directoryrole-list?view=graph-rest-1.0)
- [List directory role members](https://learn.microsoft.com/graph/api/directoryrole-list-members?view=graph-rest-1.0)
- [List MFA registration details](https://learn.microsoft.com/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-1.0)
- [List Conditional Access policies](https://learn.microsoft.com/graph/api/conditionalaccessroot-list-policies?view=graph-rest-1.0)
