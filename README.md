# SOCProbe Enterprise v4.2.1

SOCProbe Enterprise is a desktop security assessment console for auditing **local Windows security**, **Active Directory**, and **Microsoft Entra ID** against the SOCProbe Security Assessment Framework (SAF) - a 30-control methodology spanning four domains, with database-backed scoring, editable methodology, and HTML/JSON reporting.

## Features

- **30 built-in SAF controls** across four domains: Local Windows Security, Active Directory Readiness, Active Directory Security, and Microsoft Entra Security.
- **Environment-aware assessment** - controls automatically mark themselves `NOT APPLICABLE` and are excluded from scoring when they don't apply (e.g. AD controls on a non-domain-joined host, Entra controls with no Entra config present).
- **SQLite-backed methodology** - no methodology JSON files required. Control weights, risk ratings, thresholds, grade bands, and enable/disable state are all editable and stored in `socprobe.db`.
- **Multiple assessment profiles** with independent methodology configuration.
- **Custom controls** - add your own checks on top of the built-in library using approved collector templates (`windows_service`, `registry_value`, `event_id`, `local_group_member_count`, `powershell_boolean`).
- **Live assessment console** with progress bar and real-time status per control.
- **HTML and JSON reports**, plus full assessment history stored in SQLite.
- **Responsive Tkinter UI** tuned for 1080p and 1440p displays.

## Project layout

```text
SOCProbe.py              Application entry point (Tkinter UI)
assessment/engine.py     Assessment orchestration (real + demo runs)
collectors/              Data collectors: windows_local, active_directory, entra_id, custom_controls
framework/saf_controls.py  The 30 built-in SAF control definitions
database/repository.py   SQLite schema, profiles, control config, assessment history
reports/report_generator.py  HTML/JSON report generation
ui/                       Profile Manager, Control Library, Entra Config, Methodology Settings dialogs
```

## Running from source

Requires Python 3.10+ on Windows (some collectors shell out to PowerShell and are Windows-specific; Active Directory checks additionally require a domain-joined host with the AD PowerShell module).

```powershell
pip install -r requirements.txt
python SOCProbe.py
```

## Running the packaged executable

A standalone `SOCProbe.exe` build (via PyInstaller) requires no Python install - see [Releases](../../releases) for the latest build. Place it in its own folder; it creates `socprobe.db` and its report files alongside itself on first run.

To build it yourself:

```powershell
pip install pyinstaller
pyinstaller --onefile --windowed --name SOCProbe --collect-all msal SOCProbe.py
```

## Configuration

### Entra ID

Copy `entra_config.example.json` to `entra_config.json` and fill in your app registration's tenant ID, client ID, and client secret - or use the **Entra Config** button in the app. Credentials can also be supplied via environment variables (checked first).

### Profile Manager

Click **Profile Manager** to:

- Create and activate assessment profiles
- Edit control weights, risk ratings, and thresholds
- Edit grade bands
- Enable or disable individual controls per profile

### Control Library

Click **Control Library** to add, edit, duplicate, enable/disable, or delete custom controls. Built-in controls can't be deleted or have their collector definitions changed, but their weight, risk, thresholds, and profile inclusion remain configurable.

Example custom control (using the `windows_service` collector):

```json
{
  "service_name": "Spooler",
  "expected_status": "Stopped"
}
```

The PowerShell-boolean collector template blocks common modification commands and is intended only for simple read-only expressions.

## Running an assessment

Click **Run Real Windows/AD/Entra Assessment** to collect live data, or run a demo assessment to preview the UI without a live environment. Results are broken out per domain with pass/fail/not-assessed counts, an executive summary, and exportable HTML/JSON reports.

## Security notes

- `entra_config.json` and `socprobe.db` are gitignored - do not commit them, as they may contain company-specific credentials and assessment data.
- The PowerShell-boolean custom control type is restricted to read-only expressions by design; do not attempt to bypass this for write operations.
