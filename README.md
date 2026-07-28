# SOCProbe Enterprise v4.2

SOCProbe Enterprise v4.2 is a database-backed security assessment platform using the original SOCProbe Security Assessment Framework.

## Main changes

- SQLite methodology database
- Multiple assessment profiles
- Editable control weights
- Editable risk ratings
- Editable thresholds
- Editable grade bands
- Real Windows, Active Directory, and Microsoft Entra collectors
- Progress bar and live assessment status
- HTML and JSON reports
- Assessment history stored in SQLite
- Robust paths independent of the launch directory

## Run

```powershell
pip install -r requirements.txt
python main.py
```

## Profile Manager

Click **Profile Manager** to:

- create profiles
- activate profiles
- edit control weights
- edit control risks
- enable or disable controls
- edit threshold JSON
- edit grade bands

Settings are stored in:

```text
socprobe.db
```

No methodology JSON files are required.

## Entra configuration

Click **Entra Config** and enter the app registration credentials.

## Real assessment

Click:

```text
Run Real Windows/AD/Entra Assessment
```

## Security

Do not commit `entra_config.json` or `socprobe.db` if they contain company-specific information.


## Control Library Manager

Click **Control Library** to:

- add a custom control
- edit a custom control
- duplicate any control
- enable or disable controls
- delete custom controls

Built-in controls cannot be deleted or have their collector definitions changed. Their weight, risk, thresholds, and profile inclusion remain configurable.

### Approved collector templates

- `windows_service`
- `registry_value`
- `event_id`
- `local_group_member_count`
- `powershell_boolean`

The PowerShell boolean option blocks common modification commands. It is intended only for simple read-only expressions.

### Custom control example

```json
{
  "service_name": "Spooler",
  "expected_status": "Stopped"
}
```

Choose collector type:

```text
windows_service
```

The custom control is automatically added to all existing profiles and can then be assigned different weights, risks, thresholds, or enabled states in each profile.


## v4.2 Interface improvements

- Responsive equal-width score cards
- Readable dashboard titles and labels
- Four-step assessment workflow
- Improved gauge and domain score panels
- Separate failed and not-assessed counts
- Responsive results table with vertical and horizontal scrollbars
- Cleaner executive summary
- Consistent export and configuration button labels
- Better spacing for 1440p and 1080p displays
