
import subprocess
import json
import os
import re

def run_ps(command, timeout=20):
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except Exception as e:
        return "", str(e), 1

def parse_bool(value):
    return str(value).strip().lower() in ["true", "1", "yes"]

def get_system_context():
    out, err, rc = run_ps("""
    $cs = Get-CimInstance Win32_ComputerSystem
    [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        Domain = $cs.Domain
        PartOfDomain = $cs.PartOfDomain
        DomainRole = $cs.DomainRole
        Username = $env:USERNAME
    } | ConvertTo-Json -Compress
    """)
    try:
        return json.loads(out)
    except Exception:
        return {
            "ComputerName": os.environ.get("COMPUTERNAME", "Unknown"),
            "Domain": "Unknown",
            "PartOfDomain": False,
            "DomainRole": "Unknown",
            "Username": os.environ.get("USERNAME", "Unknown")
        }

def check_windows_firewall(thresholds=None):
    thresholds = thresholds or {}
    out, err, rc = run_ps("Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress")
    disabled = out.lower().count('"enabled":false')
    enabled = out.lower().count('"enabled":true')
    passed = enabled > 0 and disabled == 0
    return passed, f"Firewall profiles enabled: {enabled}. Disabled profiles: {disabled}."

def check_windows_defender(thresholds=None):
    thresholds = thresholds or {}
    out, err, rc = run_ps("(Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled")
    value = out.strip()
    if value.lower() in ["true", "false"]:
        return value.lower() == "true", f"Defender RealTimeProtectionEnabled: {value}."
    return False, "Microsoft Defender status could not be collected. Defender may be unavailable or managed by another product."

def check_security_log_access(thresholds=None):
    thresholds = thresholds or {}
    out, err, rc = run_ps("(Get-WinEvent -LogName Security -MaxEvents 5 -ErrorAction SilentlyContinue).Count")
    try:
        count = int(out.strip())
    except Exception:
        count = 0
    return count > 0, f"Recent Security log events readable: {count}."

def check_security_log_retention(thresholds=None):
    thresholds = thresholds or {}
    out, err, rc = run_ps("(Get-WinEvent -ListLog Security).MaximumSizeInBytes")
    try:
        max_size = int(out.strip())
    except Exception:
        max_size = 0
    mb = round(max_size / (1024 * 1024), 1)
    minimum = float(thresholds.get('minimum_log_size_mb', 64))
    return mb >= minimum, f"Security log maximum size: {mb} MB. Profile expects at least {minimum} MB."

def check_audit_policy(thresholds=None):
    thresholds = thresholds or {}
    out, err, rc = run_ps("auditpol /get /category:*")
    required_terms = ["Logon", "Credential Validation", "User Account Management", "Security Group Management"]
    missing = [term for term in required_terms if term not in out]
    return len(missing) == 0, f"Audit policy checked. Missing expected categories: {', '.join(missing) if missing else 'None'}."

def check_critical_event_coverage(thresholds=None):
    thresholds = thresholds or {}
    required_ids = [4624, 4625, 4648, 4720, 4728, 4776]
    missing = []
    for eid in required_ids:
        out, err, rc = run_ps(f"(Get-WinEvent -FilterHashtable @{{LogName='Security'; ID={eid}}} -MaxEvents 50 -ErrorAction SilentlyContinue).Count")
        try:
            count = int(out.strip())
        except Exception:
            count = 0
        if count == 0:
            missing.append(eid)
    return len(missing) == 0, f"Required event IDs: {required_ids}. Missing/no recent evidence: {missing if missing else 'None'}."

def check_password_policy(thresholds=None):
    thresholds = thresholds or {}
    out, err, rc = run_ps("net accounts")
    min_length = 0
    for line in out.splitlines():
        if "Minimum password length" in line:
            nums = re.findall(r"\\d+", line)
            if nums:
                min_length = int(nums[-1])
    minimum = int(thresholds.get('minimum_password_length', 8))
    return min_length >= minimum, f"Minimum password length: {min_length}. Profile expects {minimum} or more."

def check_account_lockout(thresholds=None):
    thresholds = thresholds or {}
    out, err, rc = run_ps("net accounts")
    threshold = 0
    for line in out.splitlines():
        if "Lockout threshold" in line:
            nums = re.findall(r"\\d+", line)
            if nums:
                threshold = int(nums[-1])
    maximum = int(thresholds.get('maximum_lockout_threshold', 10))
    must_be_enabled = bool(thresholds.get('must_be_enabled', True))
    passed = (threshold > 0 if must_be_enabled else True) and threshold <= maximum
    return passed, f"Account lockout threshold: {threshold}. Profile maximum: {maximum}; must be enabled: {must_be_enabled}."

def check_rdp_exposure(thresholds=None):
    thresholds = thresholds or {}
    out, err, rc = run_ps("(Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections")
    try:
        value = int(out.strip())
    except Exception:
        value = 1
    passed = value == 1
    return passed, f"RDP fDenyTSConnections value: {value}. 1 means RDP is disabled."

def check_windows_update(thresholds=None):
    thresholds = thresholds or {}
    out, err, rc = run_ps("(Get-Service wuauserv -ErrorAction SilentlyContinue).StartType")
    value = out.strip()
    passed = value.lower() != "disabled" and value != ""
    return passed, f"Windows Update service start type: {value if value else 'Unavailable'}."

def check_wdigest(thresholds=None):
    thresholds = thresholds or {}
    out, err, rc = run_ps("(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential")
    try:
        value = int(out.strip())
    except Exception:
        value = 0
    return value != 1, f"WDigest UseLogonCredential value: {value}. SAF expects it not to be enabled."

def check_local_admins(thresholds=None):
    thresholds = thresholds or {}
    out, err, rc = run_ps("net localgroup Administrators")
    lines = [x.strip() for x in out.splitlines() if x.strip()]
    members = []
    capture = False
    for line in lines:
        if "---" in line:
            capture = True
            continue
        if "command completed" in line.lower():
            capture = False
            continue
        if capture:
            members.append(line)
    maximum = int(thresholds.get('maximum_local_admins', 5))
    passed = len(members) <= maximum
    return passed, f"Local Administrators member count: {len(members)}. Profile maximum: {maximum}. Members: {', '.join(members[:10]) if members else 'None listed'}."

def check_domain_join(thresholds=None):
    thresholds = thresholds or {}
    ctx = get_system_context()
    part = bool(ctx.get("PartOfDomain"))
    return part, f"Part of domain: {part}. Domain/Workgroup: {ctx.get('Domain')}."

def check_ad_module(thresholds=None):
    thresholds = thresholds or {}
    out, err, rc = run_ps("(Get-Command Get-ADUser -ErrorAction SilentlyContinue) -ne $null")
    ok = parse_bool(out)
    return ok, f"Active Directory PowerShell module available: {ok}."

COLLECTORS = {
    "windows_firewall": check_windows_firewall,
    "windows_defender": check_windows_defender,
    "security_log_access": check_security_log_access,
    "security_log_retention": check_security_log_retention,
    "audit_policy": check_audit_policy,
    "critical_event_coverage": check_critical_event_coverage,
    "password_policy": check_password_policy,
    "account_lockout": check_account_lockout,
    "rdp_exposure": check_rdp_exposure,
    "windows_update": check_windows_update,
    "wdigest": check_wdigest,
    "local_admins": check_local_admins,
    "domain_join": check_domain_join,
    "ad_module": check_ad_module,
}
