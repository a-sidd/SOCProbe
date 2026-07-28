
from collectors.windows_local import run_ps, parse_bool

def ad_module_available():
    out, err, rc = run_ps("(Get-Command Get-ADUser -ErrorAction SilentlyContinue) -ne $null")
    return parse_bool(out)

def require_ad():
    if not ad_module_available():
        return False, "Active Directory PowerShell module is not available. Install RSAT AD tools or run on a domain controller."
    return True, ""

def check_domain_admins(thresholds=None):
    thresholds = thresholds or {}
    ok, msg = require_ad()
    if not ok:
        return False, msg
    out, err, rc = run_ps("Get-ADGroupMember 'Domain Admins' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SamAccountName")
    members = [x.strip() for x in out.splitlines() if x.strip()]
    maximum = int(thresholds.get('maximum_domain_admins', 3))
    return len(members) <= maximum, f"Domain Admin members found: {len(members)}. Members: {', '.join(members[:15]) if members else 'None listed'}."

def check_enterprise_admins(thresholds=None):
    thresholds = thresholds or {}
    ok, msg = require_ad()
    if not ok:
        return False, msg
    out, err, rc = run_ps("Get-ADGroupMember 'Enterprise Admins' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SamAccountName")
    members = [x.strip() for x in out.splitlines() if x.strip()]
    maximum = int(thresholds.get('maximum_enterprise_admins', 2))
    return len(members) <= maximum, f"Enterprise Admin members found: {len(members)}. Members: {', '.join(members[:15]) if members else 'None listed'}."

def check_stale_ad_users(thresholds=None):
    thresholds = thresholds or {}
    ok, msg = require_ad()
    if not ok:
        return False, msg
    out, err, rc = run_ps("""
    $days = "$"
    Get-ADUser -Filter * -Properties LastLogonDate,Enabled |
    Where-Object {$_.Enabled -eq $true -and ($_.LastLogonDate -eq $null -or $_.LastLogonDate -lt $cutoff)} |
    Select-Object -ExpandProperty SamAccountName
    """, timeout=30)
    users = [x.strip() for x in out.splitlines() if x.strip()]
    maximum = int(thresholds.get("maximum_stale_users", 0))
    return len(users) <= maximum, f"Enabled stale/never logged in AD users: {len(users)}. Examples: {', '.join(users[:15]) if users else 'None detected'}."

def check_disabled_privileged_users(thresholds=None):
    thresholds = thresholds or {}
    ok, msg = require_ad()
    if not ok:
        return False, msg
    out, err, rc = run_ps("""
    $privGroups=@("Domain Admins","Enterprise Admins","Schema Admins","Administrators","Backup Operators","Account Operators","Server Operators")
    $found=@()
    foreach($group in $privGroups){
      try{
        Get-ADGroupMember $group -Recursive -ErrorAction SilentlyContinue |
        Where-Object {$_.objectClass -eq "user"} |
        ForEach-Object {
          $u=Get-ADUser $_.SamAccountName -Properties Enabled -ErrorAction SilentlyContinue
          if($u.Enabled -eq $false){ $found += "$($u.SamAccountName) in $group" }
        }
      }catch{}
    }
    $found | Sort-Object -Unique
    """, timeout=30)
    users = [x.strip() for x in out.splitlines() if x.strip()]
    return len(users) == 0, f"Disabled users still in privileged groups: {len(users)}. Examples: {', '.join(users[:15]) if users else 'None detected'}."

def check_password_never_expires(thresholds=None):
    thresholds = thresholds or {}
    ok, msg = require_ad()
    if not ok:
        return False, msg
    out, err, rc = run_ps("""
    Get-ADUser -Filter * -Properties PasswordNeverExpires,Enabled |
    Where-Object {$_.Enabled -eq $true -and $_.PasswordNeverExpires -eq $true} |
    Select-Object -ExpandProperty SamAccountName
    """, timeout=30)
    users = [x.strip() for x in out.splitlines() if x.strip()]
    maximum = int(thresholds.get('maximum_password_never_expires', 3))
    return len(users) <= maximum, f"Enabled users with PasswordNeverExpires: {len(users)}. Examples: {', '.join(users[:15]) if users else 'None detected'}."

def check_spn_accounts(thresholds=None):
    thresholds = thresholds or {}
    ok, msg = require_ad()
    if not ok:
        return False, msg
    out, err, rc = run_ps("""
    Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName,Enabled |
    Where-Object {$_.Enabled -eq $true} |
    Select-Object -ExpandProperty SamAccountName
    """, timeout=30)
    accounts = [x.strip() for x in out.splitlines() if x.strip()]
    maximum = int(thresholds.get('maximum_spn_accounts', 5))
    return len(accounts) <= maximum, f"Enabled AD user accounts with SPNs: {len(accounts)}. Examples: {', '.join(accounts[:15]) if accounts else 'None detected'}."

def check_domain_controllers(thresholds=None):
    thresholds = thresholds or {}
    ok, msg = require_ad()
    if not ok:
        return False, msg
    out, err, rc = run_ps("Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName", timeout=30)
    dcs = [x.strip() for x in out.splitlines() if x.strip()]
    return len(dcs) >= 1, f"Domain controllers discovered: {len(dcs)}. DCs: {', '.join(dcs[:10]) if dcs else 'None detected'}."

def check_fsmo_roles(thresholds=None):
    thresholds = thresholds or {}
    ok, msg = require_ad()
    if not ok:
        return False, msg
    out, err, rc = run_ps("""
    $domain = Get-ADDomain
    $forest = Get-ADForest
    [PSCustomObject]@{
      PDCEmulator=$domain.PDCEmulator
      RIDMaster=$domain.RIDMaster
      InfrastructureMaster=$domain.InfrastructureMaster
      SchemaMaster=$forest.SchemaMaster
      DomainNamingMaster=$forest.DomainNamingMaster
    } | Format-List | Out-String
    """, timeout=30)
    return bool(out.strip()) and "PDCEmulator" in out, f"FSMO role evidence collected: {out.strip() if out.strip() else 'No FSMO evidence returned'}."
