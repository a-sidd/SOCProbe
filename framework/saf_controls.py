
SAF_CONTROLS = [
    {
        "id": "SAF-LW-01",
        "domain": "Local Windows Security",
        "name": "Windows Firewall Assessment",
        "objective": "Verify that Windows Firewall profiles are enabled.",
        "collector": "windows_firewall",
        "weight": 10,
        "risk": "High",
        "recommendation": "Enable Windows Firewall for Domain, Private, and Public profiles."
    },
    {
        "id": "SAF-LW-02",
        "domain": "Local Windows Security",
        "name": "Windows Defender Assessment",
        "objective": "Verify that Microsoft Defender real-time protection is enabled.",
        "collector": "windows_defender",
        "weight": 10,
        "risk": "High",
        "recommendation": "Enable Microsoft Defender real-time protection or confirm an approved EDR is installed."
    },
    {
        "id": "SAF-LW-03",
        "domain": "Local Windows Security",
        "name": "Security Log Accessibility",
        "objective": "Verify that Windows Security logs are accessible and contain recent events.",
        "collector": "security_log_access",
        "weight": 10,
        "risk": "High",
        "recommendation": "Ensure Security logs are enabled, accessible, and not being cleared unexpectedly."
    },
    {
        "id": "SAF-LW-04",
        "domain": "Local Windows Security",
        "name": "Security Log Retention",
        "objective": "Verify that Security log size is large enough for assessment and investigation.",
        "collector": "security_log_retention",
        "weight": 8,
        "risk": "Medium",
        "recommendation": "Increase Security log maximum size to at least 64 MB or higher depending on environment size."
    },
    {
        "id": "SAF-LW-05",
        "domain": "Local Windows Security",
        "name": "Audit Policy Assessment",
        "objective": "Verify that key audit categories are enabled.",
        "collector": "audit_policy",
        "weight": 10,
        "risk": "High",
        "recommendation": "Enable logon, account management, credential validation, and security group auditing."
    },
    {
        "id": "SAF-LW-06",
        "domain": "Local Windows Security",
        "name": "Critical Event Coverage",
        "objective": "Verify that important security events exist in the Security log.",
        "collector": "critical_event_coverage",
        "weight": 8,
        "risk": "Medium",
        "recommendation": "Generate or enable collection for important Windows security events used for assessment."
    },
    {
        "id": "SAF-LW-07",
        "domain": "Local Windows Security",
        "name": "Password Policy Assessment",
        "objective": "Verify minimum password length is reasonable.",
        "collector": "password_policy",
        "weight": 8,
        "risk": "High",
        "recommendation": "Set minimum password length to at least 8 characters or higher."
    },
    {
        "id": "SAF-LW-08",
        "domain": "Local Windows Security",
        "name": "Account Lockout Assessment",
        "objective": "Verify account lockout is enabled to reduce brute-force risk.",
        "collector": "account_lockout",
        "weight": 8,
        "risk": "High",
        "recommendation": "Configure account lockout threshold and duration using local or domain policy."
    },
    {
        "id": "SAF-LW-09",
        "domain": "Local Windows Security",
        "name": "Remote Desktop Exposure",
        "objective": "Verify whether RDP is disabled or controlled.",
        "collector": "rdp_exposure",
        "weight": 6,
        "risk": "Medium",
        "recommendation": "Disable RDP if not required or restrict it using firewall, VPN, and administrative controls."
    },
    {
        "id": "SAF-LW-10",
        "domain": "Local Windows Security",
        "name": "Windows Update Readiness",
        "objective": "Verify Windows Update service is not disabled.",
        "collector": "windows_update",
        "weight": 6,
        "risk": "Medium",
        "recommendation": "Enable Windows Update service and confirm patching process is active."
    },
    {
        "id": "SAF-LW-11",
        "domain": "Local Windows Security",
        "name": "Credential Exposure Assessment",
        "objective": "Verify WDigest credential caching is not enabled.",
        "collector": "wdigest",
        "weight": 8,
        "risk": "High",
        "recommendation": "Ensure WDigest UseLogonCredential is disabled."
    },
    {
        "id": "SAF-LW-12",
        "domain": "Local Windows Security",
        "name": "Local Administrator Review",
        "objective": "Review local Administrators group membership.",
        "collector": "local_admins",
        "weight": 8,
        "risk": "High",
        "recommendation": "Limit local Administrators group membership to approved administrators only."
    },

    {
        "id": "SAF-AD-01",
        "domain": "Active Directory Readiness",
        "name": "Domain Join Assessment",
        "objective": "Verify whether the system is joined to a domain.",
        "collector": "domain_join",
        "weight": 6,
        "risk": "Medium",
        "recommendation": "Join the system to the assessment domain if Active Directory assessment is required."
    },
    {
        "id": "SAF-AD-02",
        "domain": "Active Directory Readiness",
        "name": "AD PowerShell Module Assessment",
        "objective": "Verify whether Active Directory PowerShell cmdlets are available.",
        "collector": "ad_module",
        "weight": 6,
        "risk": "Medium",
        "recommendation": "Install RSAT Active Directory tools or run SOCProbe on a domain controller."
    },

    {
        "id": "SAF-AD-03",
        "domain": "Active Directory Security",
        "name": "Domain Admin Review",
        "objective": "Verify that Domain Admin membership is limited and approved.",
        "collector": "domain_admins",
        "weight": 10,
        "risk": "High",
        "recommendation": "Review Domain Admin membership and remove unnecessary privileged accounts."
    },
    {
        "id": "SAF-AD-04",
        "domain": "Active Directory Security",
        "name": "Enterprise Admin Review",
        "objective": "Verify that Enterprise Admin membership is limited and approved.",
        "collector": "enterprise_admins",
        "weight": 10,
        "risk": "High",
        "recommendation": "Review Enterprise Admin membership and remove unnecessary enterprise-level access."
    },
    {
        "id": "SAF-AD-05",
        "domain": "Active Directory Security",
        "name": "Stale AD User Assessment",
        "objective": "Identify enabled Active Directory users that have not logged in recently.",
        "collector": "stale_ad_users",
        "weight": 8,
        "risk": "High",
        "recommendation": "Disable stale AD accounts and confirm ownership before removal."
    },
    {
        "id": "SAF-AD-06",
        "domain": "Active Directory Security",
        "name": "Disabled Privileged Account Assessment",
        "objective": "Ensure disabled users are not still members of privileged groups.",
        "collector": "disabled_privileged_users",
        "weight": 8,
        "risk": "High",
        "recommendation": "Remove disabled accounts from privileged groups immediately."
    },
    {
        "id": "SAF-AD-07",
        "domain": "Active Directory Security",
        "name": "Password Never Expires Assessment",
        "objective": "Identify enabled accounts with passwords set to never expire.",
        "collector": "password_never_expires",
        "weight": 7,
        "risk": "Medium",
        "recommendation": "Review accounts with non-expiring passwords and require exception approval."
    },
    {
        "id": "SAF-AD-08",
        "domain": "Active Directory Security",
        "name": "Service Principal Exposure Assessment",
        "objective": "Identify accounts with Service Principal Names that may increase Kerberos exposure.",
        "collector": "spn_accounts",
        "weight": 8,
        "risk": "High",
        "recommendation": "Review SPN-enabled accounts, apply strong passwords, and restrict service account privileges."
    },
    {
        "id": "SAF-AD-09",
        "domain": "Active Directory Security",
        "name": "Domain Controller Discovery",
        "objective": "Verify that domain controllers can be discovered for assessment.",
        "collector": "domain_controllers",
        "weight": 6,
        "risk": "Medium",
        "recommendation": "Confirm domain controller availability and AD assessment permissions."
    },
    {
        "id": "SAF-AD-10",
        "domain": "Active Directory Security",
        "name": "FSMO Role Visibility",
        "objective": "Verify that FSMO role holders can be identified.",
        "collector": "fsmo_roles",
        "weight": 6,
        "risk": "Medium",
        "recommendation": "Confirm FSMO role visibility and document role ownership."
    },

    {
        "id": "SAF-EN-01",
        "domain": "Microsoft Entra Security",
        "name": "Entra Tenant Connection Assessment",
        "objective": "Verify that SOCProbe can authenticate to Microsoft Graph using read-only application access.",
        "collector": "entra_connection",
        "weight": 5,
        "risk": "Medium",
        "recommendation": "Configure the tenant ID, client ID, and client secret, then grant the required read-only Microsoft Graph permissions."
    },
    {
        "id": "SAF-EN-02",
        "domain": "Microsoft Entra Security",
        "name": "Cloud User Inventory Assessment",
        "objective": "Verify that cloud user inventory can be collected for assessment.",
        "collector": "entra_user_inventory",
        "weight": 5,
        "risk": "Medium",
        "recommendation": "Grant User.Read.All application permission and admin consent."
    },
    {
        "id": "SAF-EN-03",
        "domain": "Microsoft Entra Security",
        "name": "Global Administrator Review",
        "objective": "Assess the number of active Global Administrator assignments.",
        "collector": "entra_global_admins",
        "weight": 10,
        "risk": "High",
        "recommendation": "Limit Global Administrator assignments and use lower-privilege roles where possible."
    },
    {
        "id": "SAF-EN-04",
        "domain": "Microsoft Entra Security",
        "name": "Guest Account Exposure Assessment",
        "objective": "Assess the proportion of guest identities in the tenant.",
        "collector": "entra_guest_accounts",
        "weight": 7,
        "risk": "Medium",
        "recommendation": "Review guest identities regularly and remove guests that no longer require access."
    },
    {
        "id": "SAF-EN-05",
        "domain": "Microsoft Entra Security",
        "name": "Disabled Cloud Account Hygiene",
        "objective": "Identify disabled cloud accounts that require ownership or retention review.",
        "collector": "entra_disabled_accounts",
        "weight": 6,
        "risk": "Medium",
        "recommendation": "Review disabled cloud accounts and remove or document accounts that are no longer required."
    },
    {
        "id": "SAF-EN-06",
        "domain": "Microsoft Entra Security",
        "name": "MFA Registration Coverage",
        "objective": "Assess the percentage of users registered for multi-factor authentication.",
        "collector": "entra_mfa_coverage",
        "weight": 10,
        "risk": "High",
        "recommendation": "Increase MFA registration coverage, prioritizing administrators and high-risk users."
    },
    {
        "id": "SAF-EN-07",
        "domain": "Microsoft Entra Security",
        "name": "Conditional Access Readiness",
        "objective": "Verify that enabled Conditional Access policies are present.",
        "collector": "entra_conditional_access",
        "weight": 9,
        "risk": "High",
        "recommendation": "Create and enable Conditional Access policies for MFA, administrative access, and risky sign-ins."
    },
    {
        "id": "SAF-EN-08",
        "domain": "Microsoft Entra Security",
        "name": "Privileged Role Visibility",
        "objective": "Verify that activated Microsoft Entra directory roles and their members can be assessed.",
        "collector": "entra_role_visibility",
        "weight": 8,
        "risk": "High",
        "recommendation": "Grant RoleManagement.Read.Directory or Directory.Read.All read permission and review privileged role assignments."
    },

]