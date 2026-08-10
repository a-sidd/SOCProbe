
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

GRAPH_ROOT = "https://graph.microsoft.com/v1.0"
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).resolve().parent
else:
    BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_FILE = BASE_DIR / "entra_config.json"


class EntraAssessmentError(RuntimeError):
    pass


def _load_dependencies():
    try:
        import msal
        import requests
        return msal, requests
    except ImportError as exc:
        raise EntraAssessmentError(
            "Missing Python packages. Run: pip install -r requirements.txt"
        ) from exc


def load_entra_config() -> Optional[Dict[str, str]]:
    """Load credentials from environment variables first, then entra_config.json."""
    config = {
        "tenant_id": os.getenv("SOCPROBE_ENTRA_TENANT_ID", "").strip(),
        "client_id": os.getenv("SOCPROBE_ENTRA_CLIENT_ID", "").strip(),
        "client_secret": os.getenv("SOCPROBE_ENTRA_CLIENT_SECRET", "").strip(),
    }

    if all(config.values()):
        return config

    if not CONFIG_FILE.exists():
        return None

    try:
        saved = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EntraAssessmentError(f"Unable to read {CONFIG_FILE}: {exc}") from exc

    config = {
        "tenant_id": str(saved.get("tenant_id", "")).strip(),
        "client_id": str(saved.get("client_id", "")).strip(),
        "client_secret": str(saved.get("client_secret", "")).strip(),
    }

    if not all(config.values()):
        raise EntraAssessmentError(
            "entra_config.json exists but tenant_id, client_id, or client_secret is missing."
        )
    return config


class GraphClient:
    def __init__(self):
        self.msal, self.requests = _load_dependencies()
        self.config = load_entra_config()
        if not self.config:
            raise EntraAssessmentError(
                "Entra is not configured. Copy entra_config.example.json to entra_config.json and enter the app registration values."
            )
        self._token = None

    def acquire_token(self) -> str:
        if self._token:
            return self._token

        try:
            app = self.msal.ConfidentialClientApplication(
                client_id=self.config["client_id"],
                authority=f"https://login.microsoftonline.com/{self.config['tenant_id']}",
                client_credential=self.config["client_secret"],
            )
            result = app.acquire_token_for_client(
                scopes=["https://graph.microsoft.com/.default"]
            )
        except ValueError as exc:
            raise EntraAssessmentError(
                f"Microsoft identity authentication failed: {exc}"
            ) from exc
        except self.requests.exceptions.RequestException as exc:
            raise EntraAssessmentError(
                f"Unable to reach Microsoft identity endpoints: {exc}"
            ) from exc

        token = result.get("access_token")
        if not token:
            description = result.get("error_description") or result.get("error") or "Unknown token error"
            raise EntraAssessmentError(f"Microsoft identity authentication failed: {description}")
        self._token = token
        return token

    def get(self, endpoint: str) -> Dict[str, Any]:
        token = self.acquire_token()
        url = endpoint if endpoint.startswith("https://") else f"{GRAPH_ROOT}/{endpoint.lstrip('/')}"
        response = self.requests.get(
            url,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=30,
        )
        if response.status_code >= 400:
            try:
                payload = response.json()
                detail = payload.get("error", {}).get("message", response.text)
            except ValueError:
                detail = response.text
            raise EntraAssessmentError(
                f"Microsoft Graph request failed ({response.status_code}): {detail}"
            )
        return response.json()

    def get_all(self, endpoint: str) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        next_url = endpoint
        while next_url:
            payload = self.get(next_url)
            items.extend(payload.get("value", []))
            next_url = payload.get("@odata.nextLink")
        return items


def _not_assessed(message: str) -> Tuple[None, str]:
    return None, message


def _client_or_not_assessed():
    try:
        return GraphClient(), None
    except EntraAssessmentError as exc:
        return None, str(exc)


def check_entra_connection(thresholds=None):
    thresholds = thresholds or {}
    client, error = _client_or_not_assessed()
    if not client:
        return _not_assessed(error)
    try:
        users = client.get("users?$top=1&$select=id")
        visible = len(users.get("value", []))
        return True, f"Microsoft Graph authentication succeeded. Sample user records returned: {visible}."
    except EntraAssessmentError as exc:
        return False, str(exc)


def check_entra_user_inventory(thresholds=None):
    thresholds = thresholds or {}
    client, error = _client_or_not_assessed()
    if not client:
        return _not_assessed(error)
    try:
        users = client.get_all(
            "users?$select=id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime&$top=999"
        )
        return len(users) > 0, f"Cloud users collected: {len(users)}."
    except EntraAssessmentError as exc:
        return False, str(exc)


def check_entra_global_admins(thresholds=None):
    thresholds = thresholds or {}
    client, error = _client_or_not_assessed()
    if not client:
        return _not_assessed(error)
    try:
        roles = client.get_all("directoryRoles?$select=id,displayName")
        global_role = next(
            (role for role in roles if role.get("displayName") == "Global Administrator"),
            None,
        )
        if not global_role:
            return False, "Global Administrator role was not visible in the activated directory roles response."

        members = client.get_all(
            f"directoryRoles/{global_role['id']}/members?$select=id,displayName,userPrincipalName"
        )
        names = [
            member.get("userPrincipalName") or member.get("displayName") or member.get("id")
            for member in members
        ]
        minimum = int(thresholds.get('minimum_global_admins', 1))
        maximum = int(thresholds.get('maximum_global_admins', 5))
        passed = minimum <= len(members) <= maximum
        return passed, (
            f"Global Administrator assignments: {len(members)}. "
            f"Members: {', '.join(names[:15]) if names else 'None visible'}."
        )
    except EntraAssessmentError as exc:
        return False, str(exc)


def check_entra_guest_accounts(thresholds=None):
    thresholds = thresholds or {}
    client, error = _client_or_not_assessed()
    if not client:
        return _not_assessed(error)
    try:
        users = client.get_all(
            "users?$select=id,displayName,userPrincipalName,userType,accountEnabled&$top=999"
        )
        guests = [user for user in users if user.get("userType") == "Guest"]
        ratio = (len(guests) / len(users) * 100) if users else 0
        maximum = float(thresholds.get('maximum_guest_percentage', 10))
        passed = ratio <= maximum
        examples = [
            user.get("userPrincipalName") or user.get("displayName")
            for user in guests[:10]
        ]
        return passed, (
            f"Guest accounts: {len(guests)} of {len(users)} users ({ratio:.1f}%). "
            f"Examples: {', '.join(examples) if examples else 'None'}."
        )
    except EntraAssessmentError as exc:
        return False, str(exc)


def check_entra_disabled_accounts(thresholds=None):
    thresholds = thresholds or {}
    client, error = _client_or_not_assessed()
    if not client:
        return _not_assessed(error)
    try:
        users = client.get_all(
            "users?$select=id,displayName,userPrincipalName,accountEnabled,userType&$top=999"
        )
        disabled = [user for user in users if user.get("accountEnabled") is False]
        ratio = (len(disabled) / len(users) * 100) if users else 0
        maximum = float(thresholds.get('maximum_disabled_percentage', 5))
        passed = ratio <= maximum
        examples = [
            user.get("userPrincipalName") or user.get("displayName")
            for user in disabled[:10]
        ]
        return passed, (
            f"Disabled cloud accounts: {len(disabled)} of {len(users)} users ({ratio:.1f}%). "
            f"Examples: {', '.join(examples) if examples else 'None'}."
        )
    except EntraAssessmentError as exc:
        return False, str(exc)


def check_entra_mfa_coverage(thresholds=None):
    thresholds = thresholds or {}
    client, error = _client_or_not_assessed()
    if not client:
        return _not_assessed(error)
    try:
        registrations = client.get_all(
            "reports/authenticationMethods/userRegistrationDetails"
            "?$select=id,userPrincipalName,userType,isAdmin,isMfaRegistered,isMfaCapable"
            "&$top=999"
        )
        members = [
            item for item in registrations
            if item.get("userType", "member").lower() == "member"
        ]
        registered = [item for item in members if item.get("isMfaRegistered") is True]
        coverage = (len(registered) / len(members) * 100) if members else 0
        admins = [item for item in members if item.get("isAdmin") is True]
        admins_registered = [item for item in admins if item.get("isMfaRegistered") is True]
        admin_coverage = (len(admins_registered) / len(admins) * 100) if admins else 100
        minimum = float(thresholds.get('minimum_mfa_percentage', 90))
        admin_minimum = float(thresholds.get('minimum_admin_mfa_percentage', 100))
        passed = coverage >= minimum and admin_coverage >= admin_minimum
        return passed, (
            f"MFA registration coverage: {len(registered)}/{len(members)} members ({coverage:.1f}%). "
            f"Administrator MFA coverage: {len(admins_registered)}/{len(admins)} ({admin_coverage:.1f}%)."
        )
    except EntraAssessmentError as exc:
        return False, str(exc)


def check_entra_conditional_access(thresholds=None):
    thresholds = thresholds or {}
    client, error = _client_or_not_assessed()
    if not client:
        return _not_assessed(error)
    try:
        policies = client.get_all(
            "identity/conditionalAccess/policies?$select=id,displayName,state"
        )
        enabled = [policy for policy in policies if policy.get("state") == "enabled"]
        report_only = [policy for policy in policies if policy.get("state") == "enabledForReportingButNotEnforced"]
        minimum = int(thresholds.get('minimum_enabled_policies', 1))
        passed = len(enabled) >= minimum
        return passed, (
            f"Conditional Access policies: {len(policies)} total, "
            f"{len(enabled)} enabled, {len(report_only)} report-only."
        )
    except EntraAssessmentError as exc:
        return False, str(exc)


def check_entra_role_visibility(thresholds=None):
    thresholds = thresholds or {}
    client, error = _client_or_not_assessed()
    if not client:
        return _not_assessed(error)
    try:
        roles = client.get_all("directoryRoles?$select=id,displayName")
        privileged_names = {
            "Global Administrator",
            "Privileged Role Administrator",
            "Security Administrator",
            "Conditional Access Administrator",
            "Authentication Administrator",
            "Exchange Administrator",
            "SharePoint Administrator",
        }
        visible = [role for role in roles if role.get("displayName") in privileged_names]
        passed = len(roles) > 0
        names = [role.get("displayName", "Unnamed role") for role in visible]
        return passed, (
            f"Activated directory roles visible: {len(roles)}. "
            f"Selected privileged roles visible: {', '.join(names) if names else 'None from the selected set'}."
        )
    except EntraAssessmentError as exc:
        return False, str(exc)
