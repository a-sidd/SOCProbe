from __future__ import annotations

from ldap3 import ALL, Connection, NTLM, SIMPLE, Server
from ldap3.core.exceptions import LDAPBindError, LDAPException


def _normalize_ntlm_username(config: dict) -> str:
    domain_cfg = config["domain"]
    username = domain_cfg["username"]

    if "\\" in username:
        return username

    sam_account_name = username.split("@", 1)[0]
    fqdn = domain_cfg.get("fqdn") or ""
    netbios_domain = fqdn.split(".", 1)[0].upper() if fqdn else ""

    return f"{netbios_domain}\\{sam_account_name}" if netbios_domain else username


def get_ad_connection_details(config: dict) -> dict:
    domain_cfg = config["domain"]
    return {
        "server": domain_cfg["server"],
        "port": domain_cfg.get("port", 389),
        "base_dn": domain_cfg.get("base_dn", ""),
        "fqdn": domain_cfg.get("fqdn", ""),
        "username": domain_cfg.get("username", ""),
        "ntlm_username": _normalize_ntlm_username(config),
    }


def connect_to_ad(config: dict) -> Connection:
    domain_cfg = config["domain"]
    original_username = domain_cfg["username"]
    ntlm_username = _normalize_ntlm_username(config)

    server = Server(
        domain_cfg["server"],
        port=domain_cfg.get("port", 389),
        get_info=ALL,
    )

    try:
        conn = Connection(
            server,
            user=ntlm_username,
            password=domain_cfg["password"],
            authentication=NTLM,
            auto_bind=True,
            raise_exceptions=True,
        )
        return conn
    except (LDAPBindError, LDAPException, ValueError, ModuleNotFoundError) as ntlm_exc:
        try:
            conn = Connection(
                server,
                user=original_username,
                password=domain_cfg["password"],
                authentication=SIMPLE,
                auto_bind=True,
                raise_exceptions=True,
            )
            return conn
        except (LDAPBindError, LDAPException) as simple_exc:
            raise RuntimeError(
                "Active Directory bind failed for both NTLM and SIMPLE authentication. "
                f"NTLM user '{ntlm_username}' error: {ntlm_exc}. "
                f"SIMPLE user '{original_username}' error: {simple_exc}"
            ) from simple_exc


def test_ad_connection(config: dict) -> dict:
    conn = None
    details = get_ad_connection_details(config)
    try:
        conn = connect_to_ad(config)
        return {
            "connected": True,
            "details": details,
            "message": (
                f"Connected to {details['server']}:{details['port']} using "
                f"{details['ntlm_username']} with base DN {details['base_dn']}"
            ),
        }
    except Exception as exc:
        return {
            "connected": False,
            "details": details,
            "message": str(exc),
        }
    finally:
        if conn is not None and conn.bound:
            conn.unbind()
