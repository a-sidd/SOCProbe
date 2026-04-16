from __future__ import annotations

from collections import defaultdict
import re

from ldap3 import SUBTREE


def _first_value(values, default=""):
    if values is None:
        return default
    if isinstance(values, (list, tuple)):
        return values[0] if values else default
    return values


def _slugify(value: str) -> str:
    lowered = re.sub(r"[^a-zA-Z0-9]+", "_", value.strip().lower()).strip("_")
    return lowered or "company"


def _extract_company_token(name: str) -> str | None:
    if not name:
        return None

    for separator in ("_", "-", " "):
        if separator in name:
            token = name.split(separator, 1)[0].strip()
            if len(token) >= 3:
                return token
    return None


def discover_companies_in_ad(conn, config: dict) -> list[dict]:
    base_dn = config["domain"]["base_dn"]
    conn.search(
        search_base=base_dn,
        search_filter="(objectClass=organizationalUnit)",
        search_scope=SUBTREE,
        attributes=["ou", "name"],
    )

    prefix_examples = defaultdict(list)
    for entry in conn.entries:
        attrs = entry.entry_attributes_as_dict
        raw_name = str(_first_value(attrs.get("name"), _first_value(attrs.get("ou"), "")))
        token = _extract_company_token(raw_name)
        if not token:
            continue
        if "_" not in raw_name and "-" not in raw_name:
            continue
        prefix_examples[token].append(raw_name)

    discovered = []
    for token, examples in sorted(prefix_examples.items(), key=lambda item: item[0].lower()):
        if len(examples) < 2:
            continue
        discovered.append(
            {
                "name": token,
                "slug": _slugify(token),
                "industry": "Discovered from Active Directory",
                "environment": "Live AD-derived company context",
                "domain_overrides": {},
                "profile": {
                    "summary": f"Derived from AD OU naming patterns such as '{examples[0]}'.",
                    "departments": sorted(examples),
                },
            }
        )

    if discovered:
        return discovered

    fqdn = config.get("domain", {}).get("fqdn", "local-domain")
    return [
        {
            "name": fqdn,
            "slug": _slugify(fqdn),
            "industry": "Unspecified",
            "environment": "Fallback AD domain context",
            "domain_overrides": {},
            "profile": {"summary": f"No company-like AD naming pattern was found; using domain {fqdn}."},
        }
    ]


def fetch_company_directory(conn, config: dict) -> dict:
    base_dn = config["domain"]["base_dn"]
    conn.search(
        search_base=base_dn,
        search_filter="(&(objectClass=user)(objectCategory=person))",
        search_scope=SUBTREE,
        attributes=[
            "cn",
            "sAMAccountName",
            "department",
            "title",
            "mail",
            "userAccountControl",
            "distinguishedName",
        ],
    )

    departments = defaultdict(list)
    users = []

    for entry in conn.entries:
        attrs = entry.entry_attributes_as_dict
        name = str(_first_value(attrs.get("cn"), "Unknown"))
        username = str(_first_value(attrs.get("sAMAccountName"), "Unknown"))
        department = str(_first_value(attrs.get("department"), "Unassigned") or "Unassigned")
        title = str(_first_value(attrs.get("title"), ""))
        email = str(_first_value(attrs.get("mail"), ""))
        distinguished_name = str(_first_value(attrs.get("distinguishedName"), ""))
        user_account_control = int(_first_value(attrs.get("userAccountControl"), 512))
        enabled = not bool(user_account_control & 2)

        user_record = {
            "name": name,
            "username": username,
            "department": department,
            "title": title,
            "email": email,
            "enabled": enabled,
            "distinguished_name": distinguished_name,
        }

        users.append(user_record)
        departments[department].append(user_record)

    sorted_departments = []
    for department_name, department_users in sorted(departments.items(), key=lambda item: item[0].lower()):
        sorted_departments.append(
            {
                "name": department_name,
                "user_count": len(department_users),
                "users": sorted(department_users, key=lambda item: item["name"].lower()),
            }
        )

    return {
        "user_count": len(users),
        "department_count": len(sorted_departments),
        "departments": sorted_departments,
        "users": sorted(users, key=lambda item: item["name"].lower()),
    }
