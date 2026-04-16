from datetime import datetime, timedelta, timezone

from ldap3 import SUBTREE


def _to_utc(value):
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(value):
    return value.isoformat() if isinstance(value, datetime) else None


def check_stale_accounts(conn, config):
    base_dn = config["domain"]["base_dn"]
    threshold_days = int(config["thresholds"]["stale_account_days"])
    cutoff = datetime.now(timezone.utc) - timedelta(days=threshold_days)

    conn.search(
        search_base=base_dn,
        search_filter="(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        search_scope=SUBTREE,
        attributes=["cn", "sAMAccountName", "lastLogonTimestamp", "whenCreated"],
    )

    stale_accounts = []
    never_logged_in = []

    for entry in conn.entries:
        attributes = entry.entry_attributes_as_dict
        name = str(attributes.get("cn", ["Unknown"])[0])
        sam = str(attributes.get("sAMAccountName", ["Unknown"])[0])

        last_logon = _to_utc(getattr(entry, "lastLogonTimestamp", None).value if "lastLogonTimestamp" in entry else None)
        when_created = _to_utc(getattr(entry, "whenCreated", None).value if "whenCreated" in entry else None)

        if last_logon is None:
            if when_created and when_created < cutoff:
                never_logged_in.append(
                    {
                        "name": name,
                        "sam": sam,
                        "when_created": _iso(when_created),
                    }
                )
            continue

        if last_logon < cutoff:
            stale_accounts.append(
                {
                    "name": name,
                    "sam": sam,
                    "last_logon": _iso(last_logon),
                }
            )

    total_stale = len(stale_accounts) + len(never_logged_in)
    passed = total_stale == 0
    finding = "PASS - No stale enabled user accounts were detected."
    if not passed:
        finding = f"FAIL - {total_stale} stale or never-used enabled account(s) exceeded the {threshold_days}-day threshold."

    return {
        "passed": passed,
        "stale_count": len(stale_accounts),
        "never_logged_in_count": len(never_logged_in),
        "stale_accounts": stale_accounts,
        "never_logged_in": never_logged_in,
        "threshold_days": threshold_days,
        "finding": finding,
    }
