from ldap3 import SUBTREE
from ldap3.utils.conv import escape_filter_chars


def _extract_cn(distinguished_name: str) -> str:
    return distinguished_name.split(",", 1)[0].replace("CN=", "")


def check_privileged_groups(conn, config):
    base_dn = config["domain"]["base_dn"]
    privileged_groups = config["privileged_groups"]
    max_allowed = int(config["thresholds"]["max_domain_admins"])

    results = {}
    all_privileged_members = set()
    missing_groups = []

    for group in privileged_groups:
        conn.search(
            search_base=base_dn,
            search_filter=f"(&(objectClass=group)(cn={escape_filter_chars(group)}))",
            search_scope=SUBTREE,
            attributes=["member", "cn"],
        )

        if conn.entries:
            entry = conn.entries[0]
            members = entry.member.values if entry.member else []
            member_names = sorted({_extract_cn(member_dn) for member_dn in members})
            all_privileged_members.update(member_names)
            results[group] = {
                "group_found": True,
                "member_count": len(member_names),
                "members": member_names,
            }
        else:
            missing_groups.append(group)
            results[group] = {"group_found": False, "member_count": 0, "members": []}

    domain_admin_count = results.get("Domain Admins", {}).get("member_count", 0)
    issues = []
    if missing_groups:
        issues.append(f"missing groups: {', '.join(missing_groups)}")
    if domain_admin_count > max_allowed:
        issues.append(f"Domain Admins has {domain_admin_count} members (max allowed {max_allowed})")

    passed = not issues
    finding = "PASS - Privileged group membership is within the configured threshold."
    if issues:
        finding = "FAIL - " + "; ".join(issues)

    return {
        "passed": passed,
        "domain_admin_count": domain_admin_count,
        "max_allowed": max_allowed,
        "missing_groups": missing_groups,
        "groups": results,
        "total_privileged_members": len(all_privileged_members),
        "finding": finding,
    }
