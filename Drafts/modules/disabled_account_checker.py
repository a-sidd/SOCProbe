from ldap3 import SUBTREE


def check_disabled_accounts(conn, config):
    base_dn = config["domain"]["base_dn"]
    privileged_groups = set(config["privileged_groups"])

    conn.search(
        search_base=base_dn,
        search_filter="(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=2))",
        search_scope=SUBTREE,
        attributes=["cn", "sAMAccountName", "memberOf"],
    )

    disabled_in_privileged = []

    for entry in conn.entries:
        attributes = entry.entry_attributes_as_dict
        name = str(attributes.get("cn", ["Unknown"])[0])
        sam = str(attributes.get("sAMAccountName", ["Unknown"])[0])
        groups = attributes.get("memberOf", [])

        for group_dn in groups:
            group_cn = group_dn.split(",", 1)[0].replace("CN=", "")
            if group_cn in privileged_groups:
                disabled_in_privileged.append(
                    {
                        "name": name,
                        "sam": sam,
                        "privileged_group": group_cn,
                    }
                )
                break

    passed = len(disabled_in_privileged) == 0
    finding = "PASS - No disabled accounts remain in privileged groups."
    if not passed:
        finding = f"FAIL - {len(disabled_in_privileged)} disabled account(s) were found in privileged groups."

    return {
        "passed": passed,
        "count": len(disabled_in_privileged),
        "accounts": disabled_in_privileged,
        "finding": finding,
    }
