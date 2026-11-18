"""Resolve one Defender endpoint before requesting full isolation."""
BASE = "https://api.securitycenter.microsoft.com"

def resolve_machine(session, name):
    # OData strings escape embedded apostrophes by doubling them.
    value = name.replace("'", "''")
    predicate = f"computerDnsName eq '{value}'"
    if "." not in name:
        predicate += f" or startswith(computerDnsName,'{value}.')"
    response = session.get(f"{BASE}/api/machines", params={"$filter": predicate}, timeout=30)
    response.raise_for_status()
    page = response.json()
    hosts = page["value"]
    # A second page means the name is ambiguous even if this page contains one device.
    if len(hosts) != 1 or page.get("@odata.nextLink"):
        raise ValueError("Expected exactly one matching Defender device. Check the full DNS name.")
    host = hosts[0]
    dns = host["computerDnsName"].casefold()
    if name.casefold() not in (dns, dns.split(".")[0]):
        raise ValueError("Returned device name differs from search target")
    return host

def isolate(session, machine_id):
    from urllib.parse import quote
    response = session.post(f"{BASE}/api/machines/{quote(machine_id, safe='')}/isolate",
                            json={"Comment": "Analyst-confirmed SOC hunt", "IsolationType": "Full"},
                            timeout=30)
    response.raise_for_status()
    if response.status_code not in (200, 201, 202):
        raise ValueError(f"Unexpected isolation response: HTTP {response.status_code}")
    return response.json()["id"]
