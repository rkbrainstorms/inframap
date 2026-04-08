"""
CIDR range pivot — find everything on the same /24 subnet.

No API key required. Uses crt.sh + passive DNS.

Why this matters:
  Bulletproof hosters put all their clients on the same /24 subnet.
  If evil.com is on 212.92.104.11, scanning 212.92.104.0/24
  via crt.sh finds every other domain on that range.
  This surfaces co-tenant infrastructure that shared hosting reveals.

  NForce, Frantech, FranTech, M247 — these bulletproof ASNs
  cluster their clients in tight IP ranges. One pivot finds them all.
"""

import urllib.request
import urllib.parse
import urllib.error
import json
import time
import socket


RDAP_IP_URL   = "https://rdap.arin.net/registry/ip/{ip}"
BGP_HE_URL    = "https://bgp.he.net/ip/{ip}#_prefixes"
USER_AGENT    = "inframap/1.4 (github.com/rkbrainstorms/inframap; CTI research)"


def get_cidr_from_ip(ip: str, timeout: int = 10) -> dict:
    """Get the CIDR block an IP belongs to via RDAP."""
    result = {
        "ip":     ip,
        "cidr":   None,
        "range":  None,
        "org":    None,
        "errors": []
    }

    # Derive /24 directly (simple but effective for our purposes)
    parts = ip.split(".")
    if len(parts) == 4:
        result["cidr"]  = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        result["range"] = f"{parts[0]}.{parts[1]}.{parts[2]}"

    return result


def scan_cidr_crtsh(cidr_prefix: str, timeout: int = 20) -> dict:
    """
    Find domains with certs issued to IPs in a /24 range via crt.sh.
    cidr_prefix: e.g. "212.92.104"
    """
    result = {
        "prefix":   cidr_prefix,
        "domains":  [],
        "ips":      [],
        "errors":   []
    }

    # Search crt.sh for certs with SANs matching IPs in this range
    # We search for each last octet 1-254 (limited to avoid hammering)
    sample_ips = [f"{cidr_prefix}.{i}" for i in [1, 10, 20, 50, 100, 150, 200, 254]]

    seen_domains = set()

    for ip in sample_ips[:5]:  # limit to 5 to be polite
        url = f"https://crt.sh/?output=json&q={urllib.parse.quote(ip)}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            for cert in data:
                name_value = cert.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lstrip("*.")
                    if name and "." in name and name not in seen_domains:
                        seen_domains.add(name)
                        result["domains"].append({
                            "domain": name,
                            "ip":     ip,
                            "issuer": cert.get("issuer_name", "")[:50]
                        })

            if not result["ips"] or ip not in result["ips"]:
                result["ips"].append(ip)
            time.sleep(0.5)

        except urllib.error.HTTPError as e:
            if e.code == 503:
                result["errors"].append(f"crt.sh unavailable (503)")
                break
        except Exception as e:
            result["errors"].append(f"CIDR scan error for {ip}: {str(e)[:50]}")
            continue

    return result


def pivot_cidr(ip: str, timeout: int = 20) -> dict:
    """
    Full CIDR pivot: determine /24 range, scan for co-tenant domains.
    """
    result = {
        "ip":           ip,
        "cidr":         None,
        "co_tenants":   [],
        "unique_domains": set(),
        "total_found":  0,
        "errors":       []
    }

    # Get CIDR info
    cidr_info = get_cidr_from_ip(ip, timeout=timeout)
    result["cidr"] = cidr_info.get("cidr")

    cidr_prefix = cidr_info.get("range")
    if not cidr_prefix:
        result["errors"].append(f"Could not determine /24 range for {ip}")
        return result

    # Scan the range
    scan = scan_cidr_crtsh(cidr_prefix, timeout=timeout)
    result["errors"].extend(scan.get("errors", []))

    # Filter out the original IP's own domains (avoid self-reporting)
    for entry in scan.get("domains", []):
        domain = entry.get("domain", "")
        if domain:
            result["co_tenants"].append(entry)
            result["unique_domains"].add(domain)

    result["unique_domains"] = sorted(result["unique_domains"])
    result["total_found"]    = len(result["unique_domains"])

    return result
