"""
Shodan InternetDB pivot — free, no API key required.
https://internetdb.shodan.io/

Returns open ports, CPEs, tags, hostnames, and vulnerabilities
for any IP address. Rate limited but generous for individual use.

Tags of interest for CTI:
  c2          — known command & control server
  eol-product — end-of-life software (easy target)
  self-signed — self-signed cert (common on phishing infra)
  honeypot    — likely a honeypot, skip
  tor         — Tor exit node
  vpn         — VPN server
  scanner     — active scanner (not threat actor infra)
"""

import urllib.request
import urllib.error
import json
import time


INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
USER_AGENT     = "inframap/1.3 (github.com/rkbrainstorms/inframap; CTI research)"

# Tags that indicate suspicious/malicious infrastructure
MALICIOUS_TAGS = {"c2", "botnet", "malware", "phishing", "spam", "tor"}
SUSPICIOUS_TAGS = {"self-signed", "eol-product", "compromised"}
BENIGN_TAGS = {"honeypot", "scanner", "cdn", "proxy"}


def pivot_internetdb(ip: str, timeout: int = 10) -> dict:
    """
    Query Shodan InternetDB for an IP address.
    No API key required. Returns ports, tags, vulns, CPEs.
    """
    result = {
        "ip":           ip,
        "ports":        [],
        "tags":         [],
        "cpes":         [],
        "hostnames":    [],
        "vulns":        [],
        "risk_score":   0,
        "risk_label":   None,
        "risk_reasons": [],
        "errors":       []
    }

    url = INTERNETDB_URL.format(ip=ip)

    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        result["ports"]     = data.get("ports", [])
        result["tags"]      = data.get("tags", [])
        result["cpes"]      = data.get("cpes", [])
        result["hostnames"] = data.get("hostnames", [])
        result["vulns"]     = data.get("vulns", [])

        _score_internetdb(result)

    except urllib.error.HTTPError as e:
        if e.code == 404:
            result["errors"].append(f"InternetDB: no data for {ip}")
        elif e.code == 429:
            result["errors"].append("InternetDB: rate limited")
        else:
            result["errors"].append(f"InternetDB HTTP {e.code}")
    except Exception as e:
        result["errors"].append(f"InternetDB error: {str(e)}")

    return result


def _score_internetdb(result: dict):
    """Score IP risk based on InternetDB data."""
    score   = 0
    reasons = []
    tags    = set(t.lower() for t in result.get("tags", []))
    ports   = result.get("ports", [])
    vulns   = result.get("vulns", [])

    # Skip honeypots and scanners — not threat actor infra
    if tags & BENIGN_TAGS:
        result["risk_score"]  = 0
        result["risk_label"]  = "BENIGN/SCANNER"
        result["risk_reasons"]= [f"tagged as: {', '.join(tags & BENIGN_TAGS)}"]
        return

    # Malicious tags
    mal_found = tags & MALICIOUS_TAGS
    if mal_found:
        score += 40
        reasons.append(f"malicious tags: {', '.join(mal_found)}")

    # Suspicious tags
    sus_found = tags & SUSPICIOUS_TAGS
    if sus_found:
        score += 20
        reasons.append(f"suspicious tags: {', '.join(sus_found)}")

    # Known vulnerabilities
    if len(vulns) >= 3:
        score += 20
        reasons.append(f"{len(vulns)} known CVEs")
    elif vulns:
        score += 10
        reasons.append(f"{len(vulns)} known CVE(s): {', '.join(vulns[:3])}")

    # Suspicious port combinations
    phishing_ports = {80, 443, 8080, 8443}
    c2_ports       = {4444, 1337, 8888, 9001, 9050, 31337}
    rdp_ssh_combo  = {22, 3389}

    open_ports = set(ports)
    if open_ports & c2_ports:
        score += 25
        reasons.append(f"C2-associated ports open: {open_ports & c2_ports}")
    if rdp_ssh_combo.issubset(open_ports):
        score += 10
        reasons.append("both RDP and SSH open")
    if len(open_ports) > 20:
        score += 10
        reasons.append(f"many open ports ({len(open_ports)})")

    score = min(score, 100)

    result["risk_score"]   = score
    result["risk_reasons"] = reasons

    if score >= 60:
        result["risk_label"] = "HIGH-RISK"
    elif score >= 30:
        result["risk_label"] = "SUSPICIOUS"
    elif score > 0:
        result["risk_label"] = "MODERATE"
    else:
        result["risk_label"] = "CLEAN"
