"""
Passive DNS pivot — HackerTarget free API.
No API key required. Returns historical DNS resolutions for a domain.

HackerTarget free tier: 100 queries/day, no auth required.
https://hackertarget.com/ip-tools/

This is the missing link that no other free tool chains with CT logs + WHOIS.
Historical DNS resolutions reveal infrastructure reuse across campaigns.
"""

import urllib.request
import urllib.parse
import urllib.error
import time


HT_PDNS_URL  = "https://api.hackertarget.com/hostsearch/?q={domain}"
HT_RDNS_URL  = "https://api.hackertarget.com/reverseiplookup/?q={ip}"
USER_AGENT   = "inframap/1.0 (github.com/rkbrainstorms/inframap; CTI research)"


def pivot_passivedns(domain: str = None, ip: str = None, timeout: int = 10) -> dict:
    """
    Query HackerTarget for passive DNS resolutions.
    - domain: returns all IPs this domain has resolved to historically
    - ip:     returns all domains that have resolved to this IP (reverse DNS)
    """
    result = {
        "query":        domain or ip,
        "query_type":   "domain" if domain else "ip",
        "resolutions":  [],
        "unique_ips":   set(),
        "unique_domains": set(),
        "shared_hosts": [],   # domains sharing same IP = infrastructure reuse
        "errors":       []
    }

    if domain:
        _query_domain(domain, result, timeout)

    if ip:
        _query_ip(ip, result, timeout)
        time.sleep(0.5)

    # If we got IPs from domain lookup, do reverse lookup on each
    # to find co-hosted domains (infrastructure clustering)
    if domain and result["unique_ips"]:
        for resolved_ip in list(result["unique_ips"])[:3]:
            shared = _get_shared_hosts(resolved_ip, domain, timeout)
            if shared:
                result["shared_hosts"].extend(shared)
            time.sleep(0.5)

    result["unique_ips"]     = sorted(result["unique_ips"])
    result["unique_domains"] = sorted(result["unique_domains"])
    result["shared_hosts"]   = sorted(set(result["shared_hosts"]))
    result["resolution_count"] = len(result["resolutions"])

    return result


def _query_domain(domain: str, result: dict, timeout: int):
    """Forward lookup: domain -> IPs it has resolved to."""
    url = HT_PDNS_URL.format(domain=urllib.parse.quote(domain))
    text = _fetch(url, timeout, result)
    if not text:
        return

    if "API count exceeded" in text:
        result["errors"].append("HackerTarget: daily limit reached (100/day free)")
        return

    if "error" in text.lower() and len(text) < 100:
        result["errors"].append(f"HackerTarget: {text.strip()}")
        return

    for line in text.strip().splitlines():
        line = line.strip()
        if not line or "," not in line:
            continue
        parts = line.split(",", 1)
        if len(parts) == 2:
            subdomain, ip = parts[0].strip(), parts[1].strip()
            if subdomain and ip and _looks_like_ip(ip):
                result["resolutions"].append({
                    "domain": subdomain,
                    "ip":     ip,
                    "source": "hackertarget-hostsearch"
                })
                result["unique_ips"].add(ip)
                result["unique_domains"].add(subdomain)


def _query_ip(ip: str, result: dict, timeout: int):
    """Reverse lookup: IP -> domains that have pointed to it."""
    url = HT_RDNS_URL.format(ip=urllib.parse.quote(ip))
    text = _fetch(url, timeout, result)
    if not text:
        return

    if "API count exceeded" in text:
        result["errors"].append("HackerTarget: daily limit reached (100/day free)")
        return

    for line in text.strip().splitlines():
        domain = line.strip()
        if domain and "." in domain and not domain.startswith("error"):
            result["resolutions"].append({
                "domain": domain,
                "ip":     ip,
                "source": "hackertarget-reverseip"
            })
            result["unique_domains"].add(domain)


def _get_shared_hosts(ip: str, seed_domain: str, timeout: int) -> list:
    """Return domains co-hosted on the same IP, excluding the seed domain."""
    url = HT_RDNS_URL.format(ip=urllib.parse.quote(ip))
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        shared = []
        for line in text.strip().splitlines():
            domain = line.strip()
            if domain and "." in domain and domain != seed_domain \
               and not domain.startswith("error") \
               and "API count" not in domain:
                shared.append(domain)
        return shared
    except Exception:
        return []


def _fetch(url: str, timeout: int, result: dict) -> str | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        result["errors"].append(f"HackerTarget HTTP {e.code}")
    except Exception as e:
        result["errors"].append(f"HackerTarget error: {str(e)}")
    return None


def _looks_like_ip(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False
