"""
Passive DNS pivot — multi-source with automatic fallback.

Sources (tried in order):
1. HackerTarget  — free, no key, 100 queries/day
2. Mnemonic PDNS — completely free, no key, no documented rate limit
   https://passivedns.mnemonic.no/

When HackerTarget hits its daily limit, Mnemonic kicks in automatically.
No intervention needed from the user.
"""

import urllib.request
import urllib.parse
import urllib.error
import json
import time


HT_PDNS_URL    = "https://api.hackertarget.com/hostsearch/?q={domain}"
HT_RDNS_URL    = "https://api.hackertarget.com/reverseiplookup/?q={ip}"
MNEMONIC_URL   = "https://passivedns.mnemonic.no/v2/search"
USER_AGENT     = "inframap/1.2 (github.com/rkbrainstorms/inframap; CTI research)"


def pivot_passivedns(domain: str = None, ip: str = None, timeout: int = 10) -> dict:
    """
    Query passive DNS for historical resolutions.
    Automatically falls back from HackerTarget to Mnemonic on rate limit.
    """
    result = {
        "query":          domain or ip,
        "query_type":     "domain" if domain else "ip",
        "resolutions":    [],
        "unique_ips":     set(),
        "unique_domains": set(),
        "shared_hosts":   [],
        "source_used":    None,
        "errors":         []
    }

    # Try HackerTarget first
    ht_hit_limit = False
    if domain:
        ht_hit_limit = _hackertarget_domain(domain, result, timeout)
    if ip:
        _hackertarget_ip(ip, result, timeout)
        time.sleep(0.3)

    # If HackerTarget hit rate limit, fall back to Mnemonic
    if ht_hit_limit and domain:
        result["errors"] = [e for e in result["errors"] if "daily limit" not in e]
        _mnemonic_domain(domain, result, timeout)

    # Reverse lookups on discovered IPs for co-hosted domains
    if domain and result["unique_ips"]:
        for resolved_ip in list(result["unique_ips"])[:3]:
            shared = _get_shared_hosts(resolved_ip, domain, timeout)
            if shared:
                result["shared_hosts"].extend(shared)
            time.sleep(0.3)

    result["unique_ips"]     = sorted(result["unique_ips"])
    result["unique_domains"] = sorted(result["unique_domains"])
    result["shared_hosts"]   = sorted(set(result["shared_hosts"]))
    result["resolution_count"] = len(result["resolutions"])

    return result


def _hackertarget_domain(domain: str, result: dict, timeout: int) -> bool:
    """Returns True if rate limit was hit."""
    url  = HT_PDNS_URL.format(domain=urllib.parse.quote(domain))
    text = _fetch_text(url, timeout, result, "HackerTarget")
    if not text:
        return False

    if "API count exceeded" in text:
        result["errors"].append("HackerTarget: daily limit reached (100/day) — using Mnemonic fallback")
        return True

    if "error" in text.lower() and len(text) < 100:
        result["errors"].append(f"HackerTarget: {text.strip()}")
        return False

    for line in text.strip().splitlines():
        if "," not in line:
            continue
        parts = line.split(",", 1)
        if len(parts) == 2:
            subdomain, ip = parts[0].strip(), parts[1].strip()
            if subdomain and ip and _looks_like_ip(ip):
                result["resolutions"].append({
                    "domain": subdomain, "ip": ip,
                    "source": "hackertarget"
                })
                result["unique_ips"].add(ip)
                result["unique_domains"].add(subdomain)

    if result["resolutions"]:
        result["source_used"] = "HackerTarget"
    return False


def _hackertarget_ip(ip: str, result: dict, timeout: int):
    url  = HT_RDNS_URL.format(ip=urllib.parse.quote(ip))
    text = _fetch_text(url, timeout, result, "HackerTarget")
    if not text or "API count exceeded" in text:
        return
    for line in text.strip().splitlines():
        domain = line.strip()
        if domain and "." in domain and not domain.startswith("error"):
            result["resolutions"].append({
                "domain": domain, "ip": ip,
                "source": "hackertarget-reverse"
            })
            result["unique_domains"].add(domain)


def _mnemonic_domain(domain: str, result: dict, timeout: int):
    """Query Mnemonic PassiveDNS — completely free, no key required."""
    try:
        params  = urllib.parse.urlencode({"query": domain, "limit": 100})
        url     = f"{MNEMONIC_URL}?{params}"
        req     = urllib.request.Request(url, headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json"
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        records = data.get("data", {}).get("records", []) or data.get("records", [])
        for record in records:
            # Mnemonic returns different formats depending on version
            answer = record.get("answer") or record.get("rrdata", "")
            query  = record.get("query") or domain
            rtype  = record.get("rrtype", "A")

            if rtype in ("A", "AAAA") and answer:
                result["resolutions"].append({
                    "domain": query,
                    "ip":     answer,
                    "source": "mnemonic"
                })
                if _looks_like_ip(answer):
                    result["unique_ips"].add(answer)
                result["unique_domains"].add(query)

        if result["resolutions"]:
            result["source_used"] = "Mnemonic PassiveDNS"

    except urllib.error.HTTPError as e:
        result["errors"].append(f"Mnemonic PDNS HTTP {e.code}")
    except Exception as e:
        result["errors"].append(f"Mnemonic PDNS error: {str(e)}")


def _get_shared_hosts(ip: str, seed_domain: str, timeout: int) -> list:
    """Domains co-hosted on the same IP."""
    url = HT_RDNS_URL.format(ip=urllib.parse.quote(ip))
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        shared = []
        for line in text.strip().splitlines():
            domain = line.strip()
            if (domain and "." in domain and domain != seed_domain
                    and not domain.startswith("error")
                    and "API count" not in domain):
                shared.append(domain)
        return shared
    except Exception:
        return []


def _fetch_text(url: str, timeout: int, result: dict, source: str):  # -> Optional[str]
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        result["errors"].append(f"{source} HTTP {e.code}")
    except Exception as e:
        result["errors"].append(f"{source} error: {str(e)}")
    return None


def _looks_like_ip(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False
