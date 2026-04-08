"""
VirusTotal pivot — file, URL, domain, and IP reputation.
Free tier: 4 lookups/minute with free account key.
https://www.virustotal.com/gui/join-us

Returns:
  - Malicious/suspicious/clean vendor vote counts
  - Last analysis date
  - Categories (phishing, malware, etc.)
  - WHOIS data (for domains)
  - Passive DNS (for IPs)
  - Related URLs and domains

Free tier is rate-limited but sufficient for CTI investigation workflows.
"""

import urllib.request
import urllib.parse
import urllib.error
import json
import time


VT_BASE_URL  = "https://www.virustotal.com/api/v3"
USER_AGENT   = "inframap/1.4 (github.com/rkbrainstorms/inframap; CTI research)"


def pivot_virustotal_domain(domain: str, api_key: str = None, timeout: int = 15) -> dict:
    """Query VirusTotal for domain reputation."""
    result = {
        "domain":       domain,
        "malicious":    0,
        "suspicious":   0,
        "harmless":     0,
        "undetected":   0,
        "total_votes":  0,
        "verdict":      None,
        "categories":   [],
        "last_analysis": None,
        "registrar":    None,
        "creation_date": None,
        "tags":         [],
        "related_ips":  [],
        "errors":       []
    }

    if not api_key:
        result["errors"].append(
            "VirusTotal: no key — get free key at virustotal.com → "
            "inframap keys set virustotal YOUR_KEY"
        )
        return result

    url = f"{VT_BASE_URL}/domains/{urllib.parse.quote(domain, safe='')}"
    data = _vt_get(url, api_key, timeout, result)
    if not data:
        return result

    attrs = data.get("data", {}).get("attributes", {})
    _parse_vt_stats(attrs, result)

    # Domain-specific fields
    result["registrar"]    = attrs.get("registrar")
    result["creation_date"] = _format_date(attrs.get("creation_date"))
    result["tags"]         = attrs.get("tags", [])

    cats = attrs.get("categories", {})
    if isinstance(cats, dict):
        result["categories"] = list(set(cats.values()))[:5]

    return result


def pivot_virustotal_ip(ip: str, api_key: str = None, timeout: int = 15) -> dict:
    """Query VirusTotal for IP reputation."""
    result = {
        "ip":           ip,
        "malicious":    0,
        "suspicious":   0,
        "harmless":     0,
        "undetected":   0,
        "total_votes":  0,
        "verdict":      None,
        "asn":          None,
        "asn_name":     None,
        "country":      None,
        "network":      None,
        "tags":         [],
        "errors":       []
    }

    if not api_key:
        result["errors"].append(
            "VirusTotal: no key — inframap keys set virustotal YOUR_KEY"
        )
        return result

    url = f"{VT_BASE_URL}/ip_addresses/{urllib.parse.quote(ip, safe='')}"
    data = _vt_get(url, api_key, timeout, result)
    if not data:
        return result

    attrs = data.get("data", {}).get("attributes", {})
    _parse_vt_stats(attrs, result)

    result["asn"]      = attrs.get("asn")
    result["asn_name"] = attrs.get("as_owner")
    result["country"]  = attrs.get("country")
    result["network"]  = attrs.get("network")
    result["tags"]     = attrs.get("tags", [])

    return result


def pivot_virustotal_url(url_to_check: str, api_key: str = None, timeout: int = 15) -> dict:
    """Query VirusTotal for URL reputation."""
    result = {
        "url":        url_to_check,
        "malicious":  0,
        "suspicious": 0,
        "harmless":   0,
        "undetected": 0,
        "verdict":    None,
        "final_url":  None,
        "title":      None,
        "errors":     []
    }

    if not api_key:
        result["errors"].append("VirusTotal: no key")
        return result

    # VT URL lookup requires base64url encoding of the URL
    import base64
    url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().rstrip("=")
    url    = f"{VT_BASE_URL}/urls/{url_id}"

    data = _vt_get(url, api_key, timeout, result)
    if not data:
        return result

    attrs = data.get("data", {}).get("attributes", {})
    _parse_vt_stats(attrs, result)
    result["final_url"] = attrs.get("last_final_url")
    result["title"]     = attrs.get("title")

    return result


def _vt_get(url: str, api_key: str, timeout: int, result: dict):
    """Make a VirusTotal GET request."""
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": USER_AGENT,
            "x-apikey":  api_key,
            "Accept":    "application/json"
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 401:
            result["errors"].append("VirusTotal: invalid API key")
        elif e.code == 404:
            result["errors"].append("VirusTotal: resource not found")
        elif e.code == 429:
            result["errors"].append("VirusTotal: rate limit (4/min free) — wait 15s and retry")
        else:
            result["errors"].append(f"VirusTotal HTTP {e.code}")
    except Exception as e:
        result["errors"].append(f"VirusTotal error: {str(e)}")
    return None


def _parse_vt_stats(attrs: dict, result: dict):
    """Parse last_analysis_stats from VT response."""
    stats = attrs.get("last_analysis_stats", {})
    result["malicious"]   = stats.get("malicious", 0)
    result["suspicious"]  = stats.get("suspicious", 0)
    result["harmless"]    = stats.get("harmless", 0)
    result["undetected"]  = stats.get("undetected", 0)
    result["total_votes"] = sum(stats.values()) if stats else 0
    result["last_analysis"] = _format_date(attrs.get("last_analysis_date"))

    mal = result["malicious"]
    sus = result["suspicious"]
    if mal >= 5:
        result["verdict"] = "MALICIOUS"
    elif mal >= 1 or sus >= 3:
        result["verdict"] = "SUSPICIOUS"
    elif result["total_votes"] > 0:
        result["verdict"] = "CLEAN"
    else:
        result["verdict"] = "UNKNOWN"


def _format_date(ts) -> str:
    """Convert Unix timestamp to date string."""
    if not ts:
        return None
    try:
        from datetime import datetime, timezone
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        return str(ts)
