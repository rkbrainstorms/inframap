"""
GreyNoise pivot — IP noise classification.
Tells you if an IP is internet background noise vs targeted activity.

Free tiers:
  No key:   community endpoint — basic noise/riot classification
  Free key: 1000 IPs/day, full context, tags, CVEs, GNQL queries
            Sign up: https://www.greynoise.io/

Key priority:
  1. --greynoise-key CLI flag
  2. GREYNOISE_API_KEY environment variable
  3. inframap config set greynoise-key YOUR_KEY
  4. keyless community endpoint (limited but useful)

Why this matters for CTI:
  NOISE = internet background scanners, not targeting you specifically
  RIOT  = known benign infrastructure (Google, Cloudflare, etc.)
  Neither = potentially targeted activity — investigate further
"""

import urllib.request
import urllib.error
import json
import time


COMMUNITY_URL = "https://api.greynoise.io/v3/community/{ip}"
FULL_URL      = "https://api.greynoise.io/v2/noise/context/{ip}"
USER_AGENT    = "inframap/1.4 (github.com/rkbrainstorms/inframap; CTI research)"


def pivot_greynoise(ip: str, api_key: str = None, timeout: int = 10) -> dict:
    """
    Query GreyNoise for IP classification.
    Without key: community endpoint (noise/riot/unknown only).
    With key: full context including tags, CVEs, classification.
    """
    result = {
        "ip":           ip,
        "noise":        None,   # True = background scanner
        "riot":         None,   # True = known benign (Google, CF, etc.)
        "classification": None, # malicious/benign/unknown
        "name":         None,   # actor/org name
        "link":         None,   # GreyNoise URL for more info
        "last_seen":    None,
        "tags":         [],
        "cves":         [],
        "tier":         "community" if not api_key else "full",
        "errors":       []
    }

    if api_key:
        _query_full(ip, api_key, result, timeout)
    else:
        _query_community(ip, result, timeout)

    return result


def _query_community(ip: str, result: dict, timeout: int):
    """Query the free community endpoint (no key)."""
    url = COMMUNITY_URL.format(ip=ip)
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": USER_AGENT,
            "Accept":     "application/json"
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        result["noise"]   = data.get("noise", False)
        result["riot"]    = data.get("riot", False)
        result["name"]    = data.get("name")
        result["link"]    = data.get("link")
        result["last_seen"] = (data.get("last_seen") or "")[:10]

        # Derive classification from community data
        if result["riot"]:
            result["classification"] = "benign"
        elif result["noise"]:
            result["classification"] = "noise"
        else:
            result["classification"] = "unknown"

    except urllib.error.HTTPError as e:
        if e.code == 404:
            # IP not in GreyNoise — not a scanner, potentially targeted
            result["noise"]          = False
            result["riot"]           = False
            result["classification"] = "not_seen"
        elif e.code == 429:
            result["errors"].append("GreyNoise: rate limited (add free API key for 1000/day)")
        elif e.code == 401:
            result["errors"].append(
                "GreyNoise: API key required. "
                "Get free key: https://www.greynoise.io/ | "
                "inframap config set greynoise-key YOUR_KEY"
            )
        else:
            result["errors"].append(f"GreyNoise HTTP {e.code}")
    except Exception as e:
        result["errors"].append(f"GreyNoise error: {str(e)}")


def _query_full(ip: str, api_key: str, result: dict, timeout: int):
    """Query full context endpoint with API key."""
    url = FULL_URL.format(ip=ip)
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": USER_AGENT,
            "key":        api_key,
            "Accept":     "application/json"
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        result["noise"]          = data.get("seen", False)
        result["riot"]           = data.get("riot", False)
        result["classification"] = data.get("classification")
        result["name"]           = data.get("actor") or data.get("name")
        result["last_seen"]      = (data.get("last_seen") or "")[:10]
        result["tags"]           = data.get("tags") or []
        result["cves"]           = data.get("cve") or []
        result["link"]           = f"https://viz.greynoise.io/ip/{ip}"

    except urllib.error.HTTPError as e:
        if e.code == 401:
            result["errors"].append("GreyNoise: invalid API key")
            # Fall back to community
            _query_community(ip, result, timeout)
        elif e.code == 404:
            result["noise"]          = False
            result["riot"]           = False
            result["classification"] = "not_seen"
        else:
            result["errors"].append(f"GreyNoise HTTP {e.code}")
            _query_community(ip, result, timeout)
    except Exception as e:
        result["errors"].append(f"GreyNoise error: {str(e)}")
        _query_community(ip, result, timeout)


def bulk_greynoise(ips: list, api_key: str = None, timeout: int = 10) -> dict:
    """Check multiple IPs against GreyNoise."""
    results = {
        "checked":   0,
        "noise":     [],   # background scanners
        "riot":      [],   # known benign
        "not_seen":  [],   # not in GreyNoise — potentially targeted
        "malicious": [],   # classified malicious (with key)
        "errors":    []
    }

    for ip in ips[:10]:
        results["checked"] += 1
        r = pivot_greynoise(ip, api_key=api_key, timeout=timeout)
        results["errors"].extend(r.get("errors", []))

        classification = r.get("classification")
        if r.get("riot"):
            results["riot"].append(ip)
        elif classification == "malicious":
            results["malicious"].append(ip)
        elif r.get("noise"):
            results["noise"].append(ip)
        elif classification == "not_seen":
            results["not_seen"].append(ip)

        time.sleep(0.2)

    results["errors"] = list(dict.fromkeys(results["errors"]))[:3]
    return results
