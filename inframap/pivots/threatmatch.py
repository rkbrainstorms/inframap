"""
abuse.ch IOC matching — ThreatFox + URLhaus.

ThreatFox: requires free Auth-Key from https://auth.abuse.ch/
URLhaus:   requires free Auth-Key from https://auth.abuse.ch/

Both are free. Get your key in 30 seconds using GitHub/Google login.
Store it: inframap keys set threatfox YOUR_KEY

Without a key, this module runs in degraded mode and will return 401 errors.

Note: These databases track malware delivery URLs and C2 endpoints.
Infrastructure domains (AiTM platforms, bulletproof DNS providers) often
return no matches even when confirmed malicious — this is expected.
"""

import urllib.request
import urllib.parse
import urllib.error
import json
import time


THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_URL   = "https://urlhaus-api.abuse.ch/v1/"
USER_AGENT    = "inframap/1.4 (github.com/rkbrainstorms/inframap; CTI research)"


def check_threatfox(ioc: str, api_key: str = None, timeout: int = 10) -> dict:
    """Check an IOC against ThreatFox. Free key required from auth.abuse.ch"""
    result = {
        "ioc":         ioc,
        "found":       False,
        "malware":     None,
        "threat_type": None,
        "confidence":  None,
        "tags":        [],
        "first_seen":  None,
        "reporter":    None,
        "errors":      []
    }

    if not api_key:
        result["errors"].append(
            "ThreatFox: no key configured. "
            "Get free key at auth.abuse.ch → run: inframap keys set threatfox YOUR_KEY"
        )
        return result

    try:
        payload = json.dumps({"query": "search_ioc", "search_term": ioc}).encode("utf-8")
        req = urllib.request.Request(
            THREATFOX_URL,
            data=payload,
            headers={
                "Auth-Key":     api_key,
                "User-Agent":   USER_AGENT,
                "Content-Type": "application/json"
            }
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        if data.get("query_status") == "ok" and data.get("data"):
            ioc_data = data["data"][0] if isinstance(data["data"], list) else data["data"]
            result["found"]       = True
            result["malware"]     = ioc_data.get("malware_printable") or ioc_data.get("malware")
            result["threat_type"] = ioc_data.get("threat_type_desc") or ioc_data.get("threat_type")
            result["confidence"]  = ioc_data.get("confidence_level")
            result["tags"]        = ioc_data.get("tags") or []
            result["first_seen"]  = (ioc_data.get("first_seen") or "")[:10]
            result["reporter"]    = ioc_data.get("reporter")

    except urllib.error.HTTPError as e:
        if e.code == 401:
            result["errors"].append(
                "ThreatFox: invalid key. Get free key at auth.abuse.ch"
            )
        else:
            result["errors"].append(f"ThreatFox HTTP {e.code}")
    except Exception as e:
        result["errors"].append(f"ThreatFox error: {str(e)}")

    return result


def check_urlhaus(url_or_domain: str, api_key: str = None, timeout: int = 10) -> dict:
    """Check a URL or domain against URLhaus. Free key from auth.abuse.ch"""
    result = {
        "query":      url_or_domain,
        "found":      False,
        "status":     None,
        "threat":     None,
        "tags":       [],
        "date_added": None,
        "reporter":   None,
        "errors":     []
    }

    if not api_key:
        result["errors"].append(
            "URLhaus: no key configured. "
            "Get free key at auth.abuse.ch → run: inframap keys set urlhaus YOUR_KEY"
        )
        return result

    if url_or_domain.startswith("http"):
        endpoint = f"{URLHAUS_URL}url/"
        payload  = urllib.parse.urlencode({"url": url_or_domain}).encode("utf-8")
    else:
        endpoint = f"{URLHAUS_URL}host/"
        payload  = urllib.parse.urlencode({"host": url_or_domain}).encode("utf-8")

    try:
        req = urllib.request.Request(
            endpoint,
            data=payload,
            headers={
                "Auth-Key":     api_key,
                "User-Agent":   USER_AGENT,
                "Content-Type": "application/x-www-form-urlencoded"
            }
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        status = data.get("query_status", "")
        if status in ("is_host", "ok") and data.get("urls"):
            result["found"] = True
            latest = data["urls"][0]
            result["status"]     = latest.get("url_status")
            result["threat"]     = latest.get("threat")
            result["tags"]       = latest.get("tags") or []
            result["date_added"] = (latest.get("date_added") or "")[:10]
            result["reporter"]   = latest.get("reporter")

    except urllib.error.HTTPError as e:
        if e.code == 401:
            result["errors"].append("URLhaus: invalid key. Get free key at auth.abuse.ch")
        else:
            result["errors"].append(f"URLhaus HTTP {e.code}")
    except Exception as e:
        result["errors"].append(f"URLhaus error: {str(e)}")

    return result


def bulk_check_iocs(iocs: list, threatfox_key: str = None,
                    urlhaus_key: str = None, timeout: int = 10) -> dict:
    """
    Check multiple IOCs against ThreatFox and URLhaus.
    Both require free keys from auth.abuse.ch
    """
    results = {
        "checked":          0,
        "matches":          [],
        "malware_families": set(),
        "errors":           [],
        "note":             None,
        "needs_keys":       not threatfox_key and not urlhaus_key
    }

    if results["needs_keys"]:
        results["note"] = (
            "ThreatFox and URLhaus now require a free API key. "
            "Get yours at https://auth.abuse.ch/ (30 seconds, use GitHub/Google login). "
            "Then run: inframap keys set threatfox YOUR_KEY && inframap keys set urlhaus YOUR_KEY"
        )
        return results

    domains = [i["value"] for i in iocs if i.get("type") == "domain"][:5]
    ips     = [i["value"] for i in iocs if i.get("type") == "ip"][:5]
    all_errors = []

    for domain in domains:
        results["checked"] += 1
        tf = check_threatfox(domain, api_key=threatfox_key, timeout=timeout)
        uh = check_urlhaus(domain, api_key=urlhaus_key, timeout=timeout)

        all_errors.extend(tf.get("errors", []))
        all_errors.extend(uh.get("errors", []))

        if tf.get("found"):
            results["matches"].append({
                "ioc":     domain, "type": "domain",
                "source":  "ThreatFox",
                "malware": tf.get("malware"),
                "threat":  tf.get("threat_type"),
                "tags":    tf.get("tags", [])
            })
            if tf.get("malware"):
                results["malware_families"].add(tf["malware"])

        if uh.get("found"):
            results["matches"].append({
                "ioc":    domain, "type": "domain",
                "source": "URLhaus",
                "threat": uh.get("threat"),
                "status": uh.get("status"),
                "tags":   uh.get("tags", [])
            })
        time.sleep(0.3)

    for ip in ips:
        results["checked"] += 1
        tf = check_threatfox(ip, api_key=threatfox_key, timeout=timeout)
        all_errors.extend(tf.get("errors", []))
        if tf.get("found"):
            results["matches"].append({
                "ioc": ip, "type": "ip",
                "source": "ThreatFox",
                "malware": tf.get("malware"),
                "threat":  tf.get("threat_type"),
            })
            if tf.get("malware"):
                results["malware_families"].add(tf["malware"])
        time.sleep(0.3)

    results["malware_families"] = sorted(results["malware_families"])

    if not results["matches"] and results["checked"] > 0:
        unique_errors = list(set(e for e in all_errors if "no key" not in e.lower()))
        if unique_errors:
            results["note"] = "API errors occurred — results may be incomplete"
        else:
            results["note"] = (
                "No matches found. ThreatFox/URLhaus track malware delivery URLs "
                "and C2 endpoints. Infrastructure domains may not appear even "
                "when confirmed malicious — this is expected behaviour."
            )

    results["errors"] = list(set(all_errors))[:3]
    return results
