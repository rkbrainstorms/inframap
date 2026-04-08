"""
abuse.ch IOC matching — ThreatFox + URLhaus.
Both completely free, no API key required.

ThreatFox: https://threatfox.abuse.ch/api/
  - Matches IOCs against known malware campaigns
  - Returns malware family, threat type, confidence

URLhaus: https://urlhaus-api.abuse.ch/
  - Matches URLs/domains against known malware distribution URLs
  - Returns malware tags, status (online/offline), reporter

These two sources together tell you if an IOC is ALREADY KNOWN
in a malware campaign — the highest-value signal for triage.
"""

import urllib.request
import urllib.error
import urllib.parse
import json
import time


THREATFOX_URL  = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_URL    = "https://urlhaus-api.abuse.ch/v1/"
USER_AGENT     = "inframap/1.3 (github.com/rkbrainstorms/inframap; CTI research)"


def check_threatfox(ioc: str, ioc_type: str = "auto", timeout: int = 10) -> dict:
    """
    Check an IOC against ThreatFox database.
    ioc_type: 'domain', 'ip:port', 'url', 'md5_hash', 'sha256_hash', or 'auto'
    """
    result = {
        "ioc":          ioc,
        "found":        False,
        "malware":      None,
        "threat_type":  None,
        "confidence":   None,
        "tags":         [],
        "first_seen":   None,
        "reporter":     None,
        "errors":       []
    }

    payload = json.dumps({"query": "search_ioc", "search_term": ioc}).encode("utf-8")

    try:
        req = urllib.request.Request(
            THREATFOX_URL,
            data=payload,
            headers={
                "User-Agent":   USER_AGENT,
                "Content-Type": "application/json"
            }
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        status = data.get("query_status", "")

        if status == "ok" and data.get("data"):
            ioc_data = data["data"][0] if isinstance(data["data"], list) else data["data"]
            result["found"]       = True
            result["malware"]     = ioc_data.get("malware_printable") or ioc_data.get("malware")
            result["threat_type"] = ioc_data.get("threat_type_desc") or ioc_data.get("threat_type")
            result["confidence"]  = ioc_data.get("confidence_level")
            result["tags"]        = ioc_data.get("tags") or []
            result["first_seen"]  = (ioc_data.get("first_seen") or "")[:10]
            result["reporter"]    = ioc_data.get("reporter")

    except urllib.error.HTTPError as e:
        result["errors"].append(f"ThreatFox HTTP {e.code}")
    except Exception as e:
        result["errors"].append(f"ThreatFox error: {str(e)}")

    return result


def check_urlhaus(url_or_domain: str, timeout: int = 10) -> dict:
    """
    Check a URL or domain against URLhaus malware URL database.
    """
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

    # Determine if it's a URL or domain
    if url_or_domain.startswith("http"):
        endpoint = f"{URLHAUS_URL}url/"
        payload  = f"url={urllib.parse.quote(url_or_domain)}"
    else:
        endpoint = f"{URLHAUS_URL}host/"
        payload  = f"host={urllib.parse.quote(url_or_domain)}"

    try:

        payload_bytes = payload.encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=payload_bytes,
            headers={
                "User-Agent":   USER_AGENT,
                "Content-Type": "application/x-www-form-urlencoded"
            }
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        status = data.get("query_status", "")

        if status in ("is_host", "ok") and data.get("urls"):
            result["found"] = True
            # Get the most recent URL entry
            urls = data["urls"]
            if urls:
                latest = urls[0]
                result["status"]     = latest.get("url_status")
                result["threat"]     = latest.get("threat")
                result["tags"]       = latest.get("tags") or []
                result["date_added"] = (latest.get("date_added") or "")[:10]
                result["reporter"]   = latest.get("reporter")

    except urllib.error.HTTPError as e:
        result["errors"].append(f"URLhaus HTTP {e.code}")
    except Exception as e:
        result["errors"].append(f"URLhaus error: {str(e)}")

    return result


def bulk_check_iocs(iocs: list, timeout: int = 10) -> dict:
    """
    Check multiple IOCs against both ThreatFox and URLhaus.
    Returns a summary of matches with malware families found.

    iocs: list of dicts with 'type' and 'value' keys
    """
    results  = {
        "checked":         0,
        "matches":         [],
        "malware_families": set(),
        "all_known":       False,
        "errors":          []
    }

    domains = [i["value"] for i in iocs if i.get("type") == "domain"][:5]
    ips     = [i["value"] for i in iocs if i.get("type") == "ip"][:5]

    for domain in domains:
        results["checked"] += 1
        tf = check_threatfox(domain, timeout=timeout)
        uh = check_urlhaus(domain, timeout=timeout)

        if tf.get("found"):
            results["matches"].append({
                "ioc":     domain,
                "type":    "domain",
                "source":  "ThreatFox",
                "malware": tf.get("malware"),
                "threat":  tf.get("threat_type"),
                "tags":    tf.get("tags", [])
            })
            if tf.get("malware"):
                results["malware_families"].add(tf["malware"])

        if uh.get("found"):
            results["matches"].append({
                "ioc":    domain,
                "type":   "domain",
                "source": "URLhaus",
                "threat": uh.get("threat"),
                "status": uh.get("status"),
                "tags":   uh.get("tags", [])
            })

        time.sleep(0.3)

    for ip in ips:
        results["checked"] += 1
        tf = check_threatfox(ip, timeout=timeout)
        if tf.get("found"):
            results["matches"].append({
                "ioc":     ip,
                "type":    "ip",
                "source":  "ThreatFox",
                "malware": tf.get("malware"),
                "threat":  tf.get("threat_type"),
            })
            if tf.get("malware"):
                results["malware_families"].add(tf["malware"])
        time.sleep(0.3)

    results["malware_families"] = sorted(results["malware_families"])
    results["all_known"] = len(results["matches"]) > 0

    return results
