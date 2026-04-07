"""
AbuseIPDB pivot — IP reputation and abuse history.
Free API key required: https://www.abuseipdb.com/register
1000 checks/day free (3000/day with domain verification).
"""

import urllib.request
import urllib.parse
import urllib.error
import json


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
USER_AGENT    = "inframap/1.0 (github.com/rhishav/inframap; CTI research)"


def pivot_abuseip(ip: str, api_key: str = None, timeout: int = 10) -> dict:
    """
    Check an IP against AbuseIPDB.
    Returns abuse confidence score, usage type, ISP, and recent report count.
    """
    result = {
        "ip":                ip,
        "abuse_score":       None,
        "usage_type":        None,
        "isp":               None,
        "domain":            None,
        "country":           None,
        "total_reports":     None,
        "last_reported":     None,
        "is_tor":            False,
        "confidence_label":  None,
        "errors":            []
    }

    if not api_key:
        result["errors"].append("AbuseIPDB: no API key provided (get a free key at abuseipdb.com)")
        return result

    params = urllib.parse.urlencode({
        "ipAddress":     ip,
        "maxAgeInDays":  90,
        "verbose":       ""
    })
    url = f"{ABUSEIPDB_URL}?{params}"

    try:
        req = urllib.request.Request(url, headers={
            "Key":        api_key,
            "Accept":     "application/json",
            "User-Agent": USER_AGENT
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data   = json.loads(resp.read().decode("utf-8"))
            d      = data.get("data", {})
            score  = d.get("abuseConfidenceScore", 0)

            result["abuse_score"]   = score
            result["usage_type"]    = d.get("usageType")
            result["isp"]           = d.get("isp")
            result["domain"]        = d.get("domain")
            result["country"]       = d.get("countryCode")
            result["total_reports"] = d.get("totalReports", 0)
            result["last_reported"] = d.get("lastReportedAt", "")[:10] if d.get("lastReportedAt") else None
            result["is_tor"]        = d.get("isTor", False)

            # Confidence label for report output
            if score >= 80:
                result["confidence_label"] = "HIGH-RISK"
            elif score >= 40:
                result["confidence_label"] = "SUSPICIOUS"
            elif score > 0:
                result["confidence_label"] = "LOW-RISK"
            else:
                result["confidence_label"] = "CLEAN"

    except urllib.error.HTTPError as e:
        if e.code == 429:
            result["errors"].append("AbuseIPDB rate limit hit")
        elif e.code == 401:
            result["errors"].append("AbuseIPDB: invalid API key")
        else:
            result["errors"].append(f"AbuseIPDB HTTP {e.code}")
    except Exception as e:
        result["errors"].append(f"AbuseIPDB error: {str(e)}")

    return result
