"""
CertSpotter pivot — Certificate Transparency fallback.
Free API, no key required, 100 requests/hour.
https://sslmate.com/certspotter/api

Used as fallback when crt.sh is unavailable (5xx/timeout).
Returns same cert data as crt.sh in a different format.
"""

import urllib.request
import urllib.parse
import urllib.error
import json
import re
import time


CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances?domain={domain}&expand=dns_names&expand=issuer&include_subdomains=true"
GOOGLE_CT_URL   = "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_expired=true&include_subdomains=true&domain={domain}"
USER_AGENT      = "inframap/1.3 (github.com/rkbrainstorms/inframap; CTI research)"


def pivot_certspotter(domain: str, timeout: int = 15) -> dict:
    """
    Query CertSpotter for certificate data.
    Returns same structure as crtsh pivot for drop-in compatibility.
    """
    result = {
        "query":        domain,
        "source":       "certspotter",
        "certs":        [],
        "unique_names": set(),
        "issuers":      {},
        "timing_clusters": [],
        "errors":       []
    }

    url = CERTSPOTTER_URL.format(domain=urllib.parse.quote(domain, safe=""))

    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        for cert in data:
            dns_names  = cert.get("dns_names", [])
            not_before = cert.get("not_before", "")
            not_after  = cert.get("not_after", "")
            issuer     = cert.get("issuer", {})
            issuer_org = issuer.get("organization", [])
            issuer_str = issuer_org[0] if issuer_org else issuer.get("common_name", "Unknown")

            parsed = {
                "id":         cert.get("id"),
                "names":      [n.lower().strip().lstrip("*.") for n in dns_names if n],
                "issuer_org": issuer_str,
                "not_before": not_before,
                "not_after":  not_after,
            }
            result["certs"].append(parsed)
            result["unique_names"].update(parsed["names"])
            result["issuers"][issuer_str] = result["issuers"].get(issuer_str, 0) + 1

    except urllib.error.HTTPError as e:
        if e.code == 429:
            result["errors"].append("CertSpotter: rate limit (100/hour free)")
        else:
            result["errors"].append(f"CertSpotter HTTP {e.code}")
    except Exception as e:
        result["errors"].append(f"CertSpotter error: {str(e)}")

    result["unique_names"] = sorted(result["unique_names"])
    result["cert_count"]   = len(result["certs"])
    return result


def pivot_google_ct(domain: str, timeout: int = 15) -> dict:
    """
    Query Google Certificate Transparency report.
    Completely free, no key, no documented rate limit.
    Returns same structure as crtsh pivot.
    """
    result = {
        "query":        domain,
        "source":       "google_ct",
        "certs":        [],
        "unique_names": set(),
        "issuers":      {},
        "errors":       []
    }

    url = GOOGLE_CT_URL.format(domain=urllib.parse.quote(domain, safe=""))

    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json"
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")

        # Google CT API returns a weird format — strip the )]}\' prefix
        if raw.startswith(")]}'\n"):
            raw = raw[5:]

        data = json.loads(raw)

        # Navigate the nested structure
        # Format: [[results_array, ...], ...]
        certs_data = []
        if isinstance(data, list) and len(data) > 0:
            if isinstance(data[0], list):
                certs_data = data[0]

        for cert in certs_data:
            if not isinstance(cert, list) or len(cert) < 5:
                continue

            names_raw  = cert[0] if cert[0] else []
            not_before = cert[1] if cert[1] else ""
            not_after  = cert[2] if cert[2] else ""
            issuer_str = cert[3] if cert[3] else "Unknown"

            names = []
            if isinstance(names_raw, list):
                names = [n.lower().strip().lstrip("*.") for n in names_raw if n]
            elif isinstance(names_raw, str):
                names = [names_raw.lower().strip().lstrip("*.")]

            parsed = {
                "id":         None,
                "names":      names,
                "issuer_org": issuer_str,
                "not_before": str(not_before),
                "not_after":  str(not_after),
            }
            result["certs"].append(parsed)
            result["unique_names"].update(names)
            result["issuers"][issuer_str] = result["issuers"].get(issuer_str, 0) + 1

    except Exception as e:
        result["errors"].append(f"Google CT error: {str(e)}")

    result["unique_names"] = sorted(result["unique_names"])
    result["cert_count"]   = len(result["certs"])
    return result
