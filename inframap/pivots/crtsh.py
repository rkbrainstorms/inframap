"""
crt.sh pivot — Certificate Transparency log queries.
No API key required. Queries the public crt.sh JSON API.

Supports:
  - Exact domain:  example.com
  - Wildcard:      %.example.com  (also catches subdomains)
  - Onion hunting: %.onion (independently discovered technique)
"""

import urllib.request
import urllib.parse
import urllib.error
import json
import re
import hashlib
import time
from datetime import datetime


CRT_SH_URL = "https://crt.sh/?output=json&q={query}"
USER_AGENT  = "inframap/1.0 (github.com/rhishav/inframap; CTI research)"


def pivot_crtsh(domain: str, timeout: int = 10, wildcard: bool = True) -> dict:
    """
    Query crt.sh for certificates associated with a domain.
    Returns parsed cert list, extracted names, issuers, and timing clusters.
    """
    results = {
        "query": domain,
        "wildcard": wildcard,
        "certs": [],
        "unique_names": set(),
        "issuers": {},
        "timing_clusters": [],
        "errors": []
    }

    queries = []
    if wildcard:
        queries.append(f"%.{domain}")
    queries.append(domain)

    raw_certs = []
    seen_ids  = set()

    for q in queries:
        encoded = urllib.parse.quote(q, safe="")
        url     = CRT_SH_URL.format(query=encoded)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                for cert in data:
                    cid = cert.get("id")
                    if cid and cid not in seen_ids:
                        seen_ids.add(cid)
                        raw_certs.append(cert)
        except urllib.error.HTTPError as e:
            results["errors"].append(f"crt.sh HTTP {e.code} for query '{q}'")
        except Exception as e:
            results["errors"].append(f"crt.sh error for query '{q}': {str(e)}")
        time.sleep(0.3)  # be polite

    for cert in raw_certs:
        parsed = _parse_cert(cert)
        results["certs"].append(parsed)
        results["unique_names"].update(parsed["names"])

        issuer = parsed["issuer_org"]
        results["issuers"][issuer] = results["issuers"].get(issuer, 0) + 1

    results["unique_names"] = sorted(results["unique_names"])
    results["cert_count"]   = len(results["certs"])
    results["timing_clusters"] = _cluster_by_timing(results["certs"])
    results["issuer_summary"]  = _summarise_issuers(results["issuers"])

    return results


def _parse_cert(raw: dict) -> dict:
    """Normalise a raw crt.sh cert entry."""
    name_value = raw.get("name_value", "")
    names = sorted(set(
        n.strip().lower()
        for n in re.split(r"[\n,]", name_value)
        if n.strip() and n.strip() != "<not part of certificate>"
    ))

    # Extract issuer org from issuer CA field
    issuer_ca   = raw.get("issuer_ca_id", "")
    issuer_name = raw.get("issuer_name", "")
    issuer_org  = _extract_org(issuer_name)

    not_before  = raw.get("not_before", "")
    not_after   = raw.get("not_after", "")

    # Fingerprint the cert entry for clustering
    fp_input = "|".join([issuer_org, not_before[:7]])  # issuer + year-month
    fp       = hashlib.md5(fp_input.encode()).hexdigest()[:8]

    return {
        "id":          raw.get("id"),
        "serial":      raw.get("serial_number", ""),
        "names":       names,
        "issuer_org":  issuer_org,
        "issuer_name": issuer_name,
        "not_before":  not_before,
        "not_after":   not_after,
        "log_id":      raw.get("entry_timestamp", ""),
        "cluster_fp":  fp,
    }


def _extract_org(issuer_name: str) -> str:
    """Extract O= value from issuer DN string."""
    match = re.search(r"O=([^,]+)", issuer_name)
    if match:
        return match.group(1).strip().strip('"')
    # fallback: take first meaningful token
    parts = [p.strip() for p in issuer_name.split(",") if p.strip()]
    return parts[0] if parts else issuer_name or "Unknown"


def _cluster_by_timing(certs: list) -> list:
    """
    Group certs by issuer + registration month.
    Rapid cert issuance from same issuer in a short window = suspicious.
    """
    buckets = {}
    for cert in certs:
        key = cert["cluster_fp"]
        if key not in buckets:
            buckets[key] = {
                "issuer":   cert["issuer_org"],
                "month":    cert["not_before"][:7] if cert["not_before"] else "unknown",
                "certs":    [],
                "names":    set(),
            }
        buckets[key]["certs"].append(cert["id"])
        buckets[key]["names"].update(cert["names"])

    clusters = []
    for fp, bucket in buckets.items():
        bucket["cert_count"] = len(bucket["certs"])
        bucket["names"]      = sorted(bucket["names"])
        bucket["suspicious"]  = bucket["cert_count"] >= 3  # 3+ certs same issuer/month
        clusters.append(bucket)

    return sorted(clusters, key=lambda x: x["cert_count"], reverse=True)


def _summarise_issuers(issuers: dict) -> list:
    """Return issuers sorted by frequency."""
    return sorted(
        [{"issuer": k, "count": v} for k, v in issuers.items()],
        key=lambda x: x["count"],
        reverse=True
    )
