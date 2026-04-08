"""
crt.sh pivot — Certificate Transparency log queries.
No API key required. Queries the public crt.sh JSON API.

Fallback chain when crt.sh is unavailable:
  1. crt.sh (primary)
  2. CertSpotter (free, no key, 100/hour)
  3. Google CT (free, no key, no documented limit)

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
USER_AGENT  = "inframap/1.3 (github.com/rkbrainstorms/inframap; CTI research)"


def _fetch_crtsh(url: str, timeout: int, retries: int = 3) -> list:
    """Fetch crt.sh with retry logic."""
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise e
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(2 ** attempt)  # exponential backoff: 1s, 2s
                continue
            raise e
    return []


def pivot_crtsh(domain: str, timeout: int = 15, wildcard: bool = True) -> dict:
    """
    Query crt.sh for certificates associated with a domain.
    Automatically falls back to CertSpotter then Google CT on failure.
    """
    results = {
        "query":    domain,
        "wildcard": wildcard,
        "source":   "crt.sh",
        "certs":    [],
        "unique_names": set(),
        "issuers":  {},
        "timing_clusters": [],
        "errors":   []
    }

    queries = []
    if wildcard:
        queries.append(f"%.{domain}")
    queries.append(domain)

    raw_certs = []
    seen_ids  = set()
    crtsh_failed = False

    for q in queries:
        encoded = urllib.parse.quote(q, safe="")
        url     = CRT_SH_URL.format(query=encoded)
        try:
            data = _fetch_crtsh(url, timeout)
            for cert in data:
                cid = cert.get("id")
                if cid and cid not in seen_ids:
                    seen_ids.add(cid)
                    raw_certs.append(cert)
        except urllib.error.HTTPError as e:
            results["errors"].append(f"crt.sh HTTP {e.code} for query '{q}'")
            crtsh_failed = True
        except Exception as e:
            results["errors"].append(f"crt.sh error for query '{q}': {str(e)}")
            crtsh_failed = True
        time.sleep(0.3)

    # Fallback to CertSpotter if crt.sh failed
    if crtsh_failed and not raw_certs:
        results["errors"].append("crt.sh unavailable — trying CertSpotter fallback")
        try:
            from inframap.pivots.certfallback import pivot_certspotter
            fb = pivot_certspotter(domain, timeout=timeout)
            if fb.get("cert_count", 0) > 0:
                results["source"]       = "CertSpotter"
                results["unique_names"] = set(fb.get("unique_names", []))
                results["issuers"]      = fb.get("issuers", {})
                results["cert_count"]   = fb.get("cert_count", 0)
                results["certs"]        = fb.get("certs", [])
                results["timing_clusters"] = []
                results["errors"] = [e for e in results["errors"] if "crt.sh" not in e]
                results["errors"].append(f"used CertSpotter fallback ({fb['cert_count']} certs)")
                results["unique_names"] = sorted(results["unique_names"])
                return results
            else:
                results["errors"].extend(fb.get("errors", []))
        except Exception as e:
            results["errors"].append(f"CertSpotter fallback error: {str(e)}")

        # Final fallback: Google CT
        results["errors"].append("CertSpotter unavailable — trying Google CT fallback")
        try:
            from inframap.pivots.certfallback import pivot_google_ct
            fb = pivot_google_ct(domain, timeout=timeout)
            if fb.get("cert_count", 0) > 0:
                results["source"]       = "Google CT"
                results["unique_names"] = set(fb.get("unique_names", []))
                results["issuers"]      = fb.get("issuers", {})
                results["cert_count"]   = fb.get("cert_count", 0)
                results["certs"]        = fb.get("certs", [])
                results["timing_clusters"] = []
                results["errors"] = [e for e in results["errors"] if "crt.sh" not in e and "CertSpotter" not in e]
                results["errors"].append(f"used Google CT fallback ({fb['cert_count']} certs)")
                results["unique_names"] = sorted(results["unique_names"])
                return results
            else:
                results["errors"].extend(fb.get("errors", []))
        except Exception as e:
            results["errors"].append(f"Google CT fallback error: {str(e)}")  # be polite

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
