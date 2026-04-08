"""
Attribution confidence engine.

Synthesises all pivot data into a structured report with explicit
confidence tiers for each finding:

  CONFIRMED         — multiple independent corroborating sources
  ANALYST ASSESSMENT — single-source or inferred, documented basis
  CIRCUMSTANTIAL    — pattern match only, low specificity

This mirrors the analytic standards used in professional CTI reports.
"""

from datetime import datetime, timezone


CONFIDENCE_WEIGHTS = {
    "cert_cluster_match":   30,
    "whois_fp_match":       30,
    "urlscan_ip_seen":       5,   # per IP, capped — high hits on legit domains shouldn't max score
    "urlscan_ip_cap":       20,   # maximum contribution from urlscan IPs
    "asn_high_risk":        20,
    "abuseip_high":         20,
    "newly_registered":     15,
    "privacy_ns":           10,
    "fast_spin":            15,
    "onion_in_san":         25,
}

# Known-clean ASN prefixes — large legitimate providers
# High urlscan hits from these should NOT increase malicious confidence
KNOWN_CLEAN_ASNS = {
    "AS15169",  # Google
    "AS8075",   # Microsoft
    "AS16509",  # Amazon AWS
    "AS14618",  # Amazon
    "AS13335",  # Cloudflare
    "AS20940",  # Akamai
    "AS54113",  # Fastly
    "AS16625",  # Akamai
    "AS22822",  # Limelight
    "AS396982", # Google Cloud
    "AS19551",  # Incapsula/Imperva
    "AS209242", # Cloudflare
}

# Known-clean domain keywords — if seed matches, dampen confidence
KNOWN_CLEAN_DOMAINS = [
    "google", "microsoft", "amazon", "facebook", "apple", "twitter",
    "cloudflare", "akamai", "fastly", "github", "youtube", "instagram",
    "linkedin", "netflix", "adobe", "salesforce", "dropbox", "slack"
]


def build_confidence_report(
    domain: str = None,
    ip: str = None,
    cert_clusters: dict = None,
    whois_clusters: dict = None,
    asn_score: dict = None,
    pivot_results: dict = None,
    depth2: dict = None
) -> dict:
    """
    Build the final attribution report.
    Returns a structured dict ready for all output formatters.
    """
    report = {
        "meta": {
            "generated":   datetime.now(timezone.utc).isoformat(),
            "seed_domain": domain,
            "seed_ip":     ip,
            "tool":        "inframap v1.0",
            "sources_used": []
        },
        "attribution": {
            "confidence_score":  0,
            "confidence_tier":   None,
            "tier_label":        None,
            "summary":           [],
        },
        "findings":     [],
        "iocs":         [],
        "infrastructure": {},
        "errors":       [],
        "raw": {
            "cert_clusters":  cert_clusters,
            "whois_clusters": whois_clusters,
            "asn_score":      asn_score,
        }
    }

    score = 0

    # ── Infrastructure summary ──────────────────────────────────────
    infra = report["infrastructure"]
    iocs  = report["iocs"]
    errs  = report["errors"]

    # Seed IOCs
    if domain:
        iocs.append(_ioc("domain", domain, "seed"))
    if ip:
        iocs.append(_ioc("ip", ip, "seed"))

    # Cert data
    if cert_clusters and cert_clusters.get("available"):
        report["meta"]["sources_used"].append("crt.sh")
        infra["cert_count"]     = cert_clusters.get("cert_count", 0)
        infra["unique_domains"] = cert_clusters.get("unique_domains", 0)

        for name in cert_clusters.get("all_names", [])[:50]:
            if name and name != domain:
                iocs.append(_ioc("domain", name, "crt.sh"))

        for finding in cert_clusters.get("findings", []):
            conf = "ANALYST ASSESSMENT"
            if "rapid issuance" in finding or "fast-spin" in finding:
                conf = "CONFIRMED"
                score += CONFIDENCE_WEIGHTS["cert_cluster_match"]
            if "onion" in finding:
                score += CONFIDENCE_WEIGHTS["onion_in_san"]
                conf = "CONFIRMED"
            if "fast-spin" in finding:
                score += CONFIDENCE_WEIGHTS["fast_spin"]
            report["findings"].append(_finding(finding, conf, "crt.sh"))

    # WHOIS data
    if whois_clusters and whois_clusters.get("available"):
        report["meta"]["sources_used"].append("RDAP")
        infra["whois_fp"]        = whois_clusters.get("whois_fp")
        infra["registrar"]       = whois_clusters.get("registrar")
        infra["privacy"]         = whois_clusters.get("privacy")
        infra["domain_age_days"] = (pivot_results or {}).get("rdap", {}).get("domain_age_days")

        reg = whois_clusters.get("registrant", {})
        if reg.get("email"):
            iocs.append(_ioc("email", reg["email"], "RDAP"))
        if reg.get("org"):
            iocs.append(_ioc("registrant_org", reg["org"], "RDAP"))

        for ns in whois_clusters.get("nameservers", []):
            iocs.append(_ioc("nameserver", ns, "RDAP"))

        for finding in whois_clusters.get("findings", []):
            conf = "ANALYST ASSESSMENT"
            if "newly registered" in finding:
                score += CONFIDENCE_WEIGHTS["newly_registered"]
                conf = "CONFIRMED"
            if "bulletproof" in finding.lower() or "BP_NS" in finding:
                score += CONFIDENCE_WEIGHTS["privacy_ns"]
            report["findings"].append(_finding(finding, conf, "RDAP"))

    # urlscan data
    urlscan_data = (pivot_results or {}).get("urlscan", {})
    if urlscan_data and urlscan_data.get("scan_count", 0) > 0:
        report["meta"]["sources_used"].append("urlscan.io")
        infra["urlscan_hits"] = urlscan_data.get("scan_count", 0)
        infra["countries"]    = urlscan_data.get("countries", [])

        # Check if discovered ASNs are all known-clean (e.g. querying google.com)
        discovered_asns  = set(urlscan_data.get("asns_seen", []))
        clean_asns       = discovered_asns & KNOWN_CLEAN_ASNS
        all_clean        = len(clean_asns) == len(discovered_asns) and len(discovered_asns) > 0
        unknown_ips      = []

        for seen_ip in urlscan_data.get("ips_seen", []):
            iocs.append(_ioc("ip", seen_ip, "urlscan.io"))

        # Only score IPs if they're not all from known-clean providers
        if not all_clean:
            ip_score = min(
                len(urlscan_data.get("ips_seen", [])) * CONFIDENCE_WEIGHTS["urlscan_ip_seen"],
                CONFIDENCE_WEIGHTS["urlscan_ip_cap"]
            )
            score += ip_score

        for asn in urlscan_data.get("asns_seen", []):
            iocs.append(_ioc("asn", asn, "urlscan.io"))

        scan_count = urlscan_data.get("scan_count", 0)
        if scan_count > 0:
            clean_note = " (majority from known-clean providers)" if all_clean else ""
            report["findings"].append(_finding(
                f"{scan_count} existing scan(s) found on urlscan.io{clean_note}",
                "CONFIRMED" if scan_count > 5 else "ANALYST ASSESSMENT",
                "urlscan.io"
            ))

    # ASN / hosting data
    if asn_score and asn_score.get("available"):
        sources_used = []
        if (pivot_results or {}).get("bgphe"):
            sources_used.append("BGP.he.net")
        if (pivot_results or {}).get("abuseip"):
            sources_used.append("AbuseIPDB")
        report["meta"]["sources_used"].extend(sources_used)

        infra["asn"]         = asn_score.get("asn")
        infra["asn_name"]    = asn_score.get("asn_name")
        infra["country"]     = asn_score.get("country")
        infra["hosting_risk"]= asn_score.get("label")
        infra["abuse_score"] = asn_score.get("abuse_score")

        if asn_score.get("combined_score", 0) >= 60:
            score += CONFIDENCE_WEIGHTS["asn_high_risk"]

        for finding in asn_score.get("findings", []):
            conf = "ANALYST ASSESSMENT"
            if "known bulletproof" in finding.lower():
                conf = "CONFIRMED"
                score += CONFIDENCE_WEIGHTS["asn_high_risk"]
            report["findings"].append(_finding(finding, conf, " / ".join(sources_used) or "BGP.he.net"))

        if (asn_score.get("abuse_score") or 0) >= 80:
            score += CONFIDENCE_WEIGHTS["abuseip_high"]

    # ── Legitimacy dampening ────────────────────────────────────────
    # Only dampen if the seed IS the known-clean domain itself
    # e.g. google.com = dampen, but evil-google.com or onmicrosoft.co = do NOT dampen
    if domain:
        domain_lower = domain.lower()
        # Strip www. prefix for comparison
        domain_stripped = domain_lower.lstrip("www.")
        for clean in KNOWN_CLEAN_DOMAINS:
            # Must be exact match or direct subdomain: google.com or mail.google.com
            # NOT typosquats like google.co, google-login.com, onmicrosoft.co
            if domain_stripped == clean + ".com" or \
               domain_stripped == clean + ".org" or \
               domain_stripped == clean + ".net" or \
               domain_stripped.endswith("." + clean + ".com"):
                score = min(score, 30)
                report["findings"].append(_finding(
                    f"seed domain is known-clean brand '{clean}' — confidence capped",
                    "CIRCUMSTANTIAL",
                    "inframap"
                ))
                break

    # ── Overall confidence tier ──────────────────────────────────────
    score = min(score, 100)
    report["attribution"]["confidence_score"] = score

    # Detect partial data — if crt.sh failed, note it affects score
    crtsh_data    = (pivot_results or {}).get("crtsh", {})
    crtsh_errors  = crtsh_data.get("errors", [])
    crtsh_partial = crtsh_data.get("cert_count", 0) == 0 and len(crtsh_errors) > 0
    if crtsh_partial:
        report["attribution"]["partial_data"] = True
        report["attribution"]["partial_note"] = (
            "crt.sh unavailable during this run — cert signals missing. "
            "Score may be lower than actual. Re-run when crt.sh recovers."
        )
    else:
        report["attribution"]["partial_data"] = False

    if score >= 70:
        tier  = "HIGH"
        label = "CONFIRMED"
        summary = "Multiple independent indicators corroborate infrastructure attribution."
    elif score >= 40:
        tier  = "MEDIUM"
        label = "ANALYST ASSESSMENT"
        summary = "Attribution is supported by analyst assessment with documented evidence basis."
    elif score > 0:
        tier  = "LOW"
        label = "CIRCUMSTANTIAL"
        summary = "Pattern matches only. Treat as lead for further investigation."
    else:
        tier  = "NONE"
        label = "INSUFFICIENT DATA"
        summary = "Insufficient data returned. Check API keys or try additional seeds."

    report["attribution"]["confidence_tier"]  = tier
    report["attribution"]["tier_label"]       = label
    report["attribution"]["summary"]          = summary

    # Deduplicate IOCs
    report["iocs"] = _dedup_iocs(iocs)

    # Collect all errors
    for src, data in (pivot_results or {}).items():
        if isinstance(data, dict):
            for err in data.get("errors", []):
                report["errors"].append({"source": src, "error": err})

    return report


# ── Helpers ──────────────────────────────────────────────────────────

def _finding(text: str, confidence: str, source: str) -> dict:
    return {"text": text, "confidence": confidence, "source": source}


def _ioc(ioc_type: str, value: str, source: str) -> dict:
    """Create a defanged IOC entry."""
    defanged = _defang(value, ioc_type)
    return {
        "type":     ioc_type,
        "value":    value,
        "defanged": defanged,
        "source":   source,
    }


def _defang(value: str, ioc_type: str) -> str:
    """Standard CTI defanging."""
    if ioc_type in ("domain", "url", "nameserver"):
        return value.replace(".", "[.]")
    elif ioc_type == "ip":
        return value.replace(".", "[.]")
    elif ioc_type == "email":
        return value.replace("@", "[@]").replace(".", "[.]")
    return value


def _dedup_iocs(iocs: list) -> list:
    """Remove duplicate IOCs, keeping highest-priority source."""
    seen = {}
    for ioc in iocs:
        key = (ioc["type"], ioc["value"].lower())
        if key not in seen:
            seen[key] = ioc
        else:
            # Prefer seed-sourced entries
            if ioc["source"] == "seed":
                seen[key] = ioc
    return list(seen.values())
