"""
Attribution engine — clustering and scoring.

cluster_certs():  Groups certificates by issuer/timing patterns.
                  Rapid cert issuance = infrastructure standing up fast.

cluster_whois():  Groups WHOIS fingerprints across domains.
                  Shared fingerprints = shared operator.

score_asn():      Combines AbuseIPDB + BGP.he.net into a single hosting risk score.
"""

from collections import defaultdict


def cluster_certs(crtsh_data: dict) -> dict:
    """
    Analyse cert clusters from crt.sh output.
    Returns summary of suspicious patterns (rapid issuance, shared issuers, wildcard abuse).
    """
    if not crtsh_data:
        return {"available": False}

    clusters    = crtsh_data.get("timing_clusters", [])
    all_names   = crtsh_data.get("unique_names", [])
    cert_count  = crtsh_data.get("cert_count", 0)

    suspicious_clusters  = [c for c in clusters if c.get("suspicious")]
    wildcard_names       = [n for n in all_names if n.startswith("*.")]
    onion_names          = [n for n in all_names if ".onion" in n]
    multi_level_wildcards= [n for n in wildcard_names if n.count(".") > 2]

    # Fast-spin detection: multiple certs in same month
    fast_spin = False
    for cluster in clusters:
        if cluster.get("cert_count", 0) >= 5:
            fast_spin = True
            break

    # Issuer diversity (high diversity = multiple CA accounts = operator spreading infra)
    issuers    = crtsh_data.get("issuers", {})
    issuer_div = len(issuers)

    findings = []
    if suspicious_clusters:
        findings.append(f"{len(suspicious_clusters)} cert cluster(s) with rapid issuance (≥3 certs/month)")
    if wildcard_names:
        findings.append(f"{len(wildcard_names)} wildcard SAN entries detected")
    if onion_names:
        findings.append(f"onion domain(s) in SAN: {', '.join(onion_names[:3])}")
    if multi_level_wildcards:
        findings.append(f"multi-level wildcards: {', '.join(multi_level_wildcards[:3])}")
    if fast_spin:
        findings.append("fast-spin detected: ≥5 certs issued in one month (rapid infra standup)")
    if issuer_div >= 4:
        findings.append(f"high issuer diversity ({issuer_div} CAs) — operator using multiple CA accounts")

    return {
        "available":           True,
        "cert_count":          cert_count,
        "unique_domains":      len(all_names),
        "suspicious_clusters": len(suspicious_clusters),
        "wildcard_count":      len(wildcard_names),
        "onion_count":         len(onion_names),
        "issuer_diversity":    issuer_div,
        "fast_spin":           fast_spin,
        "findings":            findings,
        "top_clusters":        clusters[:5],
        "all_names":           all_names,
    }


def cluster_whois(rdap_data: dict) -> dict:
    """
    Analyse WHOIS fingerprint from RDAP data.
    Returns registrant attribution indicators and confidence factors.
    """
    if not rdap_data:
        return {"available": False}

    fp       = rdap_data.get("whois_fp")
    privacy  = rdap_data.get("privacy", False)
    reg      = rdap_data.get("registrant", {})
    ns       = rdap_data.get("nameservers", [])
    dates    = rdap_data.get("dates", {})
    registrar= rdap_data.get("registrar")

    findings = []
    indicators = []

    # Privacy proxy
    if privacy:
        findings.append("registrant behind privacy proxy (reduces attribution confidence)")
        indicators.append("PRIVACY_PROTECTED")
    else:
        email = reg.get("email")
        org   = reg.get("org")
        name  = reg.get("name")
        if email:
            indicators.append(f"registrant email: {email}")
            findings.append(f"registrant email exposed: {email}")
        if org:
            indicators.append(f"registrant org: {org}")
        if name and name != org:
            indicators.append(f"registrant name: {name}")

    # Nameserver pattern analysis
    bp_ns_patterns = ["topdns", "njalla", "1984hosting", "privacyguardian",
                      "flokinet", "ddos-guard", "vdsina"]
    for ns_entry in ns:
        for pattern in bp_ns_patterns:
            if pattern in ns_entry.lower():
                findings.append(f"bulletproof/privacy NS detected: {ns_entry}")
                indicators.append(f"BP_NS:{ns_entry}")
                break

    # Domain age
    registered = dates.get("registration") or dates.get("registrationdate", "")
    if registered:
        try:
            from datetime import datetime, timezone
            reg_date  = datetime.fromisoformat(registered.replace("Z", "+00:00"))
            age_days  = (datetime.now(timezone.utc) - reg_date).days
            if age_days < 30:
                findings.append(f"newly registered domain ({age_days} days old) — high suspicion")
                indicators.append("NEWLY_REGISTERED")
            elif age_days < 90:
                findings.append(f"recently registered domain ({age_days} days old)")
        except Exception:
            pass

    # Registrar
    shady_registrars = ["njalla", "epik", "porkbun", "namecheap"]
    if registrar:
        for sr in shady_registrars:
            if sr in (registrar or "").lower():
                findings.append(f"registrar frequently used for privacy: {registrar}")
                break

    return {
        "available":    True,
        "whois_fp":     fp,
        "privacy":      privacy,
        "registrar":    registrar,
        "registrant":   reg,
        "nameservers":  ns,
        "dates":        dates,
        "findings":     findings,
        "indicators":   indicators,
    }


def score_asn(bgphe_data: dict, abuseip_data: dict) -> dict:
    """
    Combine BGP.he.net and AbuseIPDB into a single hosting risk score.
    """
    if not bgphe_data and not abuseip_data:
        return {"available": False}

    combined_score  = 0
    findings        = []

    # BGP component
    if bgphe_data and not bgphe_data.get("errors"):
        bp_score   = bgphe_data.get("bp_score", 0)
        combined_score += int(bp_score * 0.5)  # 50% weight
        findings.extend(bgphe_data.get("bp_indicators", []))

    # AbuseIPDB component
    if abuseip_data and not abuseip_data.get("errors"):
        abuse_score = abuseip_data.get("abuse_score") or 0
        combined_score += int(abuse_score * 0.5)  # 50% weight
        label = abuseip_data.get("confidence_label", "")
        if label in ("HIGH-RISK", "SUSPICIOUS"):
            findings.append(f"AbuseIPDB score {abuse_score}/100 ({label})")
        if abuseip_data.get("is_tor"):
            findings.append("IP is a known Tor exit node")
            combined_score += 20

    combined_score = min(combined_score, 100)

    if combined_score >= 60:
        label = "HIGH-RISK"
    elif combined_score >= 30:
        label = "SUSPICIOUS"
    elif combined_score > 0:
        label = "MODERATE"
    else:
        label = "CLEAN"

    return {
        "available":     True,
        "combined_score": combined_score,
        "label":         label,
        "asn":           bgphe_data.get("asn") if bgphe_data else None,
        "asn_name":      bgphe_data.get("asn_name") if bgphe_data else None,
        "country":       bgphe_data.get("country") if bgphe_data else abuseip_data.get("country") if abuseip_data else None,
        "bp_label":      bgphe_data.get("bp_label") if bgphe_data else None,
        "abuse_score":   abuseip_data.get("abuse_score") if abuseip_data else None,
        "findings":      findings,
    }
