"""
WHOIS cluster comparison — shared operator detection.
Compare two or more domains and output a confidence score for shared infrastructure/operator.

This is the genuinely novel feature — no other free CLI tool does this.
Used in CTI investigations to link separate domains to the same threat actor.
"""

import hashlib
from difflib import SequenceMatcher


def compare_domains(rdap_a: dict, rdap_b: dict,
                    crtsh_a: dict = None, crtsh_b: dict = None,
                    passivedns_a: dict = None, passivedns_b: dict = None) -> dict:
    """
    Compare two domains' infrastructure fingerprints and return a
    shared-operator confidence score with documented evidence.

    Score interpretation:
      80-100: Almost certainly same operator
      60-79:  Likely same operator (ANALYST ASSESSMENT)
      40-59:  Possible shared infrastructure
      20-39:  Weak signal, coincidental overlap likely
      0-19:   No meaningful overlap
    """
    result = {
        "domain_a":       rdap_a.get("domain", "domain_a"),
        "domain_b":       rdap_b.get("domain", "domain_b"),
        "shared_score":   0,
        "confidence_label": None,
        "shared_indicators": [],
        "differences":    [],
        "verdict":        None,
    }

    score = 0
    indicators  = []
    differences = []

    # ── 1. WHOIS fingerprint exact match ──────────────────────────
    fp_a = rdap_a.get("whois_fp")
    fp_b = rdap_b.get("whois_fp")
    if fp_a and fp_b:
        if fp_a == fp_b:
            score += 40
            indicators.append("WHOIS fingerprints are identical — same registrant profile")
        else:
            differences.append(f"WHOIS fingerprints differ: {fp_a} vs {fp_b}")

    # ── 2. Registrar match ─────────────────────────────────────────
    reg_a = (rdap_a.get("registrar") or "").lower().strip()
    reg_b = (rdap_b.get("registrar") or "").lower().strip()
    if reg_a and reg_b:
        if reg_a == reg_b:
            score += 10
            indicators.append(f"same registrar: {rdap_a.get('registrar')}")
        else:
            differences.append(f"different registrars: {reg_a} vs {reg_b}")

    # ── 3. Registrant email match ──────────────────────────────────
    email_a = (rdap_a.get("registrant", {}).get("email") or "").lower().strip()
    email_b = (rdap_b.get("registrant", {}).get("email") or "").lower().strip()
    if email_a and email_b and not _is_privacy(email_a) and not _is_privacy(email_b):
        if email_a == email_b:
            score += 35
            indicators.append(f"identical registrant email: {email_a}")
        else:
            # Check if same domain in email
            domain_a_email = email_a.split("@")[-1] if "@" in email_a else ""
            domain_b_email = email_b.split("@")[-1] if "@" in email_b else ""
            if domain_a_email and domain_a_email == domain_b_email:
                score += 15
                indicators.append(f"registrant emails share domain: @{domain_a_email}")
            else:
                differences.append(f"different registrant emails")

    # ── 4. Registrant org match ────────────────────────────────────
    org_a = (rdap_a.get("registrant", {}).get("org") or "").lower().strip()
    org_b = (rdap_b.get("registrant", {}).get("org") or "").lower().strip()
    if org_a and org_b and not _is_privacy(org_a) and not _is_privacy(org_b):
        similarity = SequenceMatcher(None, org_a, org_b).ratio()
        if org_a == org_b:
            score += 20
            indicators.append(f"identical registrant org: {org_a}")
        elif similarity > 0.8:
            score += 10
            indicators.append(f"similar registrant org ({int(similarity*100)}% match): '{org_a}' vs '{org_b}'")

    # ── 5. Nameserver overlap ──────────────────────────────────────
    ns_a = set(rdap_a.get("nameservers", []))
    ns_b = set(rdap_b.get("nameservers", []))
    shared_ns = ns_a & ns_b
    if shared_ns:
        # Filter out mega-providers where NS overlap is meaningless
        meaningful_ns = {ns for ns in shared_ns
                        if not any(p in ns for p in
                                   ["cloudflare", "awsdns", "azure-dns",
                                    "googledomains", "domaincontrol"])}
        if meaningful_ns:
            score += 15
            indicators.append(f"shared nameservers: {', '.join(sorted(meaningful_ns))}")
        else:
            indicators.append(f"shared NS but major provider ({', '.join(sorted(shared_ns))}) — low signal")

    # ── 6. Certificate issuer overlap ─────────────────────────────
    if crtsh_a and crtsh_b:
        issuers_a = set(i["issuer"] for i in crtsh_a.get("issuer_summary", []))
        issuers_b = set(i["issuer"] for i in crtsh_b.get("issuer_summary", []))
        shared_issuers = issuers_a & issuers_b
        # Only meaningful if non-standard issuers (not Let's Encrypt which everyone uses)
        meaningful_issuers = {i for i in shared_issuers
                             if "let's encrypt" not in i.lower()
                             and "digicert" not in i.lower()
                             and "sectigo" not in i.lower()}
        if meaningful_issuers:
            score += 10
            indicators.append(f"shared uncommon cert issuer(s): {', '.join(meaningful_issuers)}")

        # Domain name overlap in SANs
        names_a = set(crtsh_a.get("unique_names", []))
        names_b = set(crtsh_b.get("unique_names", []))
        shared_names = names_a & names_b
        if shared_names and len(shared_names) > 1:
            score += 15
            indicators.append(f"{len(shared_names)} shared domain(s) in cert SANs")

    # ── 7. Passive DNS IP overlap ──────────────────────────────────
    if passivedns_a and passivedns_b:
        ips_a = set(passivedns_a.get("unique_ips", []))
        ips_b = set(passivedns_b.get("unique_ips", []))
        shared_ips = ips_a & ips_b
        if shared_ips:
            score += 20
            indicators.append(f"{len(shared_ips)} shared IP(s) in passive DNS history: "
                             f"{', '.join(sorted(shared_ips)[:3])}")

        # Shared co-hosted domains
        hosts_a = set(passivedns_a.get("shared_hosts", []))
        hosts_b = set(passivedns_b.get("shared_hosts", []))
        shared_cohosted = hosts_a & hosts_b
        if shared_cohosted:
            score += 15
            indicators.append(f"co-hosted on same infrastructure: "
                             f"{', '.join(sorted(shared_cohosted)[:3])}")

    # ── Final scoring ──────────────────────────────────────────────
    score = min(score, 100)
    result["shared_score"]      = score
    result["shared_indicators"] = indicators
    result["differences"]       = differences

    if score >= 80:
        label   = "CONFIRMED — same operator"
        verdict = "These domains almost certainly share the same operator or infrastructure owner."
    elif score >= 60:
        label   = "ANALYST ASSESSMENT — likely same operator"
        verdict = "Evidence strongly suggests shared operator. Treat as working hypothesis."
    elif score >= 40:
        label   = "CIRCUMSTANTIAL — possible shared infrastructure"
        verdict = "Some overlap detected. May indicate shared hosting or operator. Needs corroboration."
    elif score >= 20:
        label   = "WEAK SIGNAL — coincidental overlap likely"
        verdict = "Minor overlap only. Insufficient for attribution."
    else:
        label   = "NO OVERLAP"
        verdict = "No meaningful shared infrastructure detected."

    result["confidence_label"] = label
    result["verdict"]          = verdict

    return result


def _is_privacy(value: str) -> bool:
    """Check if a registrant field is a privacy proxy value."""
    privacy_keywords = ["privacy", "whoisguard", "protected", "redacted",
                       "withheld", "proxy", "domains by proxy", "perfect privacy",
                       "contact privacy", "registrant"]
    return any(k in value.lower() for k in privacy_keywords)
