"""
WHOIS cluster comparison — shared operator detection.
Compare two or more domains and output a confidence score.

v1.2: Added IP subnet overlap scoring — catches campaign-level links
even when registrant data differs (e.g. onmicrosoft.co vs topdns.com
share the 212.92.104.x range but have different registrants).
"""

import hashlib
import ipaddress
from difflib import SequenceMatcher


def compare_domains(rdap_a: dict, rdap_b: dict,
                    crtsh_a: dict = None, crtsh_b: dict = None,
                    passivedns_a: dict = None, passivedns_b: dict = None,
                    urlscan_a: dict = None, urlscan_b: dict = None) -> dict:
    """
    Compare two domains for shared operator.
    Score 0-100: 80+ = same operator, 60-79 = likely same, 40-59 = possible.
    """
    result = {
        "domain_a":         rdap_a.get("domain", "domain_a"),
        "domain_b":         rdap_b.get("domain", "domain_b"),
        "shared_score":     0,
        "confidence_label": None,
        "shared_indicators": [],
        "differences":      [],
        "verdict":          None,
    }

    score      = 0
    indicators = []
    differences= []

    # ── 1. WHOIS fingerprint ───────────────────────────────────────
    fp_a = rdap_a.get("whois_fp")
    fp_b = rdap_b.get("whois_fp")
    if fp_a and fp_b:
        if fp_a == fp_b:
            score += 40
            indicators.append("WHOIS fingerprints identical — same registrant profile")
        else:
            differences.append(f"WHOIS fingerprints differ: {fp_a} vs {fp_b}")

    # ── 2. Registrar ───────────────────────────────────────────────
    reg_a = (rdap_a.get("registrar") or "").lower().strip()
    reg_b = (rdap_b.get("registrar") or "").lower().strip()
    if reg_a and reg_b:
        if reg_a == reg_b:
            score += 10
            indicators.append(f"same registrar: {rdap_a.get('registrar')}")
        else:
            differences.append(f"different registrars: {reg_a} vs {reg_b}")

    # ── 3. Registrant email ────────────────────────────────────────
    email_a = (rdap_a.get("registrant", {}).get("email") or "").lower().strip()
    email_b = (rdap_b.get("registrant", {}).get("email") or "").lower().strip()
    if email_a and email_b and not _is_privacy(email_a) and not _is_privacy(email_b):
        if email_a == email_b:
            score += 35
            indicators.append(f"identical registrant email: {email_a}")
        else:
            ea_domain = email_a.split("@")[-1] if "@" in email_a else ""
            eb_domain = email_b.split("@")[-1] if "@" in email_b else ""
            if ea_domain and ea_domain == eb_domain:
                score += 15
                indicators.append(f"registrant emails share domain: @{ea_domain}")
            else:
                differences.append("different registrant emails")

    # ── 4. Registrant org ──────────────────────────────────────────
    org_a = (rdap_a.get("registrant", {}).get("org") or "").lower().strip()
    org_b = (rdap_b.get("registrant", {}).get("org") or "").lower().strip()
    if org_a and org_b and not _is_privacy(org_a) and not _is_privacy(org_b):
        similarity = SequenceMatcher(None, org_a, org_b).ratio()
        if org_a == org_b:
            score += 20
            indicators.append(f"identical registrant org: {org_a}")
        elif similarity > 0.8:
            score += 10
            indicators.append(f"similar registrant org ({int(similarity*100)}%): '{org_a}' vs '{org_b}'")

    # ── 5. Nameserver overlap ──────────────────────────────────────
    ns_a = set(rdap_a.get("nameservers", []))
    ns_b = set(rdap_b.get("nameservers", []))
    shared_ns = ns_a & ns_b
    if shared_ns:
        mega_providers = ["cloudflare", "awsdns", "azure-dns",
                         "googledomains", "domaincontrol", "registrar-servers"]
        meaningful_ns = {ns for ns in shared_ns
                        if not any(p in ns for p in mega_providers)}
        if meaningful_ns:
            score += 20
            indicators.append(f"shared nameservers: {', '.join(sorted(meaningful_ns))}")
        else:
            indicators.append(f"shared NS but major provider ({', '.join(sorted(shared_ns))}) — low signal")

    # ── 6. Cert issuer + SAN overlap ──────────────────────────────
    if crtsh_a and crtsh_b:
        issuers_a = set(i["issuer"] for i in crtsh_a.get("issuer_summary", []))
        issuers_b = set(i["issuer"] for i in crtsh_b.get("issuer_summary", []))
        shared_issuers = issuers_a & issuers_b
        mega_issuers = {"let's encrypt", "digicert", "sectigo", "comodo", "godaddy"}
        meaningful_issuers = {i for i in shared_issuers
                             if not any(m in i.lower() for m in mega_issuers)}
        if meaningful_issuers:
            score += 10
            indicators.append(f"shared uncommon cert issuer(s): {', '.join(meaningful_issuers)}")

        names_a = set(crtsh_a.get("unique_names", []))
        names_b = set(crtsh_b.get("unique_names", []))
        shared_names = names_a & names_b
        if len(shared_names) > 1:
            score += 15
            indicators.append(f"{len(shared_names)} shared domain(s) in cert SANs")

    # ── 7. Passive DNS IP overlap ──────────────────────────────────
    if passivedns_a and passivedns_b:
        ips_a = set(passivedns_a.get("unique_ips", []))
        ips_b = set(passivedns_b.get("unique_ips", []))
        shared_ips = ips_a & ips_b
        if shared_ips:
            score += 25
            indicators.append(f"{len(shared_ips)} identical IP(s) in passive DNS: "
                             f"{', '.join(sorted(shared_ips)[:3])}")

        hosts_a = set(passivedns_a.get("shared_hosts", []))
        hosts_b = set(passivedns_b.get("shared_hosts", []))
        shared_cohosted = hosts_a & hosts_b
        if shared_cohosted:
            score += 15
            indicators.append(f"co-hosted on same infrastructure: "
                             f"{', '.join(sorted(shared_cohosted)[:3])}")

    # ── 8. IP subnet overlap (NEW) ─────────────────────────────────
    # This catches campaign-level links where registrant data differs
    # but infrastructure is shared (e.g. same /24 IP range)
    ips_a_all = set()
    ips_b_all = set()

    if passivedns_a:
        ips_a_all.update(passivedns_a.get("unique_ips", []))
    if passivedns_b:
        ips_b_all.update(passivedns_b.get("unique_ips", []))
    if urlscan_a:
        ips_a_all.update(urlscan_a.get("ips_seen", []))
    if urlscan_b:
        ips_b_all.update(urlscan_b.get("ips_seen", []))

    # Check /24 subnet overlap
    subnets_a = _get_subnets(ips_a_all)
    subnets_b = _get_subnets(ips_b_all)
    shared_subnets = subnets_a & subnets_b

    if shared_subnets:
        # Filter out mega-provider subnets
        meaningful_subnets = {s for s in shared_subnets
                             if not _is_mega_provider_subnet(s)}
        if meaningful_subnets:
            score += 25
            indicators.append(
                f"shared IP subnet(s) /24: {', '.join(sorted(meaningful_subnets)[:3])} "
                f"— infrastructure overlap"
            )

    # ── Final scoring ──────────────────────────────────────────────
    score = min(score, 100)
    result["shared_score"]       = score
    result["shared_indicators"]  = indicators
    result["differences"]        = differences

    if score >= 80:
        label   = "CONFIRMED — same operator"
        verdict = "These domains almost certainly share the same operator or infrastructure."
    elif score >= 60:
        label   = "ANALYST ASSESSMENT — likely same operator"
        verdict = "Strong evidence of shared operator. Treat as working hypothesis."
    elif score >= 40:
        label   = "CIRCUMSTANTIAL — possible shared infrastructure"
        verdict = "Some overlap detected. May indicate shared hosting or operator."
    elif score >= 20:
        label   = "WEAK SIGNAL — coincidental overlap likely"
        verdict = "Minor overlap. Insufficient for attribution."
    else:
        label   = "NO OVERLAP"
        verdict = "No meaningful shared infrastructure detected."

    result["confidence_label"] = label
    result["verdict"]          = verdict

    return result


def _get_subnets(ips: set) -> set:
    """Extract /24 subnets from a set of IP addresses."""
    subnets = set()
    for ip in ips:
        try:
            # Skip IPv6 for subnet comparison
            if ":" in ip:
                continue
            network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            subnets.add(str(network))
        except Exception:
            continue
    return subnets


def _is_mega_provider_subnet(subnet: str) -> bool:
    """Check if a subnet belongs to a major cloud provider."""
    # Cloudflare ranges
    cloudflare = ["104.16.", "104.17.", "104.18.", "104.19.",
                  "104.20.", "104.21.", "172.64.", "172.65.",
                  "172.66.", "172.67.", "188.114.", "198.41."]
    # Google ranges
    google = ["142.250.", "142.251.", "172.253.", "216.58.",
              "74.125.", "34.0.", "35.0."]
    # AWS ranges (approximate)
    aws = ["54.0.", "52.0.", "18.0.", "3.0.", "44.0."]

    for prefix in cloudflare + google + aws:
        if subnet.startswith(prefix):
            return True
    return False


def _is_privacy(value: str) -> bool:
    privacy_keywords = ["privacy", "whoisguard", "protected", "redacted",
                       "withheld", "proxy", "domains by proxy",
                       "perfect privacy", "contact privacy", "registrant"]
    return any(k in value.lower() for k in privacy_keywords)
