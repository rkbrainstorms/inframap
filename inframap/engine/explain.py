"""
Confidence score explanation — show analysts exactly what drove the score.

No API key required. Uses existing scoring data.

The confidence score has been a black box. This module opens it up:
  - Shows which signals contributed which points
  - Explains why each signal matters
  - Lists what would change the score
  - Makes the tool auditable and trustworthy
"""


SIGNAL_EXPLANATIONS = {
    "fast_cert_spin": {
        "points":  20,
        "signal":  "Certificate fast-spin",
        "why":     "≥5 TLS certs issued in one month = rapid infrastructure standup, not normal business",
        "context": "Threat actors spin up phishing kits fast. Multiple certs in short time = operational activity"
    },
    "cert_cluster": {
        "points":  15,
        "signal":  "Cert issuance cluster",
        "why":     "Multiple certs issued in the same short window by the same issuer",
        "context": "Legitimate domains rarely need cert clusters. Attackers do — for each phishing subdomain"
    },
    "wildcard_cert": {
        "points":  10,
        "signal":  "Wildcard SAN certificate",
        "why":     "*.domain.com cert covers unlimited subdomains — common in phishing platforms",
        "context": "AiTM platforms use wildcards to serve victim-specific pages at victim.phishingdomain.com"
    },
    "urlscan_hits": {
        "points":  15,
        "signal":  "urlscan.io scan history",
        "why":     "High scan count = active security community flagging",
        "context": "Legitimate domains don't get mass-scanned. This indicates the domain is under investigation"
    },
    "abuseipdb_high": {
        "points":  25,
        "signal":  "AbuseIPDB high score",
        "why":     "IP reported multiple times for abuse by the security community",
        "context": "Direct evidence of malicious activity from independent reporters"
    },
    "bulletproof_asn": {
        "points":  20,
        "signal":  "Bulletproof ASN",
        "why":     "Hosting provider known for ignoring abuse complaints",
        "context": "Threat actors deliberately choose these providers to avoid takedowns"
    },
    "privacy_whois": {
        "points":  5,
        "signal":  "WHOIS privacy protection",
        "why":     "Registrant identity hidden behind privacy service",
        "context": "Weak signal alone — combined with others indicates deliberate obfuscation"
    },
    "newly_registered": {
        "points":  10,
        "signal":  "Newly registered domain",
        "why":     "Domain registered in last 30 days with no history",
        "context": "Phishing domains are typically registered days before use"
    },
    "vt_malicious": {
        "points":  20,
        "signal":  "VirusTotal malicious verdict",
        "why":     "Multiple AV/security vendors independently flag as malicious",
        "context": "Strong corroborating signal — independent detection from 94 security companies"
    },
    "phishing_score": {
        "points":  25,
        "signal":  "Phishing infrastructure score",
        "why":     "Multiple phishing kit signals detected simultaneously",
        "context": "Combination of cert patterns, brand keywords, and infrastructure signals"
    },
    "threatfox_match": {
        "points":  30,
        "signal":  "ThreatFox IOC match",
        "why":     "IOC directly matches known malware campaign in ThreatFox database",
        "context": "Definitive confirmation — this IOC is already associated with active malware"
    },
    "liveness": {
        "points":  10,
        "signal":  "Infrastructure currently live",
        "why":     "IOCs are actively responding — infrastructure is operational",
        "context": "Confirms ongoing threat, not historical artifact"
    }
}


def explain_score(report: dict, pivot_results: dict = None) -> dict:
    """
    Generate a detailed explanation of the confidence score.
    Returns a structured explanation with signal breakdown.
    """
    findings   = report.get("findings", [])
    infra      = report.get("infrastructure", {})
    attr       = report.get("attribution", {})
    score      = attr.get("confidence_score", 0)

    explanation = {
        "total_score":    score,
        "tier":           attr.get("tier_label", "UNKNOWN"),
        "signals_found":  [],
        "signals_missing": [],
        "what_would_increase": [],
        "partial_data":   attr.get("partial_data", False),
        "partial_note":   attr.get("partial_note", "")
    }

    found_signal_keys = set()

    # Map findings to signal keys
    for finding in findings:
        text   = finding.get("text", "").lower()
        source = finding.get("source", "").lower()
        conf   = finding.get("confidence", "")

        if "fast-spin" in text:
            found_signal_keys.add("fast_cert_spin")
        if "cluster" in text and "cert" in text:
            found_signal_keys.add("cert_cluster")
        if "wildcard" in text:
            found_signal_keys.add("wildcard_cert")
        if "urlscan" in source and "scan" in text:
            found_signal_keys.add("urlscan_hits")
        if "abuseipdb" in source:
            found_signal_keys.add("abuseipdb_high")
        if "bulletproof" in text or "shady" in text:
            found_signal_keys.add("bulletproof_asn")
        if "virustotal" in source and "malicious" in text:
            found_signal_keys.add("vt_malicious")
        if "phishing" in source and "100" in text:
            found_signal_keys.add("phishing_score")
        if "threatfox" in source:
            found_signal_keys.add("threatfox_match")
        if "liveness" in source and "live" in text:
            found_signal_keys.add("liveness")

    # Check infrastructure
    if infra.get("phishing_score", 0) >= 60:
        found_signal_keys.add("phishing_score")
    if infra.get("malware_families"):
        found_signal_keys.add("threatfox_match")

    # Build signal breakdown
    for key in found_signal_keys:
        if key in SIGNAL_EXPLANATIONS:
            sig = SIGNAL_EXPLANATIONS[key].copy()
            sig["key"] = key
            explanation["signals_found"].append(sig)

    # What's missing
    all_keys = set(SIGNAL_EXPLANATIONS.keys())
    missing  = all_keys - found_signal_keys
    for key in missing:
        sig = SIGNAL_EXPLANATIONS[key]
        explanation["signals_missing"].append({
            "key":    key,
            "signal": sig["signal"],
            "points": sig["points"],
            "why":    sig["why"]
        })
        if sig["points"] >= 15:
            explanation["what_would_increase"].append(
                f"+{sig['points']} if {sig['signal'].lower()} detected"
            )

    # Sort by points descending
    explanation["signals_found"].sort(key=lambda x: x["points"], reverse=True)
    explanation["what_would_increase"].sort(
        key=lambda x: int(x.split("+")[1].split(" ")[0]),
        reverse=True
    )

    return explanation


def format_explanation(explanation: dict) -> str:
    """Format score explanation for terminal output."""
    lines = []
    lines.append("")
    lines.append("  CONFIDENCE SCORE BREAKDOWN")
    lines.append("  " + "─" * 62)
    lines.append(f"  Total: {explanation['total_score']}/100 — {explanation['tier']}")

    if explanation.get("partial_data"):
        lines.append(f"  ⚠ {explanation.get('partial_note', 'partial data')}")

    lines.append("")
    lines.append("  SIGNALS DETECTED:")
    for sig in explanation["signals_found"]:
        lines.append(f"  +{sig['points']:>3}  {sig['signal']}")
        lines.append(f"       {sig['why']}")

    if explanation["what_would_increase"]:
        lines.append("")
        lines.append("  WHAT WOULD INCREASE THE SCORE:")
        for w in explanation["what_would_increase"][:5]:
            lines.append(f"  {w}")

    lines.append("")
    return "\n".join(lines)
