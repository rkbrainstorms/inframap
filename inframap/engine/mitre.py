"""
MITRE ATT&CK mapping — map inframap findings to ATT&CK techniques.

No API key required. Static mapping table.

Maps observed infrastructure signals to ATT&CK Enterprise techniques.
Adds professional context to reports and helps analysts write detections.
"""


# ATT&CK technique mappings for infrastructure signals
TECHNIQUE_MAP = {
    # Phishing / credential harvesting
    "phishing_kit":     {
        "technique_id":   "T1566",
        "technique_name": "Phishing",
        "tactic":         "Initial Access",
        "sub_technique":  "T1566.002 — Spearphishing Link",
        "description":    "Adversary used credential harvesting page mimicking legitimate service"
    },
    "aitm_platform":    {
        "technique_id":   "T1557",
        "technique_name": "Adversary-in-the-Middle",
        "tactic":         "Credential Access",
        "sub_technique":  "T1557.001 — LLMNR/NBT-NS Poisoning",
        "description":    "AiTM platform proxying authentication to harvest session tokens"
    },

    # Infrastructure acquisition
    "fast_cert_spin":   {
        "technique_id":   "T1583",
        "technique_name": "Acquire Infrastructure",
        "tactic":         "Resource Development",
        "sub_technique":  "T1583.001 — Domains",
        "description":    "Rapid TLS certificate issuance indicates fast infrastructure standup"
    },
    "bulletproof_host": {
        "technique_id":   "T1583",
        "technique_name": "Acquire Infrastructure",
        "tactic":         "Resource Development",
        "sub_technique":  "T1583.003 — Virtual Private Server",
        "description":    "Infrastructure hosted on bulletproof/abuse-resistant provider"
    },
    "wildcard_cert":    {
        "technique_id":   "T1583",
        "technique_name": "Acquire Infrastructure",
        "tactic":         "Resource Development",
        "sub_technique":  "T1583.001 — Domains",
        "description":    "Wildcard certificate enables rapid subdomain creation for victim targeting"
    },

    # Defense evasion
    "privacy_whois":    {
        "technique_id":   "T1584",
        "technique_name": "Compromise Infrastructure",
        "tactic":         "Resource Development",
        "sub_technique":  "T1584.001 — Domains",
        "description":    "WHOIS privacy service used to obscure registrant identity"
    },
    "cdn_proxy":        {
        "technique_id":   "T1090",
        "technique_name": "Proxy",
        "tactic":         "Command and Control",
        "sub_technique":  "T1090.002 — External Proxy",
        "description":    "CDN/proxy used to mask true hosting infrastructure"
    },

    # Credential access
    "credential_harvesting": {
        "technique_id":   "T1056",
        "technique_name": "Input Capture",
        "tactic":         "Credential Access",
        "sub_technique":  "T1056.003 — Web Portal Capture",
        "description":    "Web-based credential harvesting page detected"
    },

    # Persistence / C2
    "c2_ports":         {
        "technique_id":   "T1571",
        "technique_name": "Non-Standard Port",
        "tactic":         "Command and Control",
        "description":    "C2-associated ports detected on infrastructure"
    },
    "known_malware":    {
        "technique_id":   "T1587",
        "technique_name": "Develop Capabilities",
        "tactic":         "Resource Development",
        "sub_technique":  "T1587.001 — Malware",
        "description":    "Infrastructure associated with known malware family"
    }
}


def map_findings_to_attack(report: dict) -> list:
    """
    Map inframap findings to MITRE ATT&CK techniques.
    Returns list of applicable technique mappings.
    """
    findings     = report.get("findings", [])
    infra        = report.get("infrastructure", {})
    attr         = report.get("attribution", {})
    mapped       = []
    seen_ids     = set()

    def _add(key):
        if key in TECHNIQUE_MAP and key not in seen_ids:
            seen_ids.add(key)
            mapped.append(TECHNIQUE_MAP[key])

    # Check findings text for signals
    for finding in findings:
        text = finding.get("text", "").lower()
        src  = finding.get("source", "").lower()

        if "phishing" in text or "kit detected" in text:
            _add("phishing_kit")
            _add("credential_harvesting")

        if "fast-spin" in text or "rapid issuance" in text:
            _add("fast_cert_spin")

        if "wildcard" in text:
            _add("wildcard_cert")

        if "bulletproof" in text or "shady" in text or "nforce" in text:
            _add("bulletproof_host")

        if "c2" in text or "c2-associated" in text:
            _add("c2_ports")

        if "malware" in text or "threatfox" in src or "urlhaus" in src:
            _add("known_malware")

        if "virustotal" in src and "malicious" in text:
            _add("phishing_kit")

        if "liveness" in src:
            pass  # liveness doesn't map to a technique directly

    # Check infrastructure signals
    if infra.get("phishing_score", 0) >= 60:
        _add("phishing_kit")
        _add("credential_harvesting")

    if infra.get("malware_families"):
        _add("known_malware")

    hosting_risk = infra.get("hosting_risk", "").upper()
    if hosting_risk in ("HIGH", "CRITICAL", "BULLETPROOF"):
        _add("bulletproof_host")

    # Check ASN
    asn_name = infra.get("asn_name", "").lower()
    if any(bp in asn_name for bp in ["nforce", "frantech", "m247", "pq.hosting"]):
        _add("bulletproof_host")

    # If high confidence = adversary is deploying phishing infra
    if attr.get("confidence_score", 0) >= 70:
        _add("fast_cert_spin")

    return mapped


def format_attack_table(techniques: list) -> str:
    """Format ATT&CK mappings as a markdown table."""
    if not techniques:
        return ""

    lines = [
        "## MITRE ATT&CK Mapping",
        "",
        "| Technique ID | Name | Tactic | Sub-technique |",
        "|-------------|------|--------|---------------|"
    ]

    for t in techniques:
        tid   = t.get("technique_id", "")
        name  = t.get("technique_name", "")
        tac   = t.get("tactic", "")
        sub   = t.get("sub_technique", "N/A")
        lines.append(f"| {tid} | {name} | {tac} | {sub} |")

    lines.append("")
    return "\n".join(lines)
