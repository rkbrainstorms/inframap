"""
Automated investigation report generator.
Produces a complete, prose-format CTI investigation report
suitable for client delivery.

This is the feature that saves analysts 2-3 hours per investigation.
No other free tool generates a formatted prose report automatically.

Output format: Markdown (renders in GitHub, Confluence, Notion, etc.)
"""

from datetime import datetime, timezone


def generate_report(report: dict, pivot_results: dict = None,
                    liveness_data: dict = None) -> str:
    """
    Generate a complete prose investigation report from inframap data.
    """
    meta   = report.get("meta", {})
    attr   = report.get("attribution", {})
    infra  = report.get("infrastructure", {})
    finds  = report.get("findings", [])
    iocs   = report.get("iocs", [])

    domain     = meta.get("seed_domain", "N/A")
    ip         = meta.get("seed_ip")
    tier_label = attr.get("tier_label", "INSUFFICIENT DATA")
    score      = attr.get("confidence_score", 0)
    generated  = meta.get("generated", "")[:19].replace("T", " ")
    sources    = ", ".join(meta.get("sources_used", []))

    lines = []

    # ── Header ────────────────────────────────────────────────────
    lines.append("# Threat Infrastructure Investigation Report")
    lines.append("")
    lines.append(f"**Classification:** TLP:AMBER — Share with trusted parties only  ")
    lines.append(f"**Generated:** {generated} UTC  ")
    lines.append(f"**Tool:** inframap v1.4.0 (github.com/rkbrainstorms/inframap)  ")
    lines.append(f"**Sources:** {sources}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # ── Executive Summary ─────────────────────────────────────────
    lines.append("## Executive Summary")
    lines.append("")

    conf_desc = {
        "CONFIRMED":         "multiple independent corroborating sources",
        "ANALYST ASSESSMENT": "analyst assessment with documented evidence",
        "CIRCUMSTANTIAL":    "circumstantial indicators only",
        "INSUFFICIENT DATA": "insufficient data — further investigation required"
    }.get(tier_label, "unknown")

    seed_str = domain if domain != "N/A" else ip or "N/A"

    # Auto-generate executive summary based on findings
    confirmed_finds = [f for f in finds if f.get("confidence") == "CONFIRMED"]
    high_risk_finds = [f for f in finds
                      if "fast-spin" in f.get("text", "").lower()
                      or "phishing" in f.get("text", "").lower()
                      or "bulletproof" in f.get("text", "").lower()
                      or "AiTM" in f.get("text", "")]

    summary_parts = []

    if score >= 70:
        summary_parts.append(
            f"Investigation of `{seed_str}` identified **confirmed malicious infrastructure** "
            f"with a confidence score of **{score}/100** based on {conf_desc}."
        )
    elif score >= 40:
        summary_parts.append(
            f"Investigation of `{seed_str}` identified **suspicious infrastructure** "
            f"with a confidence score of **{score}/100** based on {conf_desc}."
        )
    else:
        summary_parts.append(
            f"Investigation of `{seed_str}` returned a confidence score of **{score}/100**. "
            f"Attribution is {conf_desc}."
        )

    if infra.get("cert_count", 0) > 0:
        summary_parts.append(
            f"Certificate transparency analysis identified **{infra['cert_count']} certificates** "
            f"covering **{infra.get('unique_domains', 0)} unique domains**."
        )

    if infra.get("urlscan_hits", 0) > 0:
        summary_parts.append(
            f"The infrastructure has been scanned **{infra['urlscan_hits']} times** on urlscan.io, "
            f"indicating active security community interest."
        )

    if infra.get("phishing_score", 0) >= 60:
        summary_parts.append(
            f"Phishing kit detection scored **{infra['phishing_score']}/100**, "
            f"indicating active credential harvesting infrastructure."
        )

    if infra.get("liveness", {}).get("live", 0) > 0:
        liveness = infra["liveness"]
        summary_parts.append(
            f"Liveness checks confirm **{liveness['live']} of {liveness['total']} IOCs "
            f"are currently active**."
        )

    if infra.get("malware_families"):
        families = ", ".join(infra["malware_families"])
        summary_parts.append(
            f"IOCs matched known malware families in threat intelligence databases: **{families}**."
        )

    lines.append(" ".join(summary_parts))
    lines.append("")

    # ── Attribution Assessment ────────────────────────────────────
    lines.append("## Attribution Assessment")
    lines.append("")
    lines.append(f"| Field | Value |")
    lines.append(f"|-------|-------|")
    lines.append(f"| Confidence tier | **{tier_label}** |")
    lines.append(f"| Score | {score}/100 |")
    lines.append(f"| Seed | `{seed_str}` |")
    if infra.get("registrar"):
        lines.append(f"| Registrar | {infra['registrar']} |")
    if infra.get("domain_age_days") is not None:
        age = infra["domain_age_days"]
        age_risk = " ⚠️ newly registered" if age < 30 else ""
        lines.append(f"| Domain age | {age} days{age_risk} |")
    if infra.get("asn"):
        lines.append(f"| ASN | {infra['asn']} ({infra.get('asn_name', '')}) |")
    if infra.get("hosting_risk"):
        lines.append(f"| Hosting risk | {infra['hosting_risk']} |")
    lines.append("")

    # ── Technical Findings ────────────────────────────────────────
    if finds:
        lines.append("## Technical Findings")
        lines.append("")

        # Group by confidence tier
        for tier in ["CONFIRMED", "ANALYST ASSESSMENT", "CIRCUMSTANTIAL"]:
            tier_finds = [f for f in finds if f.get("confidence") == tier]
            if not tier_finds:
                continue
            lines.append(f"### {tier}")
            lines.append("")
            for f in tier_finds:
                source = f.get("source", "")
                text   = f.get("text", "")
                lines.append(f"- **{source}**: {text}")
            lines.append("")

    # ── Infrastructure Summary ────────────────────────────────────
    lines.append("## Infrastructure Summary")
    lines.append("")

    cert_count = infra.get("cert_count", 0)
    if cert_count > 0:
        lines.append(f"### Certificate Transparency")
        lines.append("")
        lines.append(
            f"Certificate transparency logs reveal **{cert_count} certificates** "
            f"covering **{infra.get('unique_domains', 0)} unique domain names**. "
        )
        if infra.get("shared_hosts"):
            lines.append(
                f"Passive DNS reverse lookups identified **{len(infra['shared_hosts'])} additional domains** "
                f"co-hosted on the same infrastructure, suggesting shared hosting or a platform serving multiple campaigns."
            )
        lines.append("")

    urlscan_hits = infra.get("urlscan_hits", 0)
    if urlscan_hits > 0:
        countries = infra.get("countries", [])
        lines.append("### urlscan.io Analysis")
        lines.append("")
        lines.append(
            f"urlscan.io records **{urlscan_hits} historical scans** of this infrastructure. "
        )
        if countries:
            lines.append(f"Scans originated from: {', '.join(countries[:5])}.")
        lines.append("")

    # ── Liveness ─────────────────────────────────────────────────
    if liveness_data:
        from inframap.pivots.liveness import summarise_liveness
        ls = summarise_liveness(liveness_data)
        lines.append("### Infrastructure Liveness")
        lines.append("")
        lines.append(
            f"At the time of investigation, **{ls['live']} of {ls['total']} IOCs "
            f"({ls['live_pct']}%) are currently active**. "
            f"{ls['dead']} IOCs are offline. "
        )
        if ls.get("live_iocs"):
            lines.append("")
            lines.append("Currently active infrastructure:")
            for ioc in ls["live_iocs"][:10]:
                lines.append(f"- `{ioc.replace('.', '[.]')}`")
        lines.append("")

    # ── IOC Table ─────────────────────────────────────────────────
    if iocs:
        lines.append("## Defanged IOC Table")
        lines.append("")
        lines.append("> All values defanged. Re-fang before operationalising in detection rules.")
        lines.append("")
        lines.append("| Type | Defanged Value | Source |")
        lines.append("|------|----------------|--------|")

        type_order = ["domain", "ip", "email", "nameserver", "registrant_org", "asn"]
        ordered = sorted(iocs, key=lambda x: (
            type_order.index(x["type"]) if x["type"] in type_order else 99
        ))

        # Deduplicate for report
        seen = set()
        for ioc in ordered:
            key = (ioc["type"], ioc.get("defanged", ""))
            if key in seen:
                continue
            seen.add(key)
            lines.append(
                f"| {ioc['type']} | `{ioc.get('defanged', ioc.get('value', ''))}` | {ioc.get('source', '')} |"
            )
        lines.append("")

    # ── Recommended Actions ───────────────────────────────────────
    lines.append("## Recommended Actions")
    lines.append("")

    actions = []
    if score >= 70:
        actions.append("Block all identified IPs and domains at perimeter controls (firewall, proxy, DNS)")
        actions.append("Submit IOCs to internal SIEM/SOAR for alert correlation")
        actions.append("Check email gateway logs for messages originating from or linking to identified infrastructure")
    if infra.get("phishing_score", 0) >= 60:
        actions.append("Alert users to active credential harvesting campaign — enforce MFA review")
        actions.append("Check identity logs for authentication attempts from identified IP ranges")
    if score >= 40:
        actions.append("Monitor identified infrastructure for changes (new subdomains, IP changes)")
        actions.append("Share IOCs with industry peers via appropriate TLP channels")
    if infra.get("liveness", {}).get("live", 0) > 0:
        actions.append("Prioritise blocking of currently-live IOCs — infrastructure is active")
    if infra.get("malware_families"):
        actions.append(f"Review detection rules for identified malware families: {', '.join(infra['malware_families'])}")

    actions.append("Re-run investigation in 72 hours to track infrastructure changes")

    for i, action in enumerate(actions, 1):
        lines.append(f"{i}. {action}")
    lines.append("")

    # ── Analyst Notes ─────────────────────────────────────────────
    lines.append("## Analyst Notes")
    lines.append("")
    lines.append(
        f"> This report was auto-generated by inframap v1.4.0 on {generated} UTC. "
        f"All findings should be validated by a qualified analyst before operational use. "
        f"Confidence scores are based on publicly available passive data sources only."
    )
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(
        "*Generated by [inframap](https://github.com/rkbrainstorms/inframap) — "
        "open-source infrastructure attribution for the CTI community*"
    )

    return "\n".join(lines)
