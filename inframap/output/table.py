"""
Terminal output — colored table and summary for the CLI.
Uses ANSI escape codes with --no-color fallback.
"""

# ANSI codes
R  = "\033[0m"   # reset
B  = "\033[1m"   # bold
DIM= "\033[2m"   # dim

RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
MAGENTA= "\033[35m"
WHITE  = "\033[37m"
BRED   = "\033[91m"
BYEL   = "\033[93m"
BGRN   = "\033[92m"
BCYN   = "\033[96m"

_NO_COLOR = False


def _c(code, text):
    if _NO_COLOR:
        return text
    return f"{code}{text}{R}"


def print_summary(report: dict, no_color: bool = False):
    global _NO_COLOR
    _NO_COLOR = no_color

    attr   = report.get("attribution", {})
    infra  = report.get("infrastructure", {})
    meta   = report.get("meta", {})
    tier   = attr.get("confidence_tier", "NONE")
    label  = attr.get("tier_label", "INSUFFICIENT DATA")
    score  = attr.get("confidence_score", 0)

    tier_color = {
        "HIGH":   BGRN,
        "MEDIUM": BYEL,
        "LOW":    BRED,
        "NONE":   DIM,
    }.get(tier, WHITE)

    print()
    print(_c(B + CYAN, "━" * 64))
    print(_c(B + CYAN, "  INFRAMAP — ATTRIBUTION REPORT"))
    print(_c(B + CYAN, "━" * 64))
    print()

    seed_domain = meta.get("seed_domain", "—")
    seed_ip     = meta.get("seed_ip", "—")
    print(f"  {'Seed domain':<18} {_c(B, seed_domain)}")
    if seed_ip:
        print(f"  {'Seed IP':<18} {_c(B, seed_ip)}")
    print(f"  {'Sources used':<18} {', '.join(meta.get('sources_used', [])) or 'none'}")
    print(f"  {'Generated':<18} {meta.get('generated', '')[:19].replace('T', ' ')} UTC")
    print()

    # Confidence box
    print(_c(tier_color, f"  ┌─ ATTRIBUTION CONFIDENCE {'─' * 34}┐"))
    print(_c(tier_color, f"  │  {label:<58}│"))
    bar_filled = int(score / 2)
    bar = "█" * bar_filled + "░" * (50 - bar_filled)
    print(_c(tier_color, f"  │  [{bar}] {score:>3}/100  │"))
    print(_c(tier_color, f"  └{'─' * 60}┘"))
    print()

    summary = attr.get("summary", "")
    if summary:
        print(f"  {_c(DIM, summary)}")
        print()

    # Quick infra stats
    cols = []
    if infra.get("cert_count") is not None:
        cols.append(f"certs: {infra['cert_count']}")
    if infra.get("unique_domains") is not None:
        cols.append(f"domains: {infra['unique_domains']}")
    if infra.get("urlscan_hits") is not None:
        cols.append(f"urlscan hits: {infra['urlscan_hits']}")
    if infra.get("domain_age_days") is not None:
        age = infra["domain_age_days"]
        age_str = f"{age}d old"
        age_col = BRED if age < 30 else BYEL if age < 90 else DIM
        cols.append(f"domain age: {_c(age_col, age_str)}")
    if infra.get("registrar"):
        cols.append(f"registrar: {infra['registrar']}")
    if infra.get("asn"):
        asn_name = infra.get("asn_name", "")
        asn_str  = f"{infra['asn']} ({asn_name})" if asn_name else infra["asn"]
        cols.append(f"ASN: {asn_str}")
    if infra.get("hosting_risk"):
        risk = infra["hosting_risk"]
        rc = BRED if risk == "HIGH-RISK" else BYEL if risk == "SUSPICIOUS" else DIM
        cols.append(f"hosting: {_c(rc, risk)}")

    if cols:
        print("  " + "  ·  ".join(cols))
        print()

    # Errors
    errors = report.get("errors", [])
    if errors:
        print(_c(YELLOW, "  [!] warnings:"))
        for err in errors:
            src = err.get("source", "?")
            msg = err.get("error", "")
            print(f"      {_c(DIM, src)}: {msg}")
        print()


def print_evidence_table(report: dict, no_color: bool = False):
    global _NO_COLOR
    _NO_COLOR = no_color

    findings = report.get("findings", [])
    iocs     = report.get("iocs", [])

    # ── Findings table ──
    if findings:
        print(_c(B, "  FINDINGS"))
        print(_c(DIM, "  " + "─" * 62))
        print(f"  {'CONFIDENCE':<24} {'SOURCE':<14} FINDING")
        print(_c(DIM, "  " + "─" * 62))

        conf_color = {
            "CONFIRMED":         BGRN,
            "ANALYST ASSESSMENT": BYEL,
            "CIRCUMSTANTIAL":    BRED,
        }

        for f in findings:
            conf   = f.get("confidence", "")
            source = f.get("source", "")
            text   = f.get("text", "")
            cc     = conf_color.get(conf, WHITE)
            # Wrap long text
            if len(text) > 42:
                text = text[:40] + "…"
            print(f"  {_c(cc, conf):<33} {_c(DIM, source):<14} {text}")

        print()

    # ── IOC table ──
    if iocs:
        print(_c(B, "  DEFANGED IOCs"))
        print(_c(DIM, "  " + "─" * 62))
        print(f"  {'TYPE':<18} {'SOURCE':<14} DEFANGED VALUE")
        print(_c(DIM, "  " + "─" * 62))

        # Group by type for readability
        type_order = ["domain", "ip", "email", "nameserver", "registrant_org", "asn"]
        grouped    = {}
        for ioc in iocs:
            t = ioc.get("type", "other")
            grouped.setdefault(t, []).append(ioc)

        for t in type_order:
            for ioc in grouped.get(t, []):
                src      = ioc.get("source", "")
                defanged = ioc.get("defanged", ioc.get("value", ""))
                type_col = _c(CYAN, t)
                print(f"  {type_col:<27} {_c(DIM, src):<14} {defanged}")

        # Any remaining types
        for t, ioc_list in grouped.items():
            if t not in type_order:
                for ioc in ioc_list:
                    src      = ioc.get("source", "")
                    defanged = ioc.get("defanged", ioc.get("value", ""))
                    print(f"  {_c(CYAN, t):<27} {_c(DIM, src):<14} {defanged}")

        print()

    print(_c(DIM, "  " + "─" * 62))
    print(_c(DIM, "  inframap | defang all IOCs before sharing | use responsibly"))
    print()
