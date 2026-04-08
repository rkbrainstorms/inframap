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
    if attr.get("partial_data"):
        warn = "⚠ partial data — crt.sh unavailable, score may be lower"
        print(_c(YELLOW, f"  │  {warn:<58}│"))
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


def print_compare(result: dict, no_color: bool = False):
    global _NO_COLOR
    _NO_COLOR = no_color

    domain_a = result.get("domain_a", "domain_a")
    domain_b = result.get("domain_b", "domain_b")
    score    = result.get("shared_score", 0)
    label    = result.get("confidence_label", "")
    verdict  = result.get("verdict", "")
    indicators = result.get("shared_indicators", [])
    differences= result.get("differences", [])

    score_color = BGRN if score >= 60 else BYEL if score >= 40 else DIM

    print()
    print(_c(B + CYAN, "━" * 64))
    print(_c(B + CYAN, "  INFRAMAP — SHARED OPERATOR COMPARISON"))
    print(_c(B + CYAN, "━" * 64))
    print()
    print(f"  {'Domain A':<18} {_c(B, domain_a)}")
    print(f"  {'Domain B':<18} {_c(B, domain_b)}")
    print()

    bar_filled = int(score / 2)
    bar = "█" * bar_filled + "░" * (50 - bar_filled)
    print(_c(score_color, f"  ┌─ SHARED OPERATOR SCORE {'─' * 35}┐"))
    print(_c(score_color, f"  │  {label:<58}│"))
    print(_c(score_color, f"  │  [{bar}] {score:>3}/100  │"))
    print(_c(score_color, f"  └{'─' * 60}┘"))
    print()
    print(f"  {_c(DIM, verdict)}")
    print()

    if indicators:
        print(_c(B, "  SHARED INDICATORS"))
        print(_c(DIM, "  " + "─" * 62))
        for ind in indicators:
            print(f"  {_c(BGRN, '✓')} {ind}")
        print()

    if differences:
        print(_c(B, "  DIFFERENCES"))
        print(_c(DIM, "  " + "─" * 62))
        for diff in differences:
            print(f"  {_c(DIM, '✗')} {diff}")
        print()

    print(_c(DIM, "  " + "─" * 62))
    print(_c(DIM, "  inframap | defang all IOCs before sharing | use responsibly"))
    print()


def print_phishing(result: dict, no_color: bool = False):
    global _NO_COLOR
    _NO_COLOR = no_color

    score    = result.get("phishing_score", 0)
    detected = result.get("kit_detected", False)
    titles   = result.get("matched_titles", [])
    patterns = result.get("matched_patterns", [])
    aitm     = result.get("aitm_indicators", [])
    scans    = result.get("suspicious_scans", [])

    score_color = BRED if score >= 60 else BYEL if score >= 40 else DIM
    status = _c(BRED, "KIT DETECTED") if detected else _c(DIM, "NO KIT DETECTED")

    print()
    print(_c(B, "  PHISHING KIT DETECTION"))
    print(_c(DIM, "  " + "─" * 62))
    print(f"  Score: {_c(score_color, f'{score}/100')}  Status: {status}")
    print()

    if aitm:
        print(_c(BRED, "  [!] AiTM INDICATORS"))
        for a in aitm:
            print(f"      {a}")
        print()

    if titles:
        print(_c(B, "  MATCHED PAGE TITLES"))
        for t in titles[:5]:
            print(f"  {_c(YELLOW, '→')} {t}")
        print()

    if scans:
        print(_c(B, "  SUSPICIOUS SCANS"))
        print(_c(DIM, "  " + "─" * 62))
        print(f"  {'DATE':<12} {'COUNTRY':<8} {'ASN':<12} URL")
        print(_c(DIM, "  " + "─" * 62))
        for s in scans[:5]:
            url = s.get("url", "")[:45]
            print(f"  {s.get('date',''):<12} {s.get('country',''):<8} "
                  f"{s.get('asn',''):<12} {url}")
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

def print_hunt(result: dict, no_color: bool = False):
    global _NO_COLOR
    _NO_COLOR = no_color

    hunt_type   = result.get("hunt_type", "")
    hunt_target = result.get("hunt_target", "")
    days        = result.get("days", 30)
    found       = result.get("domains_found", 0)
    suspicious  = result.get("suspicious", [])
    errors      = result.get("errors", [])

    print()
    print(_c(B + CYAN, "━" * 64))
    print(_c(B + CYAN, "  INFRAMAP — PROACTIVE THREAT HUNT"))
    print(_c(B + CYAN, "━" * 64))
    print()
    print(f"  {'Hunt type':<18} {hunt_type}")
    print(f"  {'Target':<18} {_c(B, hunt_target)}")
    print(f"  {'Lookback':<18} {days} days")
    print(f"  {'Suspicious found':<18} {_c(BRED if found > 0 else DIM, str(found))}")
    print()

    if errors:
        for err in errors:
            if not err.startswith("Note:"):
                print(f"  {_c(YELLOW, '[!]')} {err}")
        print()

    if not suspicious:
        print(_c(DIM, "  No suspicious domains found in this time window."))
        print(_c(DIM, "  Try --days 60 or a different --keyword/--asn/--nameserver"))
        print()
        return

    print(_c(B, "  SUSPICIOUS DOMAINS (ranked by score)"))
    print(_c(DIM, "  " + "─" * 62))
    print(f"  {'SCORE':<8} {'AGE':<8} {'DATE':<12} {'DOMAIN':<30} SIGNALS")
    print(_c(DIM, "  " + "─" * 62))

    for d in suspicious[:25]:
        score   = d.get("score", 0)
        age     = f"{d.get('age_days', '?')}d" if d.get('age_days') is not None else "?"
        date    = d.get("cert_date", "")
        domain  = d.get("domain", "")[:28]
        signals = ", ".join(d.get("signals", []))[:40]

        sc = BRED if score >= 60 else BYEL if score >= 40 else DIM
        defanged = domain.replace(".", "[.]")

        print(f"  {_c(sc, f'{score:>3}/100'):<17} {age:<8} {date:<12} {defanged:<30} {_c(DIM, signals)}")

    if len(result.get("all_domains", [])) > 25:
        remaining = len(result["all_domains"]) - 25
        print(_c(DIM, f"\n  ... {remaining} more domains not shown. Use -o json for full list."))

    print()
    print(_c(DIM, "  " + "─" * 62))
    print(_c(DIM, "  inframap | defang all IOCs before sharing | use responsibly"))
    print()

def print_liveness(liveness: dict, no_color: bool = False):
    global _NO_COLOR
    _NO_COLOR = no_color

    if not liveness:
        return

    live    = [(k, v) for k, v in liveness.items() if v.get("status") == "LIVE"]
    dead    = [(k, v) for k, v in liveness.items() if v.get("status") == "DEAD"]
    unknown = [(k, v) for k, v in liveness.items() if v.get("status") == "UNKNOWN"]

    print()
    print(_c(B, "  IOC LIVENESS"))
    print(_c(DIM, "  " + "─" * 62))
    print(f"  {_c(BGRN, f'LIVE: {len(live)}')}"
          f"  {_c(BRED, f'DEAD: {len(dead)}')}"
          f"  {_c(DIM, f'UNKNOWN: {len(unknown)}')}")
    print()

    if live:
        print(_c(BGRN, "  LIVE"))
        for ioc, data in live[:10]:
            code = data.get("http_code", "")
            ms   = data.get("latency_ms", "")
            info = f"HTTP {code}" if code else ""
            if ms:
                info += f" ({ms}ms)"
            defanged = ioc.replace(".", "[.]")
            print(f"  ● {defanged:<40} {_c(DIM, info)}")

    if dead:
        print()
        print(_c(BRED, "  DEAD"))
        for ioc, data in dead[:10]:
            defanged = ioc.replace(".", "[.]")
            print(f"  ○ {_c(DIM, defanged)}")
    print()


def print_threatmatch(tm: dict, no_color: bool = False):
    global _NO_COLOR
    _NO_COLOR = no_color

    if not tm:
        return

    matches  = tm.get("matches", [])
    families = tm.get("malware_families", [])
    checked  = tm.get("checked", 0)
    note     = tm.get("note")
    errors   = tm.get("errors", [])

    print()
    print(_c(B, "  THREATFOX / URLHAUS MATCHES"))
    print(_c(DIM, "  " + "─" * 62))

    if errors:
        for err in errors[:2]:
            print(f"  {_c(YELLOW, '[!]')} {err}")

    if not matches:
        print(f"  {_c(DIM, f'Checked {checked} IOCs — no matches found')}")
        if note:
            # Word-wrap the note
            words = note.split()
            line  = "  "
            for word in words:
                if len(line) + len(word) > 70:
                    print(_c(DIM, line))
                    line = "  " + word + " "
                else:
                    line += word + " "
            if line.strip():
                print(_c(DIM, line))
        print()
        return

    print(f"  {_c(BRED, f'{len(matches)} match(es) found')} across {checked} IOCs checked")
    if families:
        print(f"  Malware families: {_c(BRED, ', '.join(families))}")
    print()
    print(f"  {'IOC':<35} {'SOURCE':<12} MALWARE/THREAT")
    print(_c(DIM, "  " + "─" * 62))
    for m in matches:
        ioc     = m.get("ioc", "").replace(".", "[.]")[:33]
        source  = m.get("source", "")
        malware = m.get("malware") or m.get("threat") or "known malicious"
        print(f"  {_c(BRED, ioc):<44} {_c(DIM, source):<12} {malware}")
    print()
