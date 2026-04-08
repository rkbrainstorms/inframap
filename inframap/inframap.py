#!/usr/bin/env python3
"""
inframap — Open-source infrastructure fingerprinting & attribution engine
Pivots across crt.sh (+fallbacks), RDAP, urlscan.io, AbuseIPDB, BGP.he.net,
HackerTarget passive DNS, Shodan InternetDB, ThreatFox, URLhaus, and more.
Using only free/no-key APIs. Built for the CTI community.
"""

import argparse
import sys
import os
import json
import time

from inframap.pivots.crtsh       import pivot_crtsh
from inframap.pivots.rdap        import pivot_rdap
from inframap.pivots.urlscan     import pivot_urlscan
from inframap.pivots.abuseip     import pivot_abuseip
from inframap.pivots.bgphe       import pivot_bgphe
from inframap.pivots.passivedns  import pivot_passivedns
from inframap.pivots.phishdetect import detect_phishing_kit
from inframap.pivots.hunt        import hunt_infrastructure
from inframap.pivots.internetdb  import pivot_internetdb
from inframap.pivots.threatmatch import bulk_check_iocs
from inframap.pivots.liveness    import check_liveness, summarise_liveness
from inframap.engine.cluster     import cluster_certs, cluster_whois, score_asn
from inframap.engine.confidence  import build_confidence_report
from inframap.engine.compare     import compare_domains
from inframap.output.table       import (print_evidence_table, print_summary,
                                          print_compare, print_phishing,
                                          print_hunt, print_liveness,
                                          print_threatmatch)
from inframap.output.export      import export_csv, export_json, export_markdown
from inframap.output.report      import generate_report

VERSION = "1.4.0"

BANNER = r"""
  _        __                          
 (_)_ __  / _|_ __ __ _ _ __ ___   __ _ _ __  
 | | '_ \| |_| '__/ _` | '_ ` _ \ / _` | '_ \ 
 | | | | |  _| | | (_| | | | | | | (_| | |_) |
 |_|_| |_|_| |_|  \__,_|_| |_| |_|\__,_| .__/ 
                                         |_|    
  infrastructure fingerprinting & attribution engine
  free & open source | no enterprise APIs required
"""

def parse_args():
    p = argparse.ArgumentParser(
        prog="inframap",
        description="Infrastructure fingerprinting & attribution engine for CTI analysts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python inframap.py -d evil.com
  python inframap.py -d evil.com --urlscan-key YOUR_KEY --abuseip-key YOUR_KEY
  python inframap.py -d evil.com -o markdown --out-file report.md
  python inframap.py --compare domain1.com domain2.com
  python inframap.py -d evil.com --phishing
  python inframap.py -d evil.com --depth 2 --quiet -o csv
  python inframap.py -d evil.com --skip crtsh bgphe

api keys (all optional, all free):
  urlscan.io  : https://urlscan.io/user/signup       (1000 searches/day)
  AbuseIPDB   : https://www.abuseipdb.com/register   (1000 checks/day)
  crt.sh      : no key needed
  RDAP        : no key needed
  BGP.he.net  : no key needed
  HackerTarget: no key needed                        (100 queries/day)
        """
    )

    p.add_argument("--version", action="version", version=f"inframap {VERSION}")

    seed = p.add_argument_group("seed (provide at least one)")
    seed.add_argument("-d", "--domain",  metavar="DOMAIN", help="seed domain (e.g. evil.com)")
    seed.add_argument("-i", "--ip",      metavar="IP",     help="seed IP address")
    seed.add_argument("-e", "--email",   metavar="EMAIL",  help="registrant email for WHOIS pivoting")
    seed.add_argument("-c", "--cert",    metavar="HASH",   help="certificate SHA-256 fingerprint")

    modes = p.add_argument_group("modes")
    modes.add_argument("--compare", nargs=2, metavar=("DOMAIN_A", "DOMAIN_B"),
                       help="compare two domains for shared operator score")
    modes.add_argument("--phishing", action="store_true",
                       help="run phishing kit detection on the seed domain")
    modes.add_argument("--hunt", action="store_true",
                       help="proactive hunting — find newly registered suspicious domains")
    modes.add_argument("--live",  action="store_true",
                       help="check liveness of all discovered IOCs (LIVE/DEAD/UNKNOWN)")
    modes.add_argument("--threatcheck", action="store_true",
                       help="check IOCs against ThreatFox + URLhaus (abuse.ch, no key)")
    modes.add_argument("--report", action="store_true",
                       help="generate full prose investigation report (saves to --out-file)")
    modes.add_argument("--asn",       metavar="ASN",
                       help="ASN to hunt (use with --hunt, e.g. AS43350)")
    modes.add_argument("--nameserver", metavar="NS",
                       help="nameserver to hunt (use with --hunt, e.g. topdns.com)")
    modes.add_argument("--keyword",   metavar="KEYWORD",
                       help="keyword to hunt in domain names (use with --hunt)")
    modes.add_argument("--days",      type=int, default=30,
                       help="look back N days for --hunt mode (default: 30)")

    keys = p.add_argument_group("api keys (optional, all free-tier)")
    keys.add_argument("--urlscan-key",  metavar="KEY", default=os.environ.get("URLSCAN_API_KEY"),
                      help="urlscan.io API key (or set URLSCAN_API_KEY env var)")
    keys.add_argument("--abuseip-key",  metavar="KEY", default=os.environ.get("ABUSEIPDB_API_KEY"),
                      help="AbuseIPDB API key (or set ABUSEIPDB_API_KEY env var)")

    opts = p.add_argument_group("options")
    opts.add_argument("--depth",  type=int, default=1, choices=[1,2],
                      help="pivot depth: 1=seed only, 2=pivot on discovered IPs/domains (default: 1)")
    opts.add_argument("--skip",   nargs="+", metavar="SOURCE",
                      choices=["crtsh","rdap","urlscan","abuseip","bgphe","passivedns","phishdetect"],
                      help="skip specific sources")
    opts.add_argument("-o", "--output", default="table",
                      choices=["table","csv","json","markdown"],
                      help="output format (default: table)")
    opts.add_argument("--out-file", metavar="FILE",
                      help="write output to file instead of stdout")
    opts.add_argument("-q", "--quiet",  action="store_true",
                      help="suppress banner and progress, print results only")
    opts.add_argument("--no-color",     action="store_true",
                      help="disable ANSI color output")
    opts.add_argument("--timeout", type=int, default=10,
                      help="request timeout in seconds (default: 10)")

    return p.parse_args()


def validate_args(args):
    if args.compare:
        return
    if args.hunt:
        if not any([args.asn, args.nameserver, args.keyword]):
            print("[!] --hunt requires one of: --asn ASN | --nameserver NS | --keyword WORD")
            sys.exit(1)
        return
    if not any([args.domain, args.ip, args.email, args.cert]):
        print("[!] provide at least one seed: -d DOMAIN | -i IP | -e EMAIL | -c CERT_HASH")
        print("[!] or use --compare DOMAIN_A DOMAIN_B for shared-operator analysis")
        print("[!] or use --hunt --asn AS43350 for proactive hunting")
        sys.exit(1)


def run_pivots(args, skip):
    results = {}
    seed_domain = args.domain
    seed_ip     = args.ip

    if "crtsh" not in skip and seed_domain:
        _progress("crt.sh", args.quiet)
        results["crtsh"] = pivot_crtsh(seed_domain, timeout=args.timeout)

    if "rdap" not in skip and seed_domain:
        _progress("RDAP / WHOIS", args.quiet)
        results["rdap"] = pivot_rdap(seed_domain, timeout=args.timeout)

    if "urlscan" not in skip:
        _progress("urlscan.io", args.quiet)
        results["urlscan"] = pivot_urlscan(
            domain=seed_domain, ip=seed_ip,
            api_key=args.urlscan_key, timeout=args.timeout
        )

    # Auto-pivot: feed top discovered IPs from urlscan into AbuseIPDB + BGP
    # even at depth-1 — this is the key fix so BGP/AbuseIPDB always run
    discovered_ips = []
    if results.get("urlscan"):
        discovered_ips = list(results["urlscan"].get("ips_seen", []))[:3]

    # Use seed IP first, then discovered IPs
    ips_to_check = []
    if seed_ip:
        ips_to_check.append(seed_ip)
    ips_to_check.extend([ip for ip in discovered_ips if ip != seed_ip])
    ips_to_check = ips_to_check[:3]  # cap at 3 to respect rate limits

    if ips_to_check:
        if "abuseip" not in skip and args.abuseip_key:
            _progress(f"AbuseIPDB ({len(ips_to_check)} IPs)", args.quiet)
            results["abuseip"] = pivot_abuseip(
                ips_to_check[0], api_key=args.abuseip_key, timeout=args.timeout
            )
            # Store additional IP results
            results["abuseip_extra"] = []
            for extra_ip in ips_to_check[1:]:
                time.sleep(0.5)
                results["abuseip_extra"].append(
                    pivot_abuseip(extra_ip, api_key=args.abuseip_key, timeout=args.timeout)
                )
        elif "abuseip" not in skip and not args.abuseip_key:
            if not args.quiet:
                print(f"  [~] AbuseIPDB skipped — no API key (free at abuseipdb.com)")

        if "bgphe" not in skip:
            _progress(f"BGP.he.net ({len(ips_to_check)} IPs)", args.quiet)
            results["bgphe"] = pivot_bgphe(ips_to_check[0], timeout=args.timeout)
            results["bgphe_extra"] = []
            for extra_ip in ips_to_check[1:]:
                time.sleep(0.3)
                results["bgphe_extra"].append(pivot_bgphe(extra_ip, args.timeout))
    elif "abuseip" not in skip and not seed_ip:
        if not args.quiet:
            print(f"  [~] AbuseIPDB/BGP skipped — no IP discovered yet")

    return results


def run_depth2(args, skip, pivot_results, quiet):
    """Depth-2: pivot on IPs/domains discovered in depth-1."""
    discovered_ips     = set()
    discovered_domains = set()

    crtsh_data = pivot_results.get("crtsh", {})
    for cert in crtsh_data.get("certs", []):
        for name in cert.get("names", []):
            if name and name != args.domain:
                discovered_domains.add(name.lstrip("*."))

    urlscan_data = pivot_results.get("urlscan", {})
    for scan in urlscan_data.get("results", []):
        ip = scan.get("page", {}).get("ip")
        if ip:
            discovered_ips.add(ip)

    if not quiet:
        print(f"\n[~] depth-2: found {len(discovered_ips)} IPs, {len(discovered_domains)} domains to pivot")

    depth2 = {"ips": {}, "domains": {}}

    for ip in list(discovered_ips)[:5]:  # cap at 5 to respect rate limits
        if "abuseip" not in skip and args.abuseip_key:
            _progress(f"  AbuseIPDB → {ip}", quiet)
            depth2["ips"][ip] = {"abuseip": pivot_abuseip(ip, args.abuseip_key, args.timeout)}
            time.sleep(0.5)
        if "bgphe" not in skip:
            _progress(f"  BGP.he.net → {ip}", quiet)
            depth2["ips"].setdefault(ip, {})["bgphe"] = pivot_bgphe(ip, args.timeout)
            time.sleep(0.5)

    for domain in list(discovered_domains)[:5]:
        if "rdap" not in skip:
            _progress(f"  RDAP → {domain}", quiet)
            depth2["domains"][domain] = {"rdap": pivot_rdap(domain, args.timeout)}
            time.sleep(0.3)

    return depth2


def _progress(source, quiet):
    if not quiet:
        print(f"  [+] pivoting {source}...", flush=True)


def main():
    args  = parse_args()
    validate_args(args)
    skip  = set(args.skip or [])

    if not args.quiet:
        print(BANNER)

    # ── HUNT MODE ────────────────────────────────────────────────────
    if args.hunt:
        if not args.quiet:
            print(f"[*] mode      : proactive threat hunting")
            if args.asn:        print(f"[*] asn       : {args.asn}")
            if args.nameserver: print(f"[*] nameserver: {args.nameserver}")
            if args.keyword:    print(f"[*] keyword   : {args.keyword}")
            print(f"[*] days      : {args.days}")
            print()

        _progress("crt.sh certificate hunt", args.quiet)
        # Hunt mode needs longer timeout — crt.sh can be slow for cert queries
        hunt_timeout = max(args.timeout, 30)
        hunt_result = hunt_infrastructure(
            asn=args.asn,
            nameserver=args.nameserver,
            keyword=args.keyword,
            days=args.days,
            timeout=hunt_timeout
        )
        print_hunt(hunt_result, no_color=args.no_color)
        return

    # ── COMPARE MODE ─────────────────────────────────────────────────
    if args.compare:
        domain_a, domain_b = args.compare
        if not args.quiet:
            print(f"[*] mode      : shared-operator comparison")
            print(f"[*] domain A  : {domain_a}")
            print(f"[*] domain B  : {domain_b}")
            print()

        _progress(f"RDAP → {domain_a}", args.quiet)
        rdap_a = pivot_rdap(domain_a, args.timeout)
        _progress(f"crt.sh → {domain_a}", args.quiet)
        crtsh_a = pivot_crtsh(domain_a, args.timeout)
        _progress(f"passive DNS → {domain_a}", args.quiet)
        pdns_a = pivot_passivedns(domain=domain_a, timeout=args.timeout)
        _progress(f"urlscan.io → {domain_a}", args.quiet)
        urlscan_a = pivot_urlscan(domain=domain_a, api_key=args.urlscan_key, timeout=args.timeout)
        time.sleep(0.5)

        _progress(f"RDAP → {domain_b}", args.quiet)
        rdap_b = pivot_rdap(domain_b, args.timeout)
        _progress(f"crt.sh → {domain_b}", args.quiet)
        crtsh_b = pivot_crtsh(domain_b, args.timeout)
        _progress(f"passive DNS → {domain_b}", args.quiet)
        pdns_b = pivot_passivedns(domain=domain_b, timeout=args.timeout)
        _progress(f"urlscan.io → {domain_b}", args.quiet)
        urlscan_b = pivot_urlscan(domain=domain_b, api_key=args.urlscan_key, timeout=args.timeout)

        if not args.quiet:
            print("\n[*] running comparison engine...\n")

        result = compare_domains(
            rdap_a=rdap_a, rdap_b=rdap_b,
            crtsh_a=crtsh_a, crtsh_b=crtsh_b,
            passivedns_a=pdns_a, passivedns_b=pdns_b,
            urlscan_a=urlscan_a, urlscan_b=urlscan_b
        )
        print_compare(result, no_color=args.no_color)
        return

    # ── STANDARD MODE ────────────────────────────────────────────────
    if not args.quiet:
        seed_str = " | ".join(filter(None, [
            args.domain and f"domain={args.domain}",
            args.ip     and f"ip={args.ip}",
            args.email  and f"email={args.email}",
            args.cert   and f"cert={args.cert[:16]}...",
        ]))
        all_sources = ['crtsh','rdap','urlscan','abuseip','bgphe','passivedns']
        if args.phishing:
            all_sources.append('phishdetect')
        print(f"[*] seed      : {seed_str}")
        print(f"[*] depth     : {args.depth}")
        print(f"[*] sources   : {', '.join(s for s in all_sources if s not in skip)}")
        keys_loaded = []
        if args.urlscan_key: keys_loaded.append("urlscan")
        if args.abuseip_key: keys_loaded.append("abuseip")
        print(f"[*] api keys  : {', '.join(keys_loaded) if keys_loaded else 'none (keyless mode)'}")
        print(f"[*] output    : {args.output}")
        print()

    # depth-1 pivots
    pivot_results = run_pivots(args, skip)

    # Passive DNS (always run unless skipped)
    if "passivedns" not in skip and args.domain:
        _progress("HackerTarget passive DNS", args.quiet)
        pivot_results["passivedns"] = pivot_passivedns(
            domain=args.domain,
            ip=args.ip,
            timeout=args.timeout
        )

    # Phishing kit detection (opt-in with --phishing flag)
    if args.phishing and "phishdetect" not in skip and args.domain:
        _progress("phishing kit detection", args.quiet)
        crtsh_data   = pivot_results.get("crtsh", {})
        rdap_data    = pivot_results.get("rdap", {})
        bgphe_data   = pivot_results.get("bgphe", {})
        pivot_results["phishdetect"] = detect_phishing_kit(
            domain=args.domain,
            api_key=args.urlscan_key,
            timeout=args.timeout,
            domain_age_days=rdap_data.get("domain_age_days"),
            cert_fast_spin=any(c.get("suspicious") for c in crtsh_data.get("timing_clusters", [])),
            cert_count=crtsh_data.get("cert_count", 0),
            asn=bgphe_data.get("asn"),
            has_wildcard_san=len([n for n in crtsh_data.get("unique_names", []) if n.startswith("*.")]) > 0
        )

    # Shodan InternetDB — always run on discovered IPs (no key needed)
    internetdb_results = {}
    all_ips = list(set(
        ([args.ip] if args.ip else []) +
        list(pivot_results.get("urlscan", {}).get("ips_seen", []))[:5]
    ))
    if all_ips and "internetdb" not in skip:
        _progress(f"Shodan InternetDB ({len(all_ips[:3])} IPs)", args.quiet)
        for ip in all_ips[:3]:
            internetdb_results[ip] = pivot_internetdb(ip, timeout=args.timeout)
            time.sleep(0.2)
        pivot_results["internetdb"] = internetdb_results

    # ThreatFox + URLhaus IOC matching (opt-in with --threatcheck)
    if args.threatcheck:
        _progress("ThreatFox + URLhaus IOC matching", args.quiet)
        # Build IOC list from what we've found
        iocs_to_check = []
        if args.domain:
            iocs_to_check.append({"type": "domain", "value": args.domain})
        for ip in all_ips[:3]:
            iocs_to_check.append({"type": "ip", "value": ip})
        pivot_results["threatmatch"] = bulk_check_iocs(iocs_to_check, timeout=args.timeout)

    # depth-2 pivots (optional)
    depth2_results = {}
    if args.depth == 2:
        depth2_results = run_depth2(args, skip, pivot_results, args.quiet)

    if not args.quiet:
        print("\n[*] running attribution engine...\n")

    # engine
    cert_clusters  = cluster_certs(pivot_results.get("crtsh", {}))
    whois_clusters = cluster_whois(pivot_results.get("rdap", {}))
    asn_score      = score_asn(pivot_results.get("bgphe", {}), pivot_results.get("abuseip", {}))
    report         = build_confidence_report(
        domain=args.domain, ip=args.ip,
        cert_clusters=cert_clusters,
        whois_clusters=whois_clusters,
        asn_score=asn_score,
        pivot_results=pivot_results,
        depth2=depth2_results
    )

    # Add passive DNS findings
    pdns = pivot_results.get("passivedns", {})
    if pdns and pdns.get("resolution_count", 0) > 0:
        report["meta"]["sources_used"].append("HackerTarget")
        report["infrastructure"]["passivedns_resolutions"] = pdns.get("resolution_count", 0)
        report["infrastructure"]["shared_hosts"] = pdns.get("shared_hosts", [])
        for dom in pdns.get("unique_domains", [])[:20]:
            report["iocs"].append({
                "type": "domain", "value": dom,
                "defanged": dom.replace(".", "[.]"),
                "source": "passivedns"
            })
        if pdns.get("shared_hosts"):
            report["findings"].append({
                "text": f"{len(pdns['shared_hosts'])} domain(s) co-hosted on same infrastructure",
                "confidence": "ANALYST ASSESSMENT",
                "source": "HackerTarget"
            })

    # Add phishing kit findings
    phish = pivot_results.get("phishdetect", {})
    if phish and phish.get("kit_detected"):
        report["findings"].extend(phish.get("findings", []))
        report["infrastructure"]["phishing_score"] = phish.get("phishing_score")
        report["infrastructure"]["phishing_titles"] = phish.get("matched_titles", [])

    # Add InternetDB findings
    if internetdb_results:
        report["meta"]["sources_used"].append("Shodan InternetDB")
        idb_summary = []
        for ip, idb in internetdb_results.items():
            errors = idb.get("errors", [])
            ports  = idb.get("ports", [])
            tags   = idb.get("tags", [])
            vulns  = idb.get("vulns", [])
            risk   = idb.get("risk_label", "UNKNOWN")

            if errors:
                # Still report what we know even with errors
                idb_summary.append(f"{ip}: no data (InternetDB)")
                continue

            # Always add a finding for each IP we checked
            if risk in ("HIGH-RISK", "SUSPICIOUS"):
                reasons = idb.get("risk_reasons", [])
                report["findings"].append({
                    "text": f"{ip}: {risk} — {'; '.join(reasons[:2])}",
                    "confidence": "CONFIRMED" if risk == "HIGH-RISK" else "ANALYST ASSESSMENT",
                    "source": "Shodan InternetDB"
                })
            elif ports:
                report["findings"].append({
                    "text": f"{ip}: {len(ports)} open ports ({', '.join(str(p) for p in ports[:5])})",
                    "confidence": "ANALYST ASSESSMENT",
                    "source": "Shodan InternetDB"
                })

            if tags:
                report["infrastructure"][f"internetdb_{ip}_tags"] = tags
                if any(t in ("c2", "botnet", "malware", "phishing") for t in tags):
                    report["findings"].append({
                        "text": f"{ip} tagged as: {', '.join(tags)} by Shodan",
                        "confidence": "CONFIRMED",
                        "source": "Shodan InternetDB"
                    })

            if vulns:
                report["findings"].append({
                    "text": f"{ip}: {len(vulns)} known CVE(s) — {', '.join(vulns[:3])}",
                    "confidence": "CONFIRMED",
                    "source": "Shodan InternetDB"
                })

        # Store full InternetDB data for output
        report["infrastructure"]["internetdb"] = internetdb_results

    # Add ThreatFox/URLhaus findings
    tm = pivot_results.get("threatmatch", {})
    if tm:
        if tm.get("matches"):
            report["meta"]["sources_used"].append("ThreatFox/URLhaus")
            for match in tm["matches"]:
                report["findings"].append({
                    "text": f"{match['ioc']} matched in {match['source']}: {match.get('malware') or match.get('threat', 'known malicious')}",
                    "confidence": "CONFIRMED",
                    "source": match["source"]
                })
            if tm.get("malware_families"):
                report["infrastructure"]["malware_families"] = tm["malware_families"]
        # Always store the note for display
        report["infrastructure"]["threatmatch_note"] = tm.get("note")

    # Liveness check (opt-in with --live)
    liveness_data = {}
    if args.live:
        _progress(f"liveness check ({len(report['iocs'][:20])} IOCs)", args.quiet)
        liveness_data = check_liveness(report["iocs"], timeout=5)
        liveness_summary = summarise_liveness(liveness_data)
        report["infrastructure"]["liveness"] = liveness_summary
        if liveness_summary.get("live", 0) > 0:
            report["findings"].append({
                "text": f"{liveness_summary['live']}/{liveness_summary['total']} IOCs are currently LIVE",
                "confidence": "CONFIRMED",
                "source": "liveness-check"
            })

    # output
    out_text = ""
    if args.output == "table":
        print_summary(report, no_color=args.no_color)
        print_evidence_table(report, no_color=args.no_color)
        if args.phishing and phish:
            print_phishing(phish, no_color=args.no_color)
        if args.live and liveness_data:
            print_liveness(liveness_data, no_color=args.no_color)
        if args.threatcheck and pivot_results.get("threatmatch"):
            print_threatmatch(pivot_results["threatmatch"], no_color=args.no_color)
        if args.report:
            report_text = generate_report(report, pivot_results, liveness_data)
            out_file = args.out_file or f"inframap_report_{(args.domain or args.ip or 'output').replace('.','_')}.md"
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(report_text)
            if not args.quiet:
                print(f"\n[✓] investigation report written to {out_file}")
        return
        return
    elif args.output == "csv":
        out_text = export_csv(report)
    elif args.output == "json":
        out_text = export_json(report)
    elif args.output == "markdown":
        out_text = export_markdown(report)

    if args.out_file:
        with open(args.out_file, "w", encoding="utf-8") as f:
            f.write(out_text)
        if not args.quiet:
            print(f"\n[✓] written to {args.out_file}")
    else:
        print(out_text)


if __name__ == "__main__":
    main()
