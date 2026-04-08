#!/usr/bin/env python3
"""
inframap — Infrastructure fingerprinting & attribution engine for CTI analysts.

Tier 0: Runs with zero keys (crt.sh, RDAP, BGP.he.net, HackerTarget,
         Shodan InternetDB, Mnemonic PDNS, CertSpotter, Google CT)
Tier 1: Better results with free account keys (urlscan.io, AbuseIPDB,
         ThreatFox, URLhaus, GreyNoise)
Tier 2: Premium features with paid keys (Shodan full, VirusTotal)

Key management:
  inframap keys set urlscan YOUR_KEY
  inframap keys set threatfox YOUR_KEY
  inframap keys list
  inframap keys remove urlscan

Keys stored encrypted in ~/.config/inframap/keys (chmod 600, never logged)
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
from inframap.pivots.greynoise   import pivot_greynoise, bulk_greynoise
from inframap.pivots.virustotal  import pivot_virustotal_domain, pivot_virustotal_ip
from inframap.pivots.greynoise   import pivot_greynoise, bulk_greynoise
from inframap.pivots.virustotal  import pivot_virustotal_domain, pivot_virustotal_ip
from inframap.engine.cluster     import cluster_certs, cluster_whois, score_asn
from inframap.engine.confidence  import build_confidence_report
from inframap.engine.compare     import compare_domains
from inframap.output.table       import (print_evidence_table, print_summary,
                                          print_compare, print_phishing,
                                          print_hunt, print_liveness,
                                          print_threatmatch)
from inframap.output.export      import export_csv, export_json, export_markdown
from inframap.output.report      import generate_report
from inframap.config             import get_all_keys, set_key, remove_key, print_key_status as _print_key_status, SOURCES
from inframap.validate           import validate_all_args

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
  inframap -d evil.com                          # keyless mode (tier 0 only)
  inframap -d evil.com --threatcheck --live     # with stored keys
  inframap --compare domain1.com domain2.com    # shared operator
  inframap --hunt --keyword "outlook-verify"    # proactive hunting
  inframap -d evil.com --report                 # auto-generate report
  inframap keys set urlscan YOUR_KEY            # store key securely
  inframap keys list                            # show key status
  inframap keys remove urlscan                  # remove a key

tiers:
  tier 0 — no key: crt.sh, RDAP, BGP.he.net, InternetDB, HackerTarget
  tier 1 — free:   urlscan.io, AbuseIPDB, ThreatFox, URLhaus, GreyNoise
  tier 2 — paid:   Shodan full, VirusTotal, SecurityTrails
        """
    )

    p.add_argument("--version", action="version", version=f"inframap {VERSION}")

    seed = p.add_argument_group("seed (provide at least one)")
    seed.add_argument("-d", "--domain",  metavar="DOMAIN")
    seed.add_argument("-i", "--ip",      metavar="IP")
    seed.add_argument("-e", "--email",   metavar="EMAIL")
    seed.add_argument("-c", "--cert",    metavar="HASH")

    modes = p.add_argument_group("modes")
    modes.add_argument("--compare",    nargs=2, metavar=("DOMAIN_A", "DOMAIN_B"))
    modes.add_argument("--phishing",   action="store_true")
    modes.add_argument("--hunt",       action="store_true")
    modes.add_argument("--live",       action="store_true")
    modes.add_argument("--threatcheck",action="store_true")
    modes.add_argument("--report",     action="store_true")
    modes.add_argument("--asn",        metavar="ASN")
    modes.add_argument("--nameserver", metavar="NS")
    modes.add_argument("--keyword",    metavar="KEYWORD")
    modes.add_argument("--days",       type=int, default=30)

    keys_cmd = p.add_argument_group("key management (keys stored encrypted, never logged)")
    keys_cmd.add_argument("keys", nargs="?", choices=["set", "list", "remove", "status"],
                          help="manage API keys: set NAME VALUE | list | remove NAME")
    keys_cmd.add_argument("key_name",  nargs="?", metavar="NAME",
                          help="key name (urlscan, abuseip, threatfox, urlhaus, greynoise, shodan, virustotal)")
    keys_cmd.add_argument("key_value", nargs="?", metavar="VALUE",
                          help="key value (only for 'keys set')")

    opts = p.add_argument_group("options")
    opts.add_argument("--depth",    type=int, default=1, choices=[1,2])
    opts.add_argument("--skip",     nargs="+", metavar="SOURCE")
    opts.add_argument("-o", "--output", default="table",
                      choices=["table","csv","json","markdown"])
    opts.add_argument("--out-file", metavar="FILE")
    opts.add_argument("-q", "--quiet",   action="store_true")
    opts.add_argument("--no-color",      action="store_true")
    opts.add_argument("--timeout", type=int, default=10)

    return p.parse_args()


def handle_keys_command(args):
    """Handle inframap keys set/list/remove commands."""
    cmd = args.keys

    if cmd == "list" or cmd == "status":
        print()
        _print_key_status()
        print()
        return True

    if cmd == "set":
        if not args.key_name or not args.key_value:
            print("[!] usage: inframap keys set NAME VALUE")
            print("[!] names: urlscan, abuseip, threatfox, urlhaus, greynoise, shodan, virustotal")
            return True
        try:
            from inframap.validate import sanitize_api_key
            clean_val = sanitize_api_key(args.key_value)
            if not clean_val:
                print("[!] key value cannot be empty")
                return True
            set_key(args.key_name, clean_val)
            print(f"[✓] {args.key_name} key stored securely in ~/.config/inframap/keys")
            print(f"    permissions: 600 (owner read/write only)")
        except ValueError as e:
            print(f"[!] {e}")
        return True

    if cmd == "remove":
        if not args.key_name:
            print("[!] usage: inframap keys remove NAME")
            return True
        remove_key(args.key_name)
        print(f"[✓] {args.key_name} key removed")
        return True

    return False


def validate_args(args):
    """Validate and sanitize all inputs."""
    if args.keys:
        return  # handled separately

    if args.compare:
        return
    if args.hunt:
        if not any([args.asn, args.nameserver, args.keyword]):
            print("[!] --hunt requires: --asn ASN | --nameserver NS | --keyword WORD")
            sys.exit(1)
        return
    if not any([args.domain, args.ip, args.email, args.cert]):
        print("[!] provide a seed: -d DOMAIN | -i IP | -e EMAIL | -c HASH")
        print("[!] or use: --compare A B | --hunt --keyword WORD | keys list")
        sys.exit(1)

    # Run full validation and sanitization
    errors = validate_all_args(args)
    if errors:
        for err in errors:
            print(f"[!] {err}")
        sys.exit(1)


def run_pivots(args, skip, keys):
    results     = {}
    seed_domain = args.domain
    seed_ip     = args.ip

    if "crtsh" not in skip and seed_domain:
        _progress("crt.sh", args.quiet)
        results["crtsh"] = pivot_crtsh(seed_domain, timeout=args.timeout)

    if "rdap" not in skip and seed_domain:
        _progress("RDAP / WHOIS", args.quiet)
        results["rdap"] = pivot_rdap(seed_domain, timeout=args.timeout)

    if "urlscan" not in skip:
        urlscan_key = keys.get("urlscan")
        if urlscan_key:
            _progress("urlscan.io (tier 1 key)", args.quiet)
        else:
            _progress("urlscan.io (keyless — add key for more results)", args.quiet)
        results["urlscan"] = pivot_urlscan(
            domain=seed_domain, ip=seed_ip,
            api_key=urlscan_key, timeout=args.timeout
        )

    # Auto-pivot discovered IPs
    discovered_ips = list(results.get("urlscan", {}).get("ips_seen", []))[:3]
    ips_to_check   = list(set(([seed_ip] if seed_ip else []) + discovered_ips))[:3]

    if ips_to_check:
        abuseip_key  = keys.get("abuseip")
        greynoise_key = keys.get("greynoise")

        if "abuseip" not in skip:
            if abuseip_key:
                _progress(f"AbuseIPDB ({len(ips_to_check)} IPs)", args.quiet)
                results["abuseip"] = pivot_abuseip(ips_to_check[0], api_key=abuseip_key, timeout=args.timeout)
                results["abuseip_extra"] = []
                for ip in ips_to_check[1:]:
                    time.sleep(0.5)
                    results["abuseip_extra"].append(pivot_abuseip(ip, api_key=abuseip_key, timeout=args.timeout))
            else:
                _progress_skip("AbuseIPDB", "abuseip", args.quiet)

        if "bgphe" not in skip:
            _progress(f"BGP.he.net ({len(ips_to_check)} IPs)", args.quiet)
            results["bgphe"] = pivot_bgphe(ips_to_check[0], timeout=args.timeout)
            results["bgphe_extra"] = []
            for ip in ips_to_check[1:]:
                time.sleep(0.3)
                results["bgphe_extra"].append(pivot_bgphe(ip, args.timeout))

        # GreyNoise — runs keyless via community endpoint, better with free key
        if "greynoise" not in skip:
            gn_mode = "with key" if greynoise_key else "community (keyless)"
            _progress(f"GreyNoise ({gn_mode}, {len(ips_to_check)} IPs)", args.quiet)
            results["greynoise"] = {}
            for ip in ips_to_check:
                results["greynoise"][ip] = pivot_greynoise(ip, api_key=greynoise_key, timeout=args.timeout)
                time.sleep(0.3)
    elif "bgphe" not in skip and not seed_ip:
        if not args.quiet:
            print(f"  [~] BGP/AbuseIPDB skipped — no IP discovered yet")

    return results


def _progress(source, quiet):
    if not quiet:
        print(f"  [+] {source}...", flush=True)


def _progress_skip(source, key_name, quiet):
    if not quiet:
        signup = SOURCES.get(key_name, {}).get("signup", "")
        print(f"  [~] {source} skipped — add key: inframap keys set {key_name} YOUR_KEY"
              + (f"  ({signup})" if signup else ""), flush=True)


def run_depth2(args, skip, keys, pivot_results, quiet):
    discovered_ips     = set()
    discovered_domains = set()

    for cert in pivot_results.get("crtsh", {}).get("certs", []):
        for name in cert.get("names", []):
            if name and name != args.domain:
                discovered_domains.add(name.lstrip("*."))

    for scan in pivot_results.get("urlscan", {}).get("results", []):
        ip = scan.get("page", {}).get("ip")
        if ip:
            discovered_ips.add(ip)

    if not quiet:
        print(f"\n[~] depth-2: {len(discovered_ips)} IPs, {len(discovered_domains)} domains")

    depth2 = {"ips": {}, "domains": {}}
    abuseip_key = keys.get("abuseip")

    for ip in list(discovered_ips)[:5]:
        if "abuseip" not in skip and abuseip_key:
            depth2["ips"][ip] = {"abuseip": pivot_abuseip(ip, abuseip_key, args.timeout)}
            time.sleep(0.5)
        if "bgphe" not in skip:
            depth2["ips"].setdefault(ip, {})["bgphe"] = pivot_bgphe(ip, args.timeout)
            time.sleep(0.5)

    for domain in list(discovered_domains)[:5]:
        if "rdap" not in skip:
            depth2["domains"][domain] = {"rdap": pivot_rdap(domain, args.timeout)}
            time.sleep(0.3)

    return depth2


def main():
    args = parse_args()

    # Handle key management commands first
    if args.keys:
        handle_keys_command(args)
        return

    validate_args(args)
    skip = set(args.skip or [])

    # Load all keys securely from encrypted store / env vars
    keys = get_all_keys()

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
        hunt_timeout = max(args.timeout, 30)
        hunt_result  = hunt_infrastructure(
            asn=args.asn, nameserver=args.nameserver,
            keyword=args.keyword, days=args.days, timeout=hunt_timeout
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

        urlscan_key = keys.get("urlscan")
        _progress(f"RDAP → {domain_a}", args.quiet)
        rdap_a    = pivot_rdap(domain_a, args.timeout)
        _progress(f"crt.sh → {domain_a}", args.quiet)
        crtsh_a   = pivot_crtsh(domain_a, args.timeout)
        _progress(f"passive DNS → {domain_a}", args.quiet)
        pdns_a    = pivot_passivedns(domain=domain_a, timeout=args.timeout)
        _progress(f"urlscan.io → {domain_a}", args.quiet)
        urlscan_a = pivot_urlscan(domain=domain_a, api_key=urlscan_key, timeout=args.timeout)
        time.sleep(0.5)

        _progress(f"RDAP → {domain_b}", args.quiet)
        rdap_b    = pivot_rdap(domain_b, args.timeout)
        _progress(f"crt.sh → {domain_b}", args.quiet)
        crtsh_b   = pivot_crtsh(domain_b, args.timeout)
        _progress(f"passive DNS → {domain_b}", args.quiet)
        pdns_b    = pivot_passivedns(domain=domain_b, timeout=args.timeout)
        _progress(f"urlscan.io → {domain_b}", args.quiet)
        urlscan_b = pivot_urlscan(domain=domain_b, api_key=urlscan_key, timeout=args.timeout)

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
        ]))
        all_sources = ['crtsh','rdap','urlscan','bgphe','passivedns','internetdb']
        if keys.get("abuseip"): all_sources.append('abuseip')
        if args.phishing:       all_sources.append('phishdetect')
        if args.threatcheck:    all_sources.append('threatfox/urlhaus')

        # Count configured keys (masked)
        configured = [k for k in ["urlscan","abuseip","threatfox","urlhaus","greynoise"] if keys.get(k)]
        key_str    = f"{len(configured)} key(s) loaded" if configured else "keyless mode (tier 0)"

        print(f"[*] seed      : {seed_str}")
        print(f"[*] sources   : {', '.join(s for s in all_sources if s not in skip)}")
        print(f"[*] keys      : {key_str}")
        print(f"[*] output    : {args.output}")
        print()

    pivot_results = run_pivots(args, skip, keys)

    # Passive DNS
    if "passivedns" not in skip and args.domain:
        _progress("HackerTarget passive DNS", args.quiet)
        pivot_results["passivedns"] = pivot_passivedns(
            domain=args.domain, ip=args.ip, timeout=args.timeout
        )

    # Phishing kit detection
    if args.phishing and "phishdetect" not in skip and args.domain:
        _progress("phishing kit detection", args.quiet)
        crtsh_data = pivot_results.get("crtsh", {})
        rdap_data  = pivot_results.get("rdap", {})
        bgphe_data = pivot_results.get("bgphe", {})
        pivot_results["phishdetect"] = detect_phishing_kit(
            domain=args.domain,
            api_key=keys.get("urlscan"),
            timeout=args.timeout,
            domain_age_days=rdap_data.get("domain_age_days"),
            cert_fast_spin=any(c.get("suspicious") for c in crtsh_data.get("timing_clusters", [])),
            cert_count=crtsh_data.get("cert_count", 0),
            asn=bgphe_data.get("asn"),
            has_wildcard_san=len([n for n in crtsh_data.get("unique_names", []) if n.startswith("*.")]) > 0
        )

    # Shodan InternetDB (tier 0 — no key needed)
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

    # GreyNoise (tier 1 — free key, 100/day)
    greynoise_key = keys.get("greynoise")
    if all_ips and "greynoise" not in skip:
        if greynoise_key:
            _progress(f"GreyNoise ({len(all_ips[:5])} IPs)", args.quiet)
            pivot_results["greynoise"] = bulk_greynoise(
                all_ips[:5], api_key=greynoise_key, timeout=args.timeout
            )
        else:
            _progress_skip("GreyNoise", "greynoise", args.quiet)

    # VirusTotal (tier 1 — free key, 4/min)
    vt_key = keys.get("virustotal")
    if "virustotal" not in skip:
        if vt_key and args.domain:
            _progress("VirusTotal domain lookup", args.quiet)
            pivot_results["virustotal"] = pivot_virustotal_domain(
                args.domain, api_key=vt_key, timeout=args.timeout
            )
            if all_ips:
                time.sleep(15)  # VT free tier: 4/min = 15s between calls
                _progress(f"VirusTotal IP lookup", args.quiet)
                pivot_results["virustotal_ip"] = pivot_virustotal_ip(
                    all_ips[0], api_key=vt_key, timeout=args.timeout
                )
        elif not vt_key:
            _progress_skip("VirusTotal", "virustotal", args.quiet)

    # ThreatFox + URLhaus (tier 1 — needs free key)
    if args.threatcheck:
        tf_key = keys.get("threatfox")
        uh_key = keys.get("urlhaus")
        if not tf_key and not uh_key:
            if not args.quiet:
                print(f"  [~] ThreatFox/URLhaus — add keys for threat matching:")
                print(f"      inframap keys set threatfox YOUR_KEY  (free: auth.abuse.ch)")
                print(f"      inframap keys set urlhaus YOUR_KEY    (same account)")
        else:
            _progress("ThreatFox + URLhaus IOC matching", args.quiet)
            iocs_to_check = []
            if args.domain:
                iocs_to_check.append({"type": "domain", "value": args.domain})
            for ip in all_ips[:3]:
                iocs_to_check.append({"type": "ip", "value": ip})
            pivot_results["threatmatch"] = bulk_check_iocs(
                iocs_to_check,
                timeout=args.timeout,
                threatfox_key=tf_key,
                urlhaus_key=uh_key
            )

    # Depth-2
    depth2_results = {}
    if args.depth == 2:
        depth2_results = run_depth2(args, skip, keys, pivot_results, args.quiet)

    if not args.quiet:
        print("\n[*] running attribution engine...\n")

    # Engine
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
                "defanged": dom.replace(".", "[.]"), "source": "passivedns"
            })
        if pdns.get("shared_hosts"):
            report["findings"].append({
                "text": f"{len(pdns['shared_hosts'])} domain(s) co-hosted on same infrastructure",
                "confidence": "ANALYST ASSESSMENT", "source": "HackerTarget"
            })

    # Add phishing findings
    phish = pivot_results.get("phishdetect", {})
    if phish and phish.get("kit_detected"):
        report["findings"].extend(phish.get("findings", []))
        report["infrastructure"]["phishing_score"]  = phish.get("phishing_score")
        report["infrastructure"]["phishing_titles"] = phish.get("matched_titles", [])

    # Add InternetDB findings
    if internetdb_results:
        report["meta"]["sources_used"].append("Shodan InternetDB")
        for ip, idb in internetdb_results.items():
            errors = idb.get("errors", [])
            ports  = idb.get("ports", [])
            tags   = idb.get("tags", [])
            vulns  = idb.get("vulns", [])
            risk   = idb.get("risk_label", "UNKNOWN")

            if errors:
                continue

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

            if tags and any(t in ("c2", "botnet", "malware", "phishing") for t in tags):
                report["findings"].append({
                    "text": f"{ip} tagged: {', '.join(tags)} (Shodan)",
                    "confidence": "CONFIRMED", "source": "Shodan InternetDB"
                })

            if vulns:
                report["findings"].append({
                    "text": f"{ip}: {len(vulns)} known CVE(s) — {', '.join(vulns[:3])}",
                    "confidence": "CONFIRMED", "source": "Shodan InternetDB"
                })

        report["infrastructure"]["internetdb"] = internetdb_results

    # Add GreyNoise findings
    gn_results = pivot_results.get("greynoise", {})
    if gn_results:
        report["meta"]["sources_used"].append("GreyNoise")
        for ip, gn in gn_results.items():
            if gn.get("errors"):
                continue
            classification = gn.get("classification", "unknown")
            noise = gn.get("noise", False)
            riot  = gn.get("riot", False)

            if riot:
                report["findings"].append({
                    "text": f"{ip} is known benign infrastructure ({gn.get('name', 'RIOT')}) — deprioritise",
                    "confidence": "CONFIRMED",
                    "source": "GreyNoise"
                })
            elif noise and classification == "benign":
                report["findings"].append({
                    "text": f"{ip} is internet background noise (scanner) — likely not threat actor",
                    "confidence": "CONFIRMED",
                    "source": "GreyNoise"
                })
            elif classification == "malicious":
                report["findings"].append({
                    "text": f"{ip} classified MALICIOUS by GreyNoise — confirmed threat activity",
                    "confidence": "CONFIRMED",
                    "source": "GreyNoise"
                })
                # Boost confidence score for confirmed malicious
                report["attribution"]["confidence_score"] = min(
                    report["attribution"]["confidence_score"] + 15, 100
                )

    # Add VirusTotal findings (if key configured)
    vt_key = keys.get("virustotal")
    if vt_key and args.domain:
        _progress("VirusTotal", args.quiet)
        vt_result = pivot_virustotal_domain(args.domain, api_key=vt_key, timeout=args.timeout)
        pivot_results["virustotal"] = vt_result
        if not vt_result.get("errors"):
            report["meta"]["sources_used"].append("VirusTotal")
            malicious = vt_result.get("malicious", 0)
            total     = vt_result.get("total_votes", 0)
            verdict   = vt_result.get("verdict")
            if malicious > 0:
                report["findings"].append({
                    "text": f"VirusTotal: {malicious}/{total} vendors flag as malicious — verdict: {verdict}",
                    "confidence": "CONFIRMED" if malicious >= 5 else "ANALYST ASSESSMENT",
                    "source": "VirusTotal"
                })
            if vt_result.get("categories"):
                cats = ", ".join(list(vt_result["categories"])[:3])
                report["findings"].append({
                    "text": f"VirusTotal categories: {cats}",
                    "confidence": "ANALYST ASSESSMENT",
                    "source": "VirusTotal"
                })
            # Add related IPs as IOCs
            for related_ip in vt_result.get("related_ips", [])[:5]:
                report["iocs"].append({
                    "type": "ip", "value": related_ip,
                    "defanged": related_ip.replace(".", "[.]"),
                    "source": "VirusTotal"
                })
    tm = pivot_results.get("threatmatch", {})
    if tm:
        if tm.get("matches"):
            report["meta"]["sources_used"].append("ThreatFox/URLhaus")
            for match in tm["matches"]:
                report["findings"].append({
                    "text": f"{match['ioc']} in {match['source']}: {match.get('malware') or match.get('threat', 'known malicious')}",
                    "confidence": "CONFIRMED", "source": match["source"]
                })
            if tm.get("malware_families"):
                report["infrastructure"]["malware_families"] = tm["malware_families"]
        report["infrastructure"]["threatmatch_note"] = tm.get("note")

    # Liveness check
    liveness_data = {}
    if args.live:
        _progress(f"liveness check ({len(report['iocs'][:20])} IOCs)", args.quiet)
        liveness_data = check_liveness(report["iocs"], timeout=5)
        liveness_summary = summarise_liveness(liveness_data)
        report["infrastructure"]["liveness"] = liveness_summary
        if liveness_summary.get("live", 0) > 0:
            report["findings"].append({
                "text": f"{liveness_summary['live']}/{liveness_summary['total']} IOCs currently LIVE",
                "confidence": "CONFIRMED", "source": "liveness-check"
            })

    # Output
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
                print(f"\n[✓] report written to {out_file}")
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
