#!/usr/bin/env python3
"""
inframap — Open-source infrastructure fingerprinting & attribution engine
Pivots across crt.sh, RDAP, urlscan.io, AbuseIPDB, and BGP.he.net
using only free/no-key APIs. Built for the CTI community.

Usage:
    python inframap.py -d example.com
    python inframap.py -i 1.2.3.4 --urlscan-key YOUR_KEY
    python inframap.py -d example.com -o csv
    python inframap.py -d example.com --depth 2 --quiet
"""

import argparse
import sys
import os
import json
import time

from inframap.pivots.crtsh   import pivot_crtsh
from inframap.pivots.rdap    import pivot_rdap
from inframap.pivots.urlscan import pivot_urlscan
from inframap.pivots.abuseip import pivot_abuseip
from inframap.pivots.bgphe   import pivot_bgphe
from inframap.engine.cluster  import cluster_certs, cluster_whois, score_asn
from inframap.engine.confidence import build_confidence_report
from inframap.output.table   import print_evidence_table, print_summary
from inframap.output.export  import export_csv, export_json, export_markdown

VERSION = "1.1.0"

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
  python inframap.py -d example.com
  python inframap.py -i 1.2.3.4 --abuseip-key YOUR_KEY
  python inframap.py -d example.com --urlscan-key YOUR_KEY -o markdown
  python inframap.py -d example.com --depth 2 --quiet -o csv
  python inframap.py -d example.com --skip crtsh bgphe

api keys (all optional, all free):
  urlscan.io  : https://urlscan.io/user/signup  (1000 searches/day free)
  AbuseIPDB   : https://www.abuseipdb.com/register (1000 checks/day free)
  crt.sh      : no key needed
  RDAP        : no key needed
  BGP.he.net  : no key needed
        """
    )

    p.add_argument("--version", action="version", version=f"inframap {VERSION}")

    seed = p.add_argument_group("seed (provide at least one)")
    seed.add_argument("-d", "--domain",  metavar="DOMAIN", help="seed domain (e.g. evil.com)")
    seed.add_argument("-i", "--ip",      metavar="IP",     help="seed IP address")
    seed.add_argument("-e", "--email",   metavar="EMAIL",  help="registrant email for WHOIS pivoting")
    seed.add_argument("-c", "--cert",    metavar="HASH",   help="certificate SHA-256 fingerprint")

    keys = p.add_argument_group("api keys (optional, all free-tier)")
    keys.add_argument("--urlscan-key",  metavar="KEY", default=os.environ.get("URLSCAN_API_KEY"),
                      help="urlscan.io API key (or set URLSCAN_API_KEY env var)")
    keys.add_argument("--abuseip-key",  metavar="KEY", default=os.environ.get("ABUSEIPDB_API_KEY"),
                      help="AbuseIPDB API key (or set ABUSEIPDB_API_KEY env var)")

    opts = p.add_argument_group("options")
    opts.add_argument("--depth",  type=int, default=1, choices=[1,2],
                      help="pivot depth: 1=seed only, 2=pivot on discovered IPs/domains (default: 1)")
    opts.add_argument("--skip",   nargs="+", metavar="SOURCE",
                      choices=["crtsh","rdap","urlscan","abuseip","bgphe"],
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
    if not any([args.domain, args.ip, args.email, args.cert]):
        print("[!] provide at least one seed: -d DOMAIN | -i IP | -e EMAIL | -c CERT_HASH")
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
        seed_str = " | ".join(filter(None, [
            args.domain and f"domain={args.domain}",
            args.ip     and f"ip={args.ip}",
            args.email  and f"email={args.email}",
            args.cert   and f"cert={args.cert[:16]}...",
        ]))
        print(f"[*] seed      : {seed_str}")
        print(f"[*] depth     : {args.depth}")
        print(f"[*] sources   : {', '.join(s for s in ['crtsh','rdap','urlscan','abuseip','bgphe'] if s not in skip)}")
        keys_loaded = []
        if args.urlscan_key: keys_loaded.append("urlscan")
        if args.abuseip_key: keys_loaded.append("abuseip")
        print(f"[*] api keys  : {', '.join(keys_loaded) if keys_loaded else 'none (keyless mode)'}")
        print(f"[*] output    : {args.output}")
        print()

    # depth-1 pivots
    pivot_results = run_pivots(args, skip)

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

    # output
    out_text = ""
    if args.output == "table":
        print_summary(report, no_color=args.no_color)
        print_evidence_table(report, no_color=args.no_color)
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
