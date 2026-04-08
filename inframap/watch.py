"""
inframap --watch mode — continuous infrastructure monitoring.

Runs inframap on a domain at a set interval and alerts when anything changes:
  - New certificates issued
  - New domains discovered
  - IOC count changes
  - Confidence score changes
  - New IPs discovered
  - Liveness changes (live → dead or dead → live)

No API key required for core monitoring. Tier 1 keys enhance detection.

Usage:
  inframap --watch -d evil.com                    # check every 24h
  inframap --watch -d evil.com --interval 6       # check every 6h
  inframap --watch -d evil.com --interval 1       # check every 1h
  inframap --watch -d evil.com --alert-file alerts.json  # save alerts
  inframap --watch -d evil.com --baseline         # reset baseline

State stored in: ~/.config/inframap/watch/{domain}.json
"""

import json
import os
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path


WATCH_DIR  = Path.home() / ".config" / "inframap" / "watch"
USER_AGENT = "inframap/1.5 (github.com/rkbrainstorms/inframap; CTI research)"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_baseline(domain: str) -> dict:
    """Load saved baseline for a domain."""
    WATCH_DIR.mkdir(parents=True, exist_ok=True)
    path = WATCH_DIR / f"{domain.replace('.', '_')}.json"
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            return {}
    return {}


def _save_baseline(domain: str, state: dict):
    """Save current state as baseline."""
    WATCH_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(WATCH_DIR, 0o700)
    path = WATCH_DIR / f"{domain.replace('.', '_')}.json"
    path.write_text(json.dumps(state, indent=2))
    os.chmod(path, 0o600)


def _extract_state(report: dict, pivot_results: dict) -> dict:
    """Extract comparable state from a scan result."""
    iocs       = report.get("iocs", [])
    findings   = report.get("findings", [])
    infra      = report.get("infrastructure", {})
    attr       = report.get("attribution", {})

    domains = sorted(set(
        i["value"] for i in iocs if i.get("type") == "domain"
        and not i.get("value", "").startswith("*")
    ))
    ips = sorted(set(
        i["value"] for i in iocs if i.get("type") == "ip"
    ))
    asns = sorted(set(
        i["value"] for i in iocs if i.get("type") == "asn"
    ))

    # Liveness snapshot
    liveness = infra.get("liveness", {})

    return {
        "timestamp":      _now(),
        "cert_count":     infra.get("cert_count", 0),
        "domain_count":   infra.get("unique_domains", 0),
        "urlscan_hits":   infra.get("urlscan_hits", 0),
        "confidence":     attr.get("confidence_score", 0),
        "tier":           attr.get("tier_label", ""),
        "asn":            infra.get("asn", ""),
        "hosting_risk":   infra.get("hosting_risk", ""),
        "domains":        domains,
        "ips":            ips,
        "asns":           asns,
        "live_count":     liveness.get("live", 0),
        "dead_count":     liveness.get("dead", 0),
        "live_iocs":      sorted(liveness.get("live_iocs", [])),
        "finding_count":  len(findings),
        "phishing_score": infra.get("phishing_score", 0),
        "malware_families": infra.get("malware_families", []),
    }


def _diff_states(old: dict, new: dict, domain: str) -> list:
    """
    Compare old and new states and return list of alert dicts.
    Each alert has: severity, category, message, old_value, new_value
    """
    alerts = []

    def alert(severity, category, message, old_val=None, new_val=None):
        alerts.append({
            "timestamp":  _now(),
            "domain":     domain,
            "severity":   severity,
            "category":   category,
            "message":    message,
            "old_value":  old_val,
            "new_value":  new_val
        })

    # Confidence score change
    old_score = old.get("confidence", 0)
    new_score = new.get("confidence", 0)
    if abs(new_score - old_score) >= 10:
        severity = "HIGH" if new_score > old_score else "MEDIUM"
        alert(severity, "confidence",
              f"Confidence score changed: {old_score} → {new_score}",
              old_score, new_score)

    # New certificates
    old_certs = old.get("cert_count", 0)
    new_certs = new.get("cert_count", 0)
    if new_certs > old_certs:
        alert("HIGH", "certificates",
              f"New certificates issued: {old_certs} → {new_certs} (+{new_certs - old_certs})",
              old_certs, new_certs)

    # New domains discovered
    old_domains = set(old.get("domains", []))
    new_domains  = set(new.get("domains", []))
    added_domains = new_domains - old_domains
    removed_domains = old_domains - new_domains
    if added_domains:
        alert("HIGH", "new_domains",
              f"{len(added_domains)} new domain(s) discovered: {', '.join(sorted(added_domains)[:5])}",
              None, sorted(added_domains))
    if removed_domains:
        alert("MEDIUM", "removed_domains",
              f"{len(removed_domains)} domain(s) no longer visible: {', '.join(sorted(removed_domains)[:5])}",
              sorted(removed_domains), None)

    # New IPs
    old_ips = set(old.get("ips", []))
    new_ips  = set(new.get("ips", []))
    added_ips = new_ips - old_ips
    if added_ips:
        alert("HIGH", "new_ips",
              f"New IP(s) discovered: {', '.join(sorted(added_ips))}",
              None, sorted(added_ips))

    # ASN change (infrastructure migration)
    if old.get("asn") and new.get("asn") and old["asn"] != new["asn"]:
        alert("HIGH", "asn_change",
              f"ASN changed: {old['asn']} → {new['asn']} — possible infrastructure migration",
              old["asn"], new["asn"])

    # Liveness changes
    old_live = set(old.get("live_iocs", []))
    new_live  = set(new.get("live_iocs", []))
    went_live = new_live - old_live
    went_dead = old_live - new_live
    if went_live:
        alert("HIGH", "ioc_live",
              f"{len(went_live)} IOC(s) came LIVE: {', '.join(sorted(went_live)[:3])}",
              None, sorted(went_live))
    if went_dead:
        alert("MEDIUM", "ioc_dead",
              f"{len(went_dead)} IOC(s) went DEAD (infrastructure taken down?): {', '.join(sorted(went_dead)[:3])}",
              sorted(went_dead), None)

    # Phishing score change
    old_phish = old.get("phishing_score", 0)
    new_phish = new.get("phishing_score", 0)
    if new_phish > old_phish and new_phish >= 60:
        alert("CRITICAL", "phishing",
              f"Phishing score increased: {old_phish} → {new_phish}",
              old_phish, new_phish)

    # New malware families
    old_mal = set(old.get("malware_families", []))
    new_mal  = set(new.get("malware_families", []))
    new_families = new_mal - old_mal
    if new_families:
        alert("CRITICAL", "malware",
              f"New malware family association: {', '.join(new_families)}",
              None, sorted(new_families))

    return alerts


def _print_alerts(alerts: list, no_color: bool = False):
    """Print alerts to terminal."""
    if not alerts:
        return

    COLORS = {
        "CRITICAL": "\033[91m",  # bright red
        "HIGH":     "\033[31m",  # red
        "MEDIUM":   "\033[33m",  # yellow
        "LOW":      "\033[34m",  # blue
        "RESET":    "\033[0m"
    }

    if no_color:
        COLORS = {k: "" for k in COLORS}

    print()
    print(f"  {'━'*62}")
    print(f"  INFRAMAP WATCH ALERTS — {alerts[0]['timestamp'][:10]}")
    print(f"  {'━'*62}")

    for a in alerts:
        sev   = a.get("severity", "LOW")
        cat   = a.get("category", "")
        msg   = a.get("message", "")
        color = COLORS.get(sev, "")
        reset = COLORS["RESET"]
        print(f"  {color}[{sev}]{reset} {cat}: {msg}")

    print()


def _save_alerts(alerts: list, alert_file: str):
    """Append alerts to a JSON file."""
    existing = []
    if os.path.exists(alert_file):
        try:
            existing = json.loads(open(alert_file).read())
        except Exception:
            existing = []
    existing.extend(alerts)
    with open(alert_file, "w") as f:
        json.dump(existing, f, indent=2)


def run_watch(domain: str, interval_hours: int = 24,
              reset_baseline: bool = False,
              alert_file: str = None,
              no_color: bool = False,
              quiet: bool = False,
              run_once: bool = False,
              scan_fn=None):
    """
    Main watch loop. Runs scan_fn repeatedly and diffs results.

    scan_fn: callable(domain) -> (report, pivot_results)
    """
    if scan_fn is None:
        raise ValueError("scan_fn required")

    baseline = {} if reset_baseline else _load_baseline(domain)

    if reset_baseline and not quiet:
        print(f"  [watch] baseline reset for {domain}")

    interval_secs = interval_hours * 3600
    run_count     = 0

    while True:
        run_count += 1
        now = _now()

        if not quiet:
            print(f"\n  [watch] scanning {domain} — {now} (run #{run_count})")

        try:
            report, pivot_results = scan_fn(domain)
            current_state = _extract_state(report, pivot_results)

            if not baseline:
                # First run — establish baseline
                _save_baseline(domain, current_state)
                baseline = current_state
                if not quiet:
                    print(f"  [watch] baseline established for {domain}")
                    print(f"          certs={current_state['cert_count']} "
                          f"domains={current_state['domain_count']} "
                          f"confidence={current_state['confidence']}/100")
            else:
                # Diff against baseline
                alerts = _diff_states(baseline, current_state, domain)

                if alerts:
                    _print_alerts(alerts, no_color=no_color)
                    if alert_file:
                        _save_alerts(alerts, alert_file)
                        if not quiet:
                            print(f"  [watch] {len(alerts)} alert(s) saved to {alert_file}")
                    # Update baseline to current state
                    _save_baseline(domain, current_state)
                    baseline = current_state
                else:
                    if not quiet:
                        print(f"  [watch] no changes detected — "
                              f"certs={current_state['cert_count']} "
                              f"live={current_state['live_count']} "
                              f"confidence={current_state['confidence']}/100")

        except KeyboardInterrupt:
            print(f"\n  [watch] stopped by user")
            break
        except Exception as e:
            if not quiet:
                print(f"  [watch] scan error: {str(e)}")

        if run_once:
            break

        if not quiet:
            next_run = datetime.now(timezone.utc)
            print(f"  [watch] next check in {interval_hours}h "
                  f"(Ctrl+C to stop)")

        try:
            time.sleep(interval_secs)
        except KeyboardInterrupt:
            print(f"\n  [watch] stopped by user")
            break
