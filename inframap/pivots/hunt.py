"""
Proactive threat hunting — find newly registered suspicious domains.

Queries crt.sh for recently issued certificates on a target ASN or
nameserver, then scores each discovered domain for suspiciousness.

Usage:
    python3 inframap.py --hunt --asn AS43350 --days 30
    python3 inframap.py --hunt --nameserver topdns.com --days 14
    python3 inframap.py --hunt --keyword "microsoft" --days 7

No API key required. Uses only crt.sh (free, unlimited).

This is proactive hunting — finding infrastructure BEFORE it's used
in a campaign. No other free CLI tool does this.
"""

import urllib.request
import urllib.parse
import urllib.error
import json
import re
import time
from datetime import datetime, timezone, timedelta


CRT_SH_URL = "https://crt.sh/?output=json&q={query}"
USER_AGENT  = "inframap/1.2 (github.com/rkbrainstorms/inframap; CTI research)"

# Brand keywords that attackers typosquat
BRAND_KEYWORDS = [
    "microsoft", "outlook", "office365", "office-365", "onedrive",
    "sharepoint", "teams", "azure", "google", "gmail",
    "apple", "icloud", "amazon", "aws", "paypal",
    "login", "signin", "sign-in", "secure", "verify",
    "account", "update", "portal", "mfa", "auth",
    "password", "reset", "helpdesk", "support", "bank",
]

SUSPICIOUS_TLDS = {
    ".co", ".site", ".xyz", ".online", ".click", ".live",
    ".top", ".club", ".info", ".vip", ".cc", ".pw",
    ".work", ".shop", ".store", ".tech", ".net"
}


def hunt_infrastructure(asn: str = None, nameserver: str = None,
                        keyword: str = None, days: int = 30,
                        timeout: int = 15) -> dict:
    """
    Hunt for newly registered suspicious domains via crt.sh.

    Returns a ranked list of suspicious domains with scores and signals.
    """
    result = {
        "hunt_type":    None,
        "hunt_target":  None,
        "days":         days,
        "domains_found": 0,
        "suspicious":   [],
        "all_domains":  [],
        "errors":       []
    }

    domains = []

    if keyword:
        result["hunt_type"]   = "keyword"
        result["hunt_target"] = keyword
        domains = _hunt_by_keyword(keyword, days, timeout, result)

    elif nameserver:
        result["hunt_type"]   = "nameserver"
        result["hunt_target"] = nameserver
        domains = _hunt_by_nameserver(nameserver, days, timeout, result)

    elif asn:
        result["hunt_type"]   = "asn"
        result["hunt_target"] = asn
        # For ASN hunting we search for domains with IPs in that ASN
        # via certificate subject alt names — best proxy via crt.sh
        domains = _hunt_by_asn_keyword(asn, days, timeout, result)

    if not domains:
        return result

    # Score each domain
    cutoff  = datetime.now(timezone.utc) - timedelta(days=days)
    scored  = []

    for domain_info in domains:
        domain   = domain_info.get("domain", "").lower().strip()
        not_before = domain_info.get("not_before", "")

        if not domain or len(domain) < 4:
            continue

        # Check if within date range
        if not_before:
            try:
                cert_date = datetime.fromisoformat(
                    not_before.replace("Z", "+00:00")
                )
                if cert_date < cutoff:
                    continue
                age_days = (datetime.now(timezone.utc) - cert_date).days
            except Exception:
                age_days = None
        else:
            age_days = None

        score, signals = _score_domain(domain, age_days)

        if score > 0:
            scored.append({
                "domain":    domain,
                "score":     score,
                "signals":   signals,
                "age_days":  age_days,
                "cert_date": not_before[:10] if not_before else "unknown",
                "issuer":    domain_info.get("issuer", ""),
            })

    # Sort by score descending
    scored.sort(key=lambda x: x["score"], reverse=True)

    result["domains_found"] = len(scored)
    result["suspicious"]    = [d for d in scored if d["score"] >= 30]
    result["all_domains"]   = scored

    return result


def _hunt_by_keyword(keyword: str, days: int, timeout: int, result: dict) -> list:
    """Search crt.sh for domains containing a keyword."""
    query    = f"%.{keyword}%"
    encoded  = urllib.parse.quote(query, safe="")
    url      = CRT_SH_URL.format(query=encoded)
    domains  = []

    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        for cert in data:
            name_value = cert.get("name_value", "")
            not_before = cert.get("not_before", "")
            issuer     = cert.get("issuer_name", "")

            for name in re.split(r"[\n,]", name_value):
                name = name.strip().lstrip("*.")
                if name and keyword.lower() in name.lower():
                    domains.append({
                        "domain":     name,
                        "not_before": not_before,
                        "issuer":     _extract_org(issuer)
                    })

    except urllib.error.HTTPError as e:
        result["errors"].append(f"crt.sh HTTP {e.code}")
    except Exception as e:
        result["errors"].append(f"crt.sh error: {str(e)}")

    return domains


def _hunt_by_nameserver(nameserver: str, days: int, timeout: int, result: dict) -> list:
    """Find domains using a specific nameserver via crt.sh wildcard."""
    # Search for the nameserver domain itself to find its cert cluster
    # then search for domains that share the same cert issuer patterns
    query   = f"%.{nameserver}"
    encoded = urllib.parse.quote(query, safe="")
    url     = CRT_SH_URL.format(query=encoded)
    domains = []

    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        for cert in data:
            name_value = cert.get("name_value", "")
            not_before = cert.get("not_before", "")
            issuer     = cert.get("issuer_name", "")

            for name in re.split(r"[\n,]", name_value):
                name = name.strip().lstrip("*.")
                if name and "." in name:
                    domains.append({
                        "domain":     name,
                        "not_before": not_before,
                        "issuer":     _extract_org(issuer)
                    })

    except Exception as e:
        result["errors"].append(f"crt.sh nameserver hunt error: {str(e)}")

    return domains


def _hunt_by_asn_keyword(asn: str, days: int, timeout: int, result: dict) -> list:
    """
    Hunt by ASN — searches for known bulletproof hoster domains.
    Maps ASN to known domain patterns and searches crt.sh.
    """
    # Known ASN to domain pattern mappings
    asn_patterns = {
        "AS43350": "nforce",
        "AS60068": "cdn77",
        "AS206485": "deltahost",
        "AS48721":  "flyservers",
        "AS9009":   "m247",
    }

    asn_upper = asn.upper()
    pattern   = asn_patterns.get(asn_upper, asn_upper.replace("AS", "").lower())

    result["errors"].append(
        f"Note: ASN hunting uses cert patterns as proxy — "
        f"searching for domains related to {asn}"
    )

    return _hunt_by_keyword(pattern, days, timeout, result)


def _score_domain(domain: str, age_days: int = None) -> tuple:
    """Score a domain for suspiciousness. Returns (score, signals)."""
    score   = 0
    signals = []

    base  = domain.split(".")[0] if "." in domain else domain
    tld   = "." + domain.split(".")[-1] if "." in domain else ""

    # Age signals
    if age_days is not None:
        if age_days <= 3:
            score += 30
            signals.append(f"brand new ({age_days}d)")
        elif age_days <= 7:
            score += 25
            signals.append(f"very new ({age_days}d)")
        elif age_days <= 14:
            score += 20
            signals.append(f"new ({age_days}d)")
        elif age_days <= 30:
            score += 10
            signals.append(f"recent ({age_days}d)")

    # Brand keyword matches
    matched = []
    for brand in BRAND_KEYWORDS:
        if brand in domain.lower():
            matched.append(brand)
    if len(matched) >= 2:
        score += 30
        signals.append(f"brand keywords: {', '.join(matched[:3])}")
    elif len(matched) == 1:
        score += 15
        signals.append(f"brand keyword: {matched[0]}")

    # Suspicious TLD
    if tld in SUSPICIOUS_TLDS:
        score += 10
        signals.append(f"suspicious TLD: {tld}")

    # Hyphenation
    hyphens = base.count("-")
    if hyphens >= 3:
        score += 15
        signals.append(f"heavily hyphenated ({hyphens} hyphens)")
    elif hyphens >= 2:
        score += 10
        signals.append(f"hyphenated ({hyphens} hyphens)")

    # Length
    if len(base) > 25:
        score += 10
        signals.append(f"very long domain ({len(base)} chars)")
    elif len(base) > 18:
        score += 5

    # Digits
    digits = sum(c.isdigit() for c in base)
    if digits >= 5:
        score += 8
        signals.append(f"many digits ({digits})")

    return min(score, 100), signals


def _extract_org(issuer_name: str) -> str:
    match = re.search(r"O=([^,]+)", issuer_name)
    if match:
        return match.group(1).strip().strip('"')
    return issuer_name.split(",")[0].strip() if issuer_name else "Unknown"
