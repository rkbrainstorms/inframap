"""
BGP.he.net pivot — ASN, routing, and hosting provider analysis.
No API key required. Parses Hurricane Electric's BGP toolkit HTML.

Used to score how "bulletproof" a hosting provider is based on:
- ASN age and size
- Peer count (high peer count = major legit provider)
- Country of registration
- Whether the ASN appears in known bulletproof hosting lists
"""

import urllib.request
import urllib.error
import re
import socket


HE_BGP_IP_URL  = "https://bgp.he.net/ip/{ip}"
HE_BGP_ASN_URL = "https://bgp.he.net/AS{asn}"
USER_AGENT     = "inframap/1.0 (github.com/rhishav/inframap; CTI research)"

# Known bulletproof/abuse-friendly ASNs (community-maintained list, non-exhaustive)
KNOWN_BULLETPROOF_ASNS = {
    "AS9009",    # M247
    "AS60068",   # Datacamp / CDN77
    "AS206485",  # Deltahost (UA bulletproof)
    "AS202422",  # G-Core (used by threat actors)
    "AS48721",   # Flyservers
    "AS395954",  # Leaseweb USA (abused)
    "AS59477",   # Serverius (NL)
}


def pivot_bgphe(ip: str, timeout: int = 10) -> dict:
    """
    Look up ASN info for an IP via BGP.he.net.
    Returns ASN number, name, country, peer count, and bulletproof score.
    """
    result = {
        "ip":             ip,
        "asn":            None,
        "asn_name":       None,
        "country":        None,
        "prefix":         None,
        "peer_count":     None,
        "is_known_bp":    False,
        "bp_score":       0,      # 0-100, higher = more suspicious
        "bp_indicators":  [],
        "errors":         []
    }

    # First resolve hostname
    try:
        result["hostname"] = socket.getfqdn(ip)
    except Exception:
        result["hostname"] = None

    url = HE_BGP_IP_URL.format(ip=ip)
    html = _fetch(url, timeout, result)
    if not html:
        return result

    _parse_ip_page(html, result)

    # If we got an ASN, fetch its page for peer data
    if result["asn"]:
        asn_num = result["asn"].replace("AS", "")
        asn_url = HE_BGP_ASN_URL.format(asn=asn_num)
        asn_html = _fetch(asn_url, timeout, result)
        if asn_html:
            _parse_asn_page(asn_html, result)

    _score_bulletproof(result)

    return result


def _fetch(url: str, timeout: int, result: dict) -> str | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        result["errors"].append(f"BGP.he.net HTTP {e.code}: {url}")
    except Exception as e:
        result["errors"].append(f"BGP.he.net error: {str(e)}")
    return None


def _parse_ip_page(html: str, result: dict):
    """Extract ASN, prefix, and country from the IP detail page."""
    # ASN
    asn_match = re.search(r'href="/AS(\d+)"[^>]*>\s*AS\d+', html)
    if asn_match:
        result["asn"] = f"AS{asn_match.group(1)}"

    # ASN name (usually next to the ASN link)
    name_match = re.search(r'AS\d+\s*</a>\s*([^\n<]{3,60})', html)
    if name_match:
        result["asn_name"] = name_match.group(1).strip()

    # Prefix (CIDR)
    prefix_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', html)
    if prefix_match:
        result["prefix"] = prefix_match.group(1)

    # Country (2-letter ISO code near flag img)
    country_match = re.search(r'flag_(\w{2})\.png', html)
    if country_match:
        result["country"] = country_match.group(1).upper()


def _parse_asn_page(html: str, result: dict):
    """Extract peer count and additional name data from ASN page."""
    # Peer count (number of BGP peers)
    peer_match = re.search(r'(\d+)\s+peers?', html, re.IGNORECASE)
    if peer_match:
        result["peer_count"] = int(peer_match.group(1))

    # More precise ASN name from title
    title_match = re.search(r'<title>([^<]+)</title>', html)
    if title_match and not result["asn_name"]:
        title = title_match.group(1).strip()
        # Format: "AS12345 SOMENAME - BGP.he.net"
        name_part = re.sub(r'^AS\d+\s*', '', title).split(' - ')[0].strip()
        if name_part:
            result["asn_name"] = name_part


def _score_bulletproof(result: dict):
    """
    Score how suspicious the hosting provider is.
    Based on: known BP list, peer count, country, ASN name keywords.
    """
    score       = 0
    indicators  = []

    # Known bulletproof ASN
    if result["asn"] in KNOWN_BULLETPROOF_ASNS:
        score += 40
        indicators.append(f"{result['asn']} is in known bulletproof ASN list")
        result["is_known_bp"] = True

    # Very few peers = small/shady hosting provider
    peers = result.get("peer_count")
    if peers is not None:
        if peers < 5:
            score += 20
            indicators.append(f"very low peer count ({peers}) — micro/shady hoster")
        elif peers < 15:
            score += 10
            indicators.append(f"low peer count ({peers}) — small hosting provider")

    # Country risk heuristic (based on CTI community consensus, not political)
    high_risk_countries = {"RU", "CN", "KP", "IR", "BY"}
    medium_risk_countries = {"UA", "MD", "BG", "RO", "NL", "BZ", "PA"}
    country = result.get("country", "")
    if country in high_risk_countries:
        score += 20
        indicators.append(f"hosted in {country} (high-risk jurisdiction for cybercrime hosting)")
    elif country in medium_risk_countries:
        score += 10
        indicators.append(f"hosted in {country} (commonly used for bulletproof hosting)")

    # ASN name keywords
    asn_name = (result.get("asn_name") or "").lower()
    bp_keywords = ["bulletproof", "offshore", "anonymous", "privacy", "no-log"]
    for kw in bp_keywords:
        if kw in asn_name:
            score += 15
            indicators.append(f"ASN name contains '{kw}'")

    result["bp_score"]      = min(score, 100)
    result["bp_indicators"] = indicators

    # Human-readable label
    if score >= 60:
        result["bp_label"] = "HIGH-RISK HOSTING"
    elif score >= 30:
        result["bp_label"] = "SUSPICIOUS HOSTING"
    elif score > 0:
        result["bp_label"] = "MODERATE RISK"
    else:
        result["bp_label"] = "MAINSTREAM HOSTING"
