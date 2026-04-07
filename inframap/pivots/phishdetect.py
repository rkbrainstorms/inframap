"""
Phishing kit detection — multi-signal scoring engine.
No API key required for search (keyless quota applies).

Scores based on BOTH infrastructure signals AND urlscan page title analysis:
- Domain age + cert fast-spin (infrastructure-level detection)
- Brand keyword typosquatting in domain name
- Bulletproof ASN hosting
- Suspicious TLD
- urlscan page title patterns (when available)
- AiTM platform indicators

This hybrid approach catches phishing infrastructure even when
urlscan hasn't scanned the page yet.
"""

import urllib.request
import urllib.parse
import urllib.error
import json
import re
import time


URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"
USER_AGENT     = "inframap/1.2 (github.com/rkbrainstorms/inframap; CTI research)"

# Page titles commonly seen in phishing kits
PHISHING_TITLE_PATTERNS = [
    r"microsoft.*sign.?in", r"sign.?in.*microsoft",
    r"office\s*365", r"microsoft\s*365",
    r"outlook.*login", r"microsoft.*account",
    r"verify.*microsoft", r"microsoft.*verify",
    r"teams.*login", r"sharepoint.*login",
    r"google.*sign.?in", r"sign.?in.*google",
    r"gmail.*login", r"google.*account.*verify",
    r"account.*suspended", r"verify.*account",
    r"account.*verify", r"confirm.*identity",
    r"unusual.*sign.?in", r"suspicious.*activity",
    r"password.*expired", r"account.*locked",
    r"two.?factor.*auth", r"security.*alert",
    r"update.*payment", r"secure.*banking",
    r"online.*banking.*login", r"bank.*verify",
]

# Brand keywords that attackers typosquat
BRAND_KEYWORDS = [
    "microsoft", "outlook", "office365", "office-365",
    "onedrive", "sharepoint", "teams", "azure",
    "google", "gmail", "workspace",
    "apple", "icloud",
    "login", "signin", "sign-in", "secure", "verify",
    "account", "update", "portal", "mfa", "auth",
    "password", "reset", "helpdesk", "support",
]

# Suspicious TLDs frequently used in phishing
SUSPICIOUS_TLDS = {
    ".co", ".site", ".xyz", ".online", ".click",
    ".live", ".top", ".club", ".info", ".vip",
    ".cc", ".pw", ".tk", ".ml", ".ga", ".cf",
    ".work", ".shop", ".store", ".tech"
}

# Bulletproof ASNs
PHISHING_ASNS = {
    "AS60068", "AS206485", "AS48721", "AS202422",
    "AS9009", "AS59477", "AS395082", "AS40034",
    "AS43350",  # NForce — used by topdns.com
}

_COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in PHISHING_TITLE_PATTERNS]


def detect_phishing_kit(domain: str, api_key: str = None, timeout: int = 10,
                        domain_age_days: int = None, cert_fast_spin: bool = False,
                        cert_count: int = 0, asn: str = None,
                        has_wildcard_san: bool = False) -> dict:
    """
    Multi-signal phishing kit detection.
    Scores based on infrastructure signals + urlscan page analysis.
    """
    result = {
        "domain":           domain,
        "phishing_score":   0,
        "kit_detected":     False,
        "matched_titles":   [],
        "matched_patterns": [],
        "suspicious_scans": [],
        "aitm_indicators":  [],
        "infra_signals":    [],
        "findings":         [],
        "errors":           []
    }

    score = 0
    infra_signals = []

    # ── 1. Infrastructure signals (no urlscan needed) ──────────────

    # Domain age
    if domain_age_days is not None:
        if domain_age_days < 7:
            score += 30
            infra_signals.append(f"very new domain ({domain_age_days}d old)")
        elif domain_age_days < 30:
            score += 20
            infra_signals.append(f"newly registered ({domain_age_days}d old)")
        elif domain_age_days < 90:
            score += 10
            infra_signals.append(f"recently registered ({domain_age_days}d old)")

    # Cert fast-spin
    if cert_fast_spin:
        score += 25
        infra_signals.append("cert fast-spin detected (≥5 certs in one month)")

    # High cert volume
    if cert_count >= 20:
        score += 20
        infra_signals.append(f"very high cert volume ({cert_count} certs)")
    elif cert_count >= 10:
        score += 15
        infra_signals.append(f"high cert volume ({cert_count} certs)")
    elif cert_count >= 3:
        score += 8
        infra_signals.append(f"elevated cert volume ({cert_count} certs)")

    # Wildcard SAN
    if has_wildcard_san:
        score += 15
        infra_signals.append("wildcard SAN certificate")

    # Bulletproof ASN
    if asn and asn in PHISHING_ASNS:
        score += 20
        infra_signals.append(f"hosted on known phishing ASN: {asn}")

    # ── 2. Domain name analysis ────────────────────────────────────

    domain_lower = domain.lower()
    base_domain  = domain_lower.split(".")[0]

    # Brand keyword in domain
    matched_brands = []
    for brand in BRAND_KEYWORDS:
        if brand in domain_lower and brand not in ["co", "info"]:
            matched_brands.append(brand)

    if len(matched_brands) >= 2:
        score += 25
        infra_signals.append(f"multiple brand keywords in domain: {', '.join(matched_brands[:3])}")
    elif len(matched_brands) == 1:
        score += 15
        infra_signals.append(f"brand keyword in domain: {matched_brands[0]}")

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain_lower.endswith(tld):
            score += 10
            infra_signals.append(f"suspicious TLD: {tld}")
            break

    # Hyphenated domain (common in phishing)
    if base_domain.count("-") >= 2:
        score += 10
        infra_signals.append(f"heavily hyphenated domain ({base_domain.count('-')} hyphens)")
    elif base_domain.count("-") == 1:
        score += 5

    # Long domain (phishing domains tend to be descriptive)
    if len(base_domain) > 20:
        score += 8
        infra_signals.append(f"long domain name ({len(base_domain)} chars)")

    # Numbers in domain (random-looking)
    digit_count = sum(c.isdigit() for c in base_domain)
    if digit_count >= 4:
        score += 8
        infra_signals.append(f"many digits in domain ({digit_count})")

    result["infra_signals"] = infra_signals

    # ── 3. urlscan page title analysis ────────────────────────────

    scans = _search_urlscan(domain, api_key, timeout)
    matched_titles  = set()
    matched_patterns= set()
    suspicious_scans= []
    aitm_indicators = []

    for scan in scans:
        page   = scan.get("page", {})
        task   = scan.get("task", {})
        title  = (page.get("title") or "").strip()
        url    = page.get("url", task.get("url", ""))
        asn_s  = page.get("asn", "")
        country= page.get("country", "")

        if title:
            for i, pattern in enumerate(_COMPILED_PATTERNS):
                if pattern.search(title):
                    matched_titles.add(title)
                    matched_patterns.add(PHISHING_TITLE_PATTERNS[i])
                    score += 20
                    suspicious_scans.append({
                        "url":     url,
                        "title":   title,
                        "country": country,
                        "asn":     asn_s,
                        "date":    task.get("time", "")[:10]
                    })
                    break

        # AiTM indicators
        aitm_patterns = ["evilginx", "modlishka", "muraena",
                         "necrobrowser", "aitm", "reverse proxy"]
        for ap in aitm_patterns:
            if ap in url.lower():
                aitm_indicators.append(f"AiTM pattern '{ap}' in URL")
                score += 30

        if asn_s in PHISHING_ASNS:
            score += 10

    score = min(score, 100)

    result["phishing_score"]    = score
    result["kit_detected"]      = score >= 40
    result["matched_titles"]    = sorted(matched_titles)
    result["matched_patterns"]  = list(matched_patterns)[:5]
    result["suspicious_scans"]  = suspicious_scans[:10]
    result["aitm_indicators"]   = aitm_indicators

    # Build findings
    if infra_signals:
        conf = "CONFIRMED" if score >= 60 else "ANALYST ASSESSMENT" if score >= 40 else "CIRCUMSTANTIAL"
        result["findings"].append({
            "text":       f"phishing infrastructure score {score}/100 — {len(infra_signals)} signal(s)",
            "confidence": conf,
            "source":     "phishing-detection"
        })
    if matched_titles:
        result["findings"].append({
            "text":       f"{len(matched_titles)} phishing page title(s) detected on urlscan",
            "confidence": "CONFIRMED",
            "source":     "phishing-detection"
        })
    if aitm_indicators:
        result["findings"].append({
            "text":       "AiTM platform indicator detected",
            "confidence": "CONFIRMED",
            "source":     "phishing-detection"
        })

    return result


def _search_urlscan(domain: str, api_key: str, timeout: int) -> list:
    query   = f'page.domain:"{domain}"'
    params  = urllib.parse.urlencode({"q": query, "size": 100})
    url     = f"{URLSCAN_SEARCH}?{params}"
    headers = {"User-Agent": USER_AGENT}
    if api_key:
        headers["API-Key"] = api_key
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("results", [])
    except Exception:
        return []
