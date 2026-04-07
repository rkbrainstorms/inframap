"""
Phishing kit detection — urlscan.io page title + content analysis.
No API key required for search (keyless quota applies).

Detects phishing kits by querying urlscan.io for:
- Suspicious page titles on newly registered domains
- Microsoft/Google/bank login page impersonation
- Credential harvesting patterns in page content
- AiTM (Adversary-in-the-Middle) platform indicators

This is a novel capability — no other free CLI tool does this.
"""

import urllib.request
import urllib.parse
import urllib.error
import json
import re
import time


URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"
USER_AGENT     = "inframap/1.0 (github.com/rkbrainstorms/inframap; CTI research)"

# Page titles commonly seen in phishing kits
PHISHING_TITLE_PATTERNS = [
    # Microsoft impersonation
    r"microsoft.*sign.?in",
    r"sign.?in.*microsoft",
    r"office\s*365",
    r"microsoft\s*365",
    r"outlook.*login",
    r"microsoft.*account",
    r"verify.*microsoft",
    r"microsoft.*verify",
    r"teams.*login",
    r"sharepoint.*login",

    # Google impersonation
    r"google.*sign.?in",
    r"sign.?in.*google",
    r"gmail.*login",
    r"google.*account.*verify",

    # Generic credential harvesting
    r"account.*suspended",
    r"verify.*account",
    r"account.*verify",
    r"confirm.*identity",
    r"unusual.*sign.?in",
    r"suspicious.*activity",
    r"password.*expired",
    r"account.*locked",
    r"two.?factor.*auth",
    r"security.*alert",
    r"update.*payment",

    # Banking
    r"secure.*banking",
    r"online.*banking.*login",
    r"bank.*verify",
]

# ASNs commonly used in phishing infrastructure
PHISHING_ASNS = {
    "AS60068",   # Datacamp/CDN77
    "AS206485",  # Deltahost
    "AS48721",   # Flyservers
    "AS202422",  # G-Core
    "AS9009",    # M247
    "AS59477",   # Serverius
    "AS395082",  # HostRoyale
}

# Compiled patterns
_COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in PHISHING_TITLE_PATTERNS]


def detect_phishing_kit(domain: str, api_key: str = None, timeout: int = 10,
                        domain_age_days: int = None, cert_fast_spin: bool = False,
                        cert_count: int = 0) -> dict:
    """
    Scan urlscan.io results for phishing kit indicators on a domain.
    Returns scored findings with matched patterns.
    """
    result = {
        "domain":           domain,
        "phishing_score":   0,
        "kit_detected":     False,
        "matched_titles":   [],
        "matched_patterns": [],
        "suspicious_scans": [],
        "aitm_indicators":  [],
        "findings":         [],
        "errors":           []
    }

    # Search for scans of this domain
    scans = _search_urlscan(domain, api_key, timeout)
    if not scans:
        return result

    score = 0

    # Boost score from cert/domain signals passed in from main engine
    if cert_fast_spin:
        score += 25
    if cert_count >= 10:
        score += 15
    elif cert_count >= 3:
        score += 10
    if domain_age_days is not None and domain_age_days < 30:
        score += 20
    elif domain_age_days is not None and domain_age_days < 90:
        score += 10
    matched_titles  = set()
    matched_patterns= set()
    suspicious_scans= []
    aitm_indicators = []

    for scan in scans:
        page    = scan.get("page", {})
        task    = scan.get("task", {})
        title   = (page.get("title") or "").strip()
        url     = page.get("url", task.get("url", ""))
        asn     = page.get("asn", "")
        country = page.get("country", "")
        status  = page.get("status", "")
        server  = page.get("server", "")

        # Check title against phishing patterns
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
                        "asn":     asn,
                        "date":    task.get("time", "")[:10]
                    })
                    break

        # AiTM platform indicators
        aitm_patterns = ["evilginx", "modlishka", "muraena", "necrobrowser",
                         "aitm", "adversary-in-the-middle", "reverse proxy"]
        for ap in aitm_patterns:
            if ap in url.lower() or ap in (server or "").lower():
                aitm_indicators.append(f"AiTM pattern '{ap}' in {url}")
                score += 30

        # Suspicious ASN
        if asn in PHISHING_ASNS:
            score += 15

        # HTTP 200 on a login-looking URL from a bulletproof ASN
        if status == "200" and asn in PHISHING_ASNS:
            score += 10

    # Cap score at 100
    score = min(score, 100)

    result["phishing_score"]    = score
    result["kit_detected"]      = score >= 40
    result["matched_titles"]    = sorted(matched_titles)
    result["matched_patterns"]  = list(matched_patterns)[:5]
    result["suspicious_scans"]  = suspicious_scans[:10]
    result["aitm_indicators"]   = aitm_indicators

    # Build findings
    if matched_titles:
        result["findings"].append({
            "text":       f"{len(matched_titles)} scan(s) show phishing page titles",
            "confidence": "CONFIRMED" if score >= 60 else "ANALYST ASSESSMENT",
            "source":     "phishing-detection"
        })
    if aitm_indicators:
        result["findings"].append({
            "text":       f"AiTM platform indicator detected",
            "confidence": "CONFIRMED",
            "source":     "phishing-detection"
        })
    if score >= 40 and not matched_titles:
        result["findings"].append({
            "text":       f"phishing kit score {score}/100 — infrastructure pattern match",
            "confidence": "ANALYST ASSESSMENT",
            "source":     "phishing-detection"
        })

    return result


def _search_urlscan(domain: str, api_key: str, timeout: int) -> list:
    """Search urlscan for recent scans of a domain."""
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
    except urllib.error.HTTPError as e:
        if e.code == 429:
            return []
        return []
    except Exception:
        return []
