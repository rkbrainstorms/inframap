"""
RDAP pivot — Structured WHOIS via IANA RDAP protocol.
No API key required. Uses iana.org bootstrap to find correct RDAP server.

RDAP (RFC 7480) replaces raw WHOIS with structured JSON.
We use it for registrant fingerprinting and WHOIS hash clustering —
the same methodology used in professional CTI attribution reports.
"""

import urllib.request
import urllib.error
import json
import hashlib
import re
import time


RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
USER_AGENT      = "inframap/1.0 (github.com/rhishav/inframap; CTI research)"

# Cache bootstrap data for the session
_bootstrap_cache = None


def pivot_rdap(domain: str, timeout: int = 10) -> dict:
    """
    Perform RDAP lookup for a domain.
    Returns structured registrant data, normalised fingerprint, and confidence indicators.
    """
    result = {
        "domain":       domain,
        "registrar":    None,
        "registrant":   {},
        "nameservers":  [],
        "dates":        {},
        "privacy":      False,
        "raw_entities": [],
        "whois_fp":     None,
        "errors":       []
    }

    rdap_url = _resolve_rdap_server(domain, timeout)
    if not rdap_url:
        result["errors"].append("could not resolve RDAP server (TLD not in bootstrap)")
        # fallback to rdap.org which handles most TLDs
        rdap_url = f"https://rdap.org/domain/{domain}"

    try:
        url = rdap_url.rstrip("/") + f"/domain/{domain}" if "rdap.org" not in rdap_url else rdap_url
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            _parse_rdap(data, result)
    except urllib.error.HTTPError as e:
        result["errors"].append(f"RDAP HTTP {e.code}: {domain}")
        # try rdap.org fallback
        if e.code in (404, 400):
            _try_rdap_fallback(domain, result, timeout)
    except Exception as e:
        result["errors"].append(f"RDAP error: {str(e)}")
        _try_rdap_fallback(domain, result, timeout)

    # Generate WHOIS fingerprint for clustering
    result["whois_fp"] = _fingerprint(result)

    # Calculate domain age
    result["domain_age_days"] = _calc_age(result.get("dates", {}))

    return result


def _calc_age(dates: dict):  # -> Optional[int]
    """Calculate domain age in days from registration date."""
    registered = dates.get("registration") or dates.get("registrationdate", "")
    if not registered:
        return None
    try:
        from datetime import datetime, timezone
        reg_date = datetime.fromisoformat(registered.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - reg_date).days
    except Exception:
        return None


def _resolve_rdap_server(domain: str, timeout: int):  # -> Optional[str]
    """Bootstrap: find the correct RDAP server for a TLD."""
    global _bootstrap_cache
    tld = domain.split(".")[-1].lower()

    if _bootstrap_cache is None:
        try:
            req = urllib.request.Request(RDAP_BOOTSTRAP, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                _bootstrap_cache = json.loads(resp.read().decode("utf-8"))
        except Exception:
            return None

    services = _bootstrap_cache.get("services", [])
    for entry in services:
        tlds, servers = entry[0], entry[1]
        if tld in [t.lower() for t in tlds] and servers:
            base = servers[0].rstrip("/")
            return f"{base}/domain/{domain}"

    return None


def _try_rdap_fallback(domain: str, result: dict, timeout: int):
    """Try rdap.org as a universal fallback."""
    try:
        url = f"https://rdap.org/domain/{domain}"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            _parse_rdap(data, result)
            result["errors"] = [e for e in result["errors"] if "RDAP" not in e]
    except Exception as e:
        result["errors"].append(f"rdap.org fallback failed: {str(e)}")


def _parse_rdap(data: dict, result: dict):
    """Extract structured fields from RDAP JSON response."""
    # Nameservers
    for ns in data.get("nameservers", []):
        name = ns.get("ldhName", "").lower()
        if name:
            result["nameservers"].append(name)

    # Dates
    for event in data.get("events", []):
        action = event.get("eventAction", "")
        date   = event.get("eventDate", "")[:10]
        if action and date:
            result["dates"][action] = date

    # Entities (registrar, registrant, tech, admin)
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        vcard = entity.get("vcardArray", [])
        parsed = _parse_vcard(vcard)
        parsed["roles"] = roles
        result["raw_entities"].append(parsed)

        if "registrar" in roles:
            result["registrar"] = parsed.get("org") or parsed.get("name")

        if "registrant" in roles:
            result["registrant"] = parsed
            # Detect privacy proxy
            name = (parsed.get("name", "") or "").lower()
            org  = (parsed.get("org",  "") or "").lower()
            privacy_keywords = ["privacy", "whoisguard", "protected", "redacted",
                                "withheld", "proxy", "domains by proxy", "perfect privacy"]
            if any(k in name or k in org for k in privacy_keywords):
                result["privacy"] = True


def _parse_vcard(vcard_array: list) -> dict:
    """Parse vCard 4.0 array from RDAP into flat dict."""
    out = {"name": None, "org": None, "email": None, "phone": None, "address": None}
    if not vcard_array or len(vcard_array) < 2:
        return out

    for field in vcard_array[1]:
        if not isinstance(field, list) or len(field) < 4:
            continue
        key   = field[0].lower() if field[0] else ""
        value = field[3] if field[3] is not None else ""

        if key == "fn":
            out["name"] = str(value).strip()
        elif key == "org":
            out["org"] = str(value).strip() if isinstance(value, str) else (value[0] if value else None)
        elif key == "email":
            out["email"] = str(value).strip()
        elif key == "tel":
            out["phone"] = str(value).strip()
        elif key == "adr":
            if isinstance(value, list):
                out["address"] = ", ".join(str(v) for v in value if v).strip(", ")
            else:
                out["address"] = str(value).strip()

    return out


def _fingerprint(result: dict) -> str:
    """
    Generate a normalised WHOIS fingerprint for cluster matching.
    Strips noise (privacy proxies, generic values) before hashing.
    Domains sharing a fingerprint likely share infrastructure/operator.
    """
    reg = result.get("registrant", {})
    ns  = "|".join(sorted(result.get("nameservers", [])))

    # Extract registrar TLD (e.g. "namecheap" from "namecheap.com")
    registrar     = (result.get("registrar") or "").lower()
    registrar_key = registrar.split(".")[0] if "." in registrar else registrar

    # Normalise registrant fields - skip if privacy proxy
    if result.get("privacy"):
        reg_key = "PRIVACY_PROTECTED"
    else:
        parts = [
            (reg.get("org") or "").lower().strip(),
            (reg.get("email") or "").lower().strip(),
            (reg.get("name") or "").lower().strip(),
        ]
        reg_key = "|".join(p for p in parts if p and len(p) > 2)

    fp_input = f"{registrar_key}||{reg_key}||{ns}"
    return hashlib.sha256(fp_input.encode()).hexdigest()[:16]
