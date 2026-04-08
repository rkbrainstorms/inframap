"""
Favicon hash hunting — find phishing kit reuse across domains.

Technique: Every phishing kit has a favicon. Hash it with MurmurHash3
and search urlscan.io for other pages using the same favicon.
This surfaces entire campaigns from a single IOC.

Tier 0: urlscan.io public search (no key, limited results)
Tier 1: urlscan.io API key (1000/day, full results)

Why this matters:
  Attackers reuse phishing kits across dozens of domains.
  Different domain names, different IPs, different registrars —
  but the same favicon hash betrays them all.
  This is how analysts find entire AiTM campaigns from one seed.
"""

import urllib.request
import urllib.parse
import urllib.error
import json
import hashlib
import struct
import time


URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/?q={query}&size=100"
URLSCAN_RESULT = "https://urlscan.io/api/v1/result/{uuid}/"
USER_AGENT     = "inframap/1.4 (github.com/rkbrainstorms/inframap; CTI research)"


def _murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 32-bit — same algorithm Shodan/urlscan use for favicon hashing."""
    length = len(data)
    c1, c2  = 0xcc9e2d51, 0x1b873593
    h1      = seed
    blocks  = length // 4

    for i in range(blocks):
        k1 = struct.unpack_from("<I", data, i * 4)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF

    tail  = data[blocks * 4:]
    k1    = 0
    tlen  = length & 3
    if tlen >= 3: k1 ^= tail[2] << 16
    if tlen >= 2: k1 ^= tail[1] << 8
    if tlen >= 1:
        k1 ^= tail[0]
        k1  = (k1 * c1) & 0xFFFFFFFF
        k1  = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1  = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1  = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1  = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    # Return signed int (matches Shodan convention)
    return struct.unpack("i", struct.pack("I", h1))[0]


def fetch_favicon(domain: str, timeout: int = 10) -> dict:
    """Fetch favicon from a domain and compute its hash."""
    result = {
        "domain":    domain,
        "favicon_url": None,
        "hash":      None,
        "hash_hex":  None,
        "size":      None,
        "errors":    []
    }

    favicon_paths = [
        f"https://{domain}/favicon.ico",
        f"https://{domain}/favicon.png",
        f"https://www.{domain}/favicon.ico",
    ]

    for url in favicon_paths:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if resp.status == 200:
                    data = resp.read()
                    if len(data) > 0:
                        import base64
                        b64     = base64.b64encode(data).decode("ascii")
                        favicon_hash = _murmur3_32(base64.b64decode(b64))
                        result["favicon_url"] = url
                        result["hash"]        = favicon_hash
                        result["hash_hex"]    = hex(favicon_hash & 0xFFFFFFFF)
                        result["size"]        = len(data)
                        return result
        except Exception:
            continue

    result["errors"].append(f"No favicon found at {domain}")
    return result


def hunt_by_favicon_hash(favicon_hash: int, api_key: str = None,
                          timeout: int = 15) -> dict:
    """
    Search urlscan.io for domains sharing the same favicon hash.
    Tier 0: public search (limited)
    Tier 1: API key for full results
    """
    result = {
        "hash":         favicon_hash,
        "matches":      [],
        "unique_domains": set(),
        "unique_ips":   set(),
        "errors":       []
    }

    query   = f"page.favicon:{favicon_hash}"
    encoded = urllib.parse.quote(query, safe="")
    url     = URLSCAN_SEARCH.format(query=encoded)

    headers = {"User-Agent": USER_AGENT}
    if api_key:
        headers["API-Key"] = api_key

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        for hit in data.get("results", []):
            page   = hit.get("page", {})
            domain = page.get("domain", "")
            ip     = page.get("ip", "")
            url_   = page.get("url", "")
            date   = hit.get("task", {}).get("time", "")[:10]

            if domain:
                result["matches"].append({
                    "domain": domain,
                    "ip":     ip,
                    "url":    url_,
                    "date":   date,
                    "uuid":   hit.get("task", {}).get("uuid", "")
                })
                result["unique_domains"].add(domain)
                if ip:
                    result["unique_ips"].add(ip)

    except urllib.error.HTTPError as e:
        if e.code == 429:
            result["errors"].append("urlscan.io: rate limited — try again later")
        else:
            result["errors"].append(f"urlscan.io HTTP {e.code}")
    except Exception as e:
        result["errors"].append(f"Favicon hunt error: {str(e)}")

    result["unique_domains"] = sorted(result["unique_domains"])
    result["unique_ips"]     = sorted(result["unique_ips"])
    result["match_count"]    = len(result["matches"])
    return result


def get_screenshot_url(uuid: str) -> str:
    """Get urlscan.io screenshot URL for a scan UUID."""
    return f"https://urlscan.io/screenshots/{uuid}.png"


def pivot_favicon(domain: str, api_key: str = None, timeout: int = 15) -> dict:
    """
    Full favicon pivot: fetch favicon, hash it, hunt for matches.
    Returns domains sharing the same phishing kit favicon.
    """
    result = {
        "domain":         domain,
        "favicon":        None,
        "related_domains": [],
        "related_ips":    [],
        "match_count":    0,
        "screenshot_url": None,
        "errors":         []
    }

    # Step 1: fetch and hash favicon
    favicon = fetch_favicon(domain, timeout=timeout)
    result["favicon"] = favicon

    if favicon.get("errors") or not favicon.get("hash"):
        result["errors"].extend(favicon.get("errors", []))
        return result

    # Step 2: hunt urlscan for matching favicon hash
    time.sleep(0.5)
    hunt = hunt_by_favicon_hash(favicon["hash"], api_key=api_key, timeout=timeout)
    result["errors"].extend(hunt.get("errors", []))

    # Filter out the seed domain itself
    related = [m for m in hunt.get("matches", [])
               if m.get("domain", "").rstrip(".") != domain.rstrip(".")]

    result["related_domains"] = list(set(m["domain"] for m in related))
    result["related_ips"]     = list(set(m["ip"] for m in related if m.get("ip")))
    result["match_count"]     = len(related)

    # Get screenshot URL from most recent scan
    if hunt.get("matches"):
        uuid = hunt["matches"][0].get("uuid", "")
        if uuid:
            result["screenshot_url"] = get_screenshot_url(uuid)

    return result
