"""
urlscan.io pivot — search existing scans by domain/IP.
Free account: 1000 searches/day, 5000 public scans.
Keyless: minor quota (still usable for small hunts).

We search existing scans — not submit new ones — to avoid
inadvertently tipping off threat actors.
"""

import urllib.request
import urllib.parse
import urllib.error
import json
import time


URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"
USER_AGENT     = "inframap/1.0 (github.com/rhishav/inframap; CTI research)"


def pivot_urlscan(domain: str = None, ip: str = None,
                  api_key: str = None, timeout: int = 10) -> dict:
    """
    Search urlscan.io for existing scans matching a domain or IP.
    Extracts: IPs seen, page titles, ASNs, countries, submission timeline.
    """
    result = {
        "queries":   [],
        "results":   [],
        "ips_seen":  set(),
        "asns_seen": set(),
        "asn_names": {},
        "countries": set(),
        "page_titles": [],
        "submission_timeline": [],
        "errors":    [],
        "keyless":   api_key is None
    }

    queries = []
    if domain:
        queries.append(("domain", domain, f'domain:"{domain}"'))
        # Also search for page.domain to catch redirects
        queries.append(("page_domain", domain, f'page.domain:"{domain}"'))
    if ip:
        queries.append(("ip", ip, f'page.ip:"{ip}"'))

    seen_scan_ids = set()

    for (qtype, qval, qstr) in queries:
        params  = urllib.parse.urlencode({"q": qstr, "size": 100})
        url     = f"{URLSCAN_SEARCH}?{params}"
        headers = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
        if api_key:
            headers["API-Key"] = api_key

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data  = json.loads(resp.read().decode("utf-8"))
                scans = data.get("results", [])
                result["queries"].append({"type": qtype, "value": qval, "hits": len(scans)})

                for scan in scans:
                    sid = scan.get("_id") or scan.get("id")
                    if sid in seen_scan_ids:
                        continue
                    seen_scan_ids.add(sid)
                    parsed = _parse_scan(scan)
                    result["results"].append(parsed)

                    if parsed.get("ip"):
                        result["ips_seen"].add(parsed["ip"])
                    if parsed.get("asn"):
                        asn = parsed["asn"]
                        asn_name = parsed.get("asn_name", "")
                        result["asns_seen"].add(asn)
                        # Store ASN names for display
                        if asn and asn_name:
                            result["asn_names"][asn] = asn_name
                    if parsed.get("country"):
                        result["countries"].add(parsed["country"])
                    if parsed.get("title"):
                        result["page_titles"].append(parsed["title"])

        except urllib.error.HTTPError as e:
            if e.code == 429:
                result["errors"].append("urlscan.io rate limit hit — add API key for higher quota")
            elif e.code == 401:
                result["errors"].append("urlscan.io: invalid API key")
            else:
                result["errors"].append(f"urlscan.io HTTP {e.code} for query '{qstr}'")
        except Exception as e:
            result["errors"].append(f"urlscan.io error: {str(e)}")

        time.sleep(0.5)

    # Build submission timeline (sorted by date)
    timeline = []
    for scan in result["results"]:
        if scan.get("date"):
            timeline.append({"date": scan["date"][:10], "domain": scan.get("domain"), "ip": scan.get("ip")})
    result["submission_timeline"] = sorted(timeline, key=lambda x: x["date"])

    # Deduplicate sets → lists for JSON serialisation
    result["ips_seen"]  = sorted(result["ips_seen"])
    result["asns_seen"] = sorted(result["asns_seen"])
    result["countries"] = sorted(result["countries"])
    result["scan_count"] = len(result["results"])

    return result


def _parse_scan(scan: dict) -> dict:
    """Flatten a urlscan result entry into key fields."""
    page = scan.get("page", {})
    task = scan.get("task", {})

    return {
        "id":      scan.get("_id") or scan.get("id"),
        "url":     page.get("url", task.get("url", "")),
        "domain":  page.get("domain", ""),
        "ip":      page.get("ip", ""),
        "asn":     page.get("asn", ""),
        "asn_name":page.get("asnname", ""),
        "country": page.get("country", ""),
        "server":  page.get("server", ""),
        "title":   page.get("title", ""),
        "status":  page.get("status", ""),
        "date":    task.get("time", ""),
        "submitter": task.get("source", ""),
        "screenshot": f"https://urlscan.io/screenshots/{scan.get('_id', '')}.png"
    }
