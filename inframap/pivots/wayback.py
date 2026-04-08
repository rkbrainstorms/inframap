"""
Wayback Machine pivot — historical web content analysis.

No API key required. Uses archive.org CDX API (completely free).
https://web.archive.org/cdx/search/cdx

Why this matters for CTI:
  - Domain was clean 1 year ago but now malicious = compromised/sold
  - Domain showed Microsoft login 6 months ago = known phishing, now parked
  - Domain registered recently but has archive history = domain takeover
  - Sudden content change = infrastructure repurposing

  Knowing a domain's history catches attackers who recycle aged domains
  to bypass reputation filters.
"""

import urllib.request
import urllib.parse
import urllib.error
import json
import time


CDX_URL    = "https://web.archive.org/cdx/search/cdx"
USER_AGENT = "inframap/1.4 (github.com/rkbrainstorms/inframap; CTI research)"

# Page titles associated with phishing/credential harvesting
PHISHING_TITLES = [
    "microsoft", "office 365", "outlook", "sign in", "login",
    "verify", "account", "password", "credential", "authentication",
    "secure", "update", "suspended", "unusual activity",
    "google", "apple", "amazon", "paypal", "docusign",
    "dropbox", "onedrive", "sharepoint", "teams"
]


def pivot_wayback(domain: str, timeout: int = 15, limit: int = 50) -> dict:
    """
    Query Wayback Machine CDX API for domain history.
    Returns snapshots, content changes, and phishing indicators.
    """
    result = {
        "domain":          domain,
        "snapshots":       [],
        "first_seen":      None,
        "last_seen":       None,
        "total_snapshots": 0,
        "status_codes":    {},
        "mime_types":      {},
        "phishing_titles": [],
        "content_changes": [],
        "risk_signals":    [],
        "errors":          []
    }

    params = {
        "url":       f"*.{domain}",
        "output":    "json",
        "fl":        "timestamp,statuscode,mimetype,original,title",
        "collapse":  "digest",
        "limit":     str(limit),
        "from":      "20200101"
    }

    url = CDX_URL + "?" + urllib.parse.urlencode(params)

    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")

        if not raw.strip() or raw.strip() == "[]":
            result["errors"].append("No Wayback Machine records found")
            return result

        rows = json.loads(raw)
        if not rows or len(rows) < 2:
            return result

        # First row is headers
        headers = rows[0]
        data    = rows[1:]

        ts_idx   = headers.index("timestamp")   if "timestamp"  in headers else 0
        sc_idx   = headers.index("statuscode")  if "statuscode" in headers else 1
        mt_idx   = headers.index("mimetype")    if "mimetype"   in headers else 2
        url_idx  = headers.index("original")    if "original"   in headers else 3
        tit_idx  = headers.index("title")       if "title"      in headers else 4

        timestamps = []
        seen_titles = set()

        for row in data:
            if len(row) <= max(ts_idx, sc_idx, mt_idx):
                continue

            ts     = row[ts_idx] if ts_idx < len(row) else ""
            sc     = row[sc_idx] if sc_idx < len(row) else ""
            mt     = row[mt_idx] if mt_idx < len(row) else ""
            orig   = row[url_idx] if url_idx < len(row) else ""
            title  = row[tit_idx] if tit_idx < len(row) else ""

            # Format timestamp
            date = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts

            snapshot = {
                "date":   date,
                "status": sc,
                "type":   mt,
                "url":    orig,
                "title":  title
            }
            result["snapshots"].append(snapshot)
            timestamps.append(ts)

            # Track status codes
            result["status_codes"][sc] = result["status_codes"].get(sc, 0) + 1

            # Track mime types
            result["mime_types"][mt] = result["mime_types"].get(mt, 0) + 1

            # Check for phishing titles
            title_lower = title.lower()
            for phish in PHISHING_TITLES:
                if phish in title_lower and title not in seen_titles:
                    result["phishing_titles"].append({
                        "title": title,
                        "date":  date,
                        "url":   orig
                    })
                    seen_titles.add(title)
                    break

        result["total_snapshots"] = len(result["snapshots"])

        if timestamps:
            timestamps.sort()
            result["first_seen"] = f"{timestamps[0][:4]}-{timestamps[0][4:6]}-{timestamps[0][6:8]}"
            result["last_seen"]  = f"{timestamps[-1][:4]}-{timestamps[-1][4:6]}-{timestamps[-1][6:8]}"

        # Risk signals
        if result["phishing_titles"]:
            result["risk_signals"].append(
                f"historical phishing page titles found: "
                f"{', '.join(t['title'][:30] for t in result['phishing_titles'][:3])}"
            )

        if result["total_snapshots"] == 0:
            result["risk_signals"].append("no archive history — newly registered or never indexed")
        elif result["total_snapshots"] < 5:
            result["risk_signals"].append(
                f"very few archive records ({result['total_snapshots']}) — low-profile or new domain"
            )

        # Check for 200→parked pattern (active then dead)
        statuses = [s["status"] for s in result["snapshots"]]
        if "200" in statuses and statuses[-1] in ("301", "302", "404"):
            result["risk_signals"].append("domain was active but now redirecting/dead — possible retired infra")

    except urllib.error.HTTPError as e:
        result["errors"].append(f"Wayback Machine HTTP {e.code}")
    except Exception as e:
        result["errors"].append(f"Wayback Machine error: {str(e)}")

    return result
