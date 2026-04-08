"""
Infrastructure liveness checker.
Checks whether discovered domains/IPs are still active.

No API key required. Uses:
- DNS resolution (stdlib socket)
- HTTP HEAD request (urllib)
- ICMP ping alternative via TCP connect

This is the missing piece that no other free tool provides inline.
Analysts waste hours pivoting on dead infrastructure.
A LIVE/DEAD/UNKNOWN tag on every IOC saves that time.
"""

import urllib.request
import urllib.error
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


USER_AGENT = "inframap/1.3 (github.com/rkbrainstorms/inframap; CTI research)"


def check_liveness(iocs: list, timeout: int = 5, max_workers: int = 10) -> dict:
    """
    Check liveness of a list of IOCs in parallel.

    iocs: list of dicts with 'type' and 'value' keys
    Returns dict mapping IOC value -> liveness result
    """
    results = {}

    # Filter to checkable IOCs (domains and IPs only)
    checkable = [
        ioc for ioc in iocs
        if ioc.get("type") in ("domain", "ip")
        and ioc.get("value")
        and not ioc.get("value", "").startswith("*")
    ][:30]  # cap at 30 to avoid being too aggressive

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ioc = {
            executor.submit(_check_single, ioc["value"], ioc["type"], timeout): ioc
            for ioc in checkable
        }
        for future in as_completed(future_to_ioc):
            ioc = future_to_ioc[future]
            try:
                result = future.result()
                results[ioc["value"]] = result
            except Exception as e:
                results[ioc["value"]] = {
                    "status": "UNKNOWN",
                    "error":  str(e)
                }

    return results


def _check_single(value: str, ioc_type: str, timeout: int) -> dict:
    """Check a single IOC for liveness."""
    result = {
        "value":    value,
        "type":     ioc_type,
        "status":   "UNKNOWN",
        "resolves": None,
        "http_code": None,
        "server":   None,
        "redirect": None,
        "latency_ms": None,
    }

    # Step 1: DNS resolution
    if ioc_type == "domain":
        try:
            start = time.time()
            resolved_ips = socket.getaddrinfo(value, None, socket.AF_INET)
            latency = int((time.time() - start) * 1000)
            if resolved_ips:
                result["resolves"]   = True
                result["latency_ms"] = latency
                result["resolved_ip"] = resolved_ips[0][4][0]
            else:
                result["resolves"] = False
                result["status"]   = "DEAD"
                return result
        except socket.gaierror:
            result["resolves"] = False
            result["status"]   = "DEAD"
            return result
        except Exception:
            result["resolves"] = None

    # Step 2: HTTP HEAD check
    for scheme in ["https", "http"]:
        try:
            url = f"{scheme}://{value}"
            req = urllib.request.Request(
                url,
                method="HEAD",
                headers={"User-Agent": USER_AGENT}
            )

            # Create SSL context that doesn't verify certs
            # (phishing sites often have self-signed certs)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

            start = time.time()
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                latency = int((time.time() - start) * 1000)
                result["status"]     = "LIVE"
                result["http_code"]  = resp.status
                result["server"]     = resp.headers.get("Server", "")
                result["latency_ms"] = latency
                # Check for redirect
                final_url = resp.url
                if final_url and final_url != url:
                    result["redirect"] = final_url
                return result

        except urllib.error.HTTPError as e:
            # Even 4xx/5xx means the server is live
            result["status"]    = "LIVE"
            result["http_code"] = e.code
            return result
        except urllib.error.URLError:
            continue
        except Exception:
            continue

    # Step 3: TCP connect fallback (port 80/443)
    if ioc_type == "ip" or result.get("resolves"):
        target = value
        for port in [443, 80]:
            try:
                start = time.time()
                sock  = socket.create_connection((target, port), timeout=timeout)
                sock.close()
                latency = int((time.time() - start) * 1000)
                result["status"]     = "LIVE"
                result["latency_ms"] = latency
                result["http_code"]  = f"TCP:{port}"
                return result
            except Exception:
                continue

    result["status"] = "DEAD"
    return result


def summarise_liveness(liveness: dict) -> dict:
    """Summarise liveness check results."""
    live    = [v for v in liveness.values() if v.get("status") == "LIVE"]
    dead    = [v for v in liveness.values() if v.get("status") == "DEAD"]
    unknown = [v for v in liveness.values() if v.get("status") == "UNKNOWN"]

    return {
        "total":   len(liveness),
        "live":    len(live),
        "dead":    len(dead),
        "unknown": len(unknown),
        "live_pct": int(len(live) / len(liveness) * 100) if liveness else 0,
        "live_iocs":    [v["value"] for v in live],
        "dead_iocs":    [v["value"] for v in dead],
        "unknown_iocs": [v["value"] for v in unknown],
    }
