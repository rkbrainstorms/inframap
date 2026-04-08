"""
MX record analysis — mail infrastructure signals.

No API key required. Uses stdlib DNS resolution.

Why this matters for CTI:
  AiTM platforms register subdomains like mail.victim.onmicrosoft.co
  specifically to intercept email. Domains with mail-specific subdomains
  are actively targeting email flows, not just credential harvesting.

  Phishing domains often have NO MX records (disposable infra).
  Legitimate domains always have MX records.
  Mismatch between domain age and MX provider is a signal.
"""

import socket
import subprocess
import re


SUSPICIOUS_MX = {
    "topdns.com", "1984.is", "njalla.net", "privacyguardian.org",
    "anonymize.com", "mailhide.io"
}

BULLETPROOF_MX = {
    "nforce.nl", "nforce.com", "frantech.ca", "pq.hosting",
    "maxko.org", "serverius.net"
}


def pivot_mx(domain: str, timeout: int = 5) -> dict:
    """
    Look up MX records for a domain and score them for suspicion.
    Uses system dig/nslookup — no API key required.
    """
    result = {
        "domain":       domain,
        "mx_records":   [],
        "has_mx":       False,
        "mx_providers": [],
        "suspicious":   False,
        "risk_signals": [],
        "errors":       []
    }

    try:
        # Use dig for reliable MX lookup
        proc = subprocess.run(
            ["dig", "+short", "MX", domain],
            capture_output=True, text=True, timeout=timeout
        )
        output = proc.stdout.strip()

        if output and "NXDOMAIN" not in output:
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    priority = parts[0]
                    mx_host  = parts[1].rstrip(".")
                    result["mx_records"].append({
                        "priority": priority,
                        "host":     mx_host
                    })
                    # Extract provider from MX host
                    parts2 = mx_host.split(".")
                    if len(parts2) >= 2:
                        provider = ".".join(parts2[-2:])
                        result["mx_providers"].append(provider)

        result["has_mx"] = len(result["mx_records"]) > 0

    except (subprocess.TimeoutExpired, FileNotFoundError):
        # Fallback: try socket DNS
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, "MX")
            for rdata in answers:
                mx_host = str(rdata.exchange).rstrip(".")
                result["mx_records"].append({
                    "priority": rdata.preference,
                    "host":     mx_host
                })
            result["has_mx"] = True
        except Exception as e:
            result["errors"].append(f"MX lookup failed: {str(e)}")
    except Exception as e:
        result["errors"].append(f"MX error: {str(e)}")

    # Score MX records
    for mx in result["mx_records"]:
        host = mx.get("host", "").lower()

        # Check for suspicious/bulletproof MX providers
        for sus in SUSPICIOUS_MX:
            if sus in host:
                result["suspicious"] = True
                result["risk_signals"].append(f"suspicious MX provider: {host}")

        for bp in BULLETPROOF_MX:
            if bp in host:
                result["suspicious"] = True
                result["risk_signals"].append(f"bulletproof MX provider: {host}")

        # Mail subdomains of the domain itself = AiTM signal
        if domain in host and any(x in host for x in ["mail.", "smtp.", "mx."]):
            result["risk_signals"].append(
                f"self-hosted mail on suspicious domain: {host}"
            )

    # No MX = likely disposable/phishing domain
    if not result["has_mx"] and not result["errors"]:
        result["risk_signals"].append("no MX records — likely disposable infrastructure")

    return result
