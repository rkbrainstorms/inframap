"""
STIX 2.1 export — standard threat intelligence sharing format.

No API key required. Pure formatting.

STIX 2.1 is the industry standard for sharing threat intelligence.
Every SIEM (Splunk, Sentinel), SOAR, and TIP (MISP, OpenCTI) ingests it.
This makes inframap output directly importable into enterprise security tools.

Output: STIX 2.1 Bundle with:
  - Indicators (domain, IP, URL)
  - Malware (if ThreatFox matches found)
  - Relationship objects
  - Bundle metadata
"""

import json
import uuid
import hashlib
from datetime import datetime, timezone


STIX_SPEC_VERSION = "2.1"
INFRAMAP_IDENTITY_ID = "identity--inframap-rkbrainstorms"


def _stix_id(obj_type: str, value: str) -> str:
    """Generate deterministic STIX ID from type + value."""
    namespace = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
    return f"{obj_type}--{uuid.uuid5(namespace, f'{obj_type}:{value}')}"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _indicator_pattern(ioc_type: str, value: str) -> str:
    """Generate STIX pattern string for an IOC."""
    type_map = {
        "domain":    f"[domain-name:value = '{value}']",
        "ip":        f"[ipv4-addr:value = '{value}']",
        "url":       f"[url:value = '{value}']",
        "email":     f"[email-addr:value = '{value}']",
        "md5":       f"[file:hashes.MD5 = '{value}']",
        "sha256":    f"[file:hashes.'SHA-256' = '{value}']",
    }
    return type_map.get(ioc_type, f"[domain-name:value = '{value}']")


def export_stix(report: dict, pivot_results: dict = None) -> str:
    """
    Export inframap report as STIX 2.1 Bundle JSON.
    Returns JSON string ready for file output or API submission.
    """
    now        = _now()
    objects    = []
    iocs       = report.get("iocs", [])
    findings   = report.get("findings", [])
    meta       = report.get("meta", {})
    attr       = report.get("attribution", {})
    infra      = report.get("infrastructure", {})

    seed_domain = meta.get("seed_domain", "unknown")
    score       = attr.get("confidence_score", 0)
    tier_label  = attr.get("tier_label", "UNKNOWN")

    # Map confidence score to STIX confidence (0-100)
    stix_confidence = score

    # ── Identity (inframap as the tool) ─────────────────────────
    identity = {
        "type":            "identity",
        "spec_version":    STIX_SPEC_VERSION,
        "id":              INFRAMAP_IDENTITY_ID,
        "created":         now,
        "modified":        now,
        "name":            "inframap",
        "identity_class":  "tool",
        "description":     "Open-source infrastructure attribution engine (github.com/rkbrainstorms/inframap)"
    }
    objects.append(identity)

    # ── Threat Actor / Campaign (if confirmed) ───────────────────
    campaign_id = None
    if score >= 70:
        campaign_id = _stix_id("campaign", seed_domain)
        campaign = {
            "type":          "campaign",
            "spec_version":  STIX_SPEC_VERSION,
            "id":            campaign_id,
            "created":       now,
            "modified":      now,
            "name":          f"Infrastructure campaign: {seed_domain}",
            "description":   (
                f"Malicious infrastructure campaign identified via inframap. "
                f"Seed: {seed_domain}. "
                f"Confidence: {score}/100 ({tier_label}). "
                f"Sources: {', '.join(meta.get('sources_used', []))}"
            ),
            "confidence":    stix_confidence,
            "created_by_ref": INFRAMAP_IDENTITY_ID
        }
        objects.append(campaign)

    # ── Indicators ───────────────────────────────────────────────
    indicator_ids = []
    seen = set()

    for ioc in iocs:
        ioc_type  = ioc.get("type", "domain")
        ioc_value = ioc.get("value", "")

        # Skip wildcards, ASNs, skip already-processed
        if not ioc_value or ioc_value.startswith("*") or ioc_type == "asn":
            continue
        if ioc_value in seen:
            continue
        seen.add(ioc_value)

        # Map ioc types to STIX indicator types
        stix_type_map = {
            "domain":      "domain-name",
            "ip":          "ipv4-addr",
            "email":       "email-addr",
            "url":         "url",
            "nameserver":  "domain-name",
        }
        pattern_type = stix_type_map.get(ioc_type, "domain-name")

        indicator_id = _stix_id("indicator", ioc_value)
        indicator_ids.append(indicator_id)

        # Determine labels
        labels = ["malicious-activity"]
        phish_score = infra.get("phishing_score", 0)
        if phish_score and phish_score >= 60:
            labels.append("phishing")
        if infra.get("malware_families"):
            labels.append("malware")

        indicator = {
            "type":          "indicator",
            "spec_version":  STIX_SPEC_VERSION,
            "id":            indicator_id,
            "created":       now,
            "modified":      now,
            "name":          f"{ioc_type}: {ioc_value}",
            "description":   f"IOC discovered via inframap from seed {seed_domain}. Source: {ioc.get('source', 'unknown')}",
            "pattern":       _indicator_pattern(ioc_type, ioc_value),
            "pattern_type":  "stix",
            "valid_from":    now,
            "labels":        labels,
            "confidence":    stix_confidence,
            "created_by_ref": INFRAMAP_IDENTITY_ID
        }
        objects.append(indicator)

        # Relate indicator to campaign
        if campaign_id:
            rel_id = _stix_id("relationship", f"indicates-{indicator_id}-{campaign_id}")
            relationship = {
                "type":              "relationship",
                "spec_version":      STIX_SPEC_VERSION,
                "id":                rel_id,
                "created":           now,
                "modified":          now,
                "relationship_type": "indicates",
                "source_ref":        indicator_id,
                "target_ref":        campaign_id,
                "created_by_ref":    INFRAMAP_IDENTITY_ID
            }
            objects.append(relationship)

    # ── Malware objects (if ThreatFox matches) ───────────────────
    tm = (pivot_results or {}).get("threatmatch", {})
    for family in tm.get("malware_families", []):
        malware_id = _stix_id("malware", family)
        malware = {
            "type":          "malware",
            "spec_version":  STIX_SPEC_VERSION,
            "id":            malware_id,
            "created":       now,
            "modified":      now,
            "name":          family,
            "is_family":     True,
            "labels":        ["trojan"],
            "created_by_ref": INFRAMAP_IDENTITY_ID
        }
        objects.append(malware)

    # ── Note (investigation summary) ─────────────────────────────
    note_id = _stix_id("note", seed_domain + now)
    note = {
        "type":           "note",
        "spec_version":   STIX_SPEC_VERSION,
        "id":             note_id,
        "created":        now,
        "modified":       now,
        "abstract":       f"inframap investigation: {seed_domain} — {tier_label} ({score}/100)",
        "content":        (
            f"Automated investigation by inframap v1.4.0.\n"
            f"Seed: {seed_domain}\n"
            f"Confidence: {score}/100 ({tier_label})\n"
            f"Sources used: {', '.join(meta.get('sources_used', []))}\n"
            f"Generated: {now}\n\n"
            f"Key findings:\n" +
            "\n".join(f"- [{f.get('confidence','')}] {f.get('source','')}: {f.get('text','')}"
                     for f in findings[:10])
        ),
        "object_refs":    indicator_ids[:10],
        "created_by_ref": INFRAMAP_IDENTITY_ID
    }
    objects.append(note)

    # ── Bundle ───────────────────────────────────────────────────
    bundle = {
        "type":         "bundle",
        "id":           f"bundle--{uuid.uuid4()}",
        "spec_version": STIX_SPEC_VERSION,
        "objects":      objects
    }

    return json.dumps(bundle, indent=2)
