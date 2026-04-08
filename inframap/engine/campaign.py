"""
Campaign clustering engine — find shared operators across multiple IOCs.

No API key required for core clustering.
Tier 1 keys enhance matching quality.

Usage:
  inframap --campaign domain1.com domain2.com domain3.com

Algorithm:
  1. Run pivots on each seed (crtsh, rdap, passivedns, urlscan)
  2. Extract fingerprints: registrant hash, nameservers, IP subnets, cert issuers
  3. Build similarity matrix across all seeds
  4. Cluster seeds by shared fingerprints
  5. Score each cluster — SAME_OPERATOR / RELATED / UNRELATED

Why this matters:
  Analysts receive 10-50 suspicious domains per day.
  Manually comparing them takes hours.
  Campaign clustering collapses a list of IOCs into operator clusters
  in seconds — telling you "these 7 are the same campaign, these 3 are different."
"""

from collections import defaultdict
import hashlib


def _extract_fingerprints(pivot_data: dict) -> dict:
    """Extract comparable fingerprints from pivot results for one seed."""
    fps = {
        "registrant_hash": None,
        "nameservers":     set(),
        "ip_subnets":      set(),  # /24
        "cert_issuers":    set(),
        "asns":            set(),
        "registrar":       None,
        "creation_year":   None,
    }

    # RDAP fingerprints
    rdap = pivot_data.get("rdap", {})
    if rdap:
        fps["registrant_hash"] = rdap.get("registrant_hash")
        fps["registrar"]       = rdap.get("registrar", "")
        fps["nameservers"]     = set(rdap.get("nameservers", []))
        age_days = rdap.get("domain_age_days")
        if age_days is not None:
            from datetime import datetime, timezone, timedelta
            year = (datetime.now(timezone.utc) - timedelta(days=age_days)).year
            fps["creation_year"] = year

    # crt.sh fingerprints
    crtsh = pivot_data.get("crtsh", {})
    if crtsh:
        for issuer, count in crtsh.get("issuers", {}).items():
            fps["cert_issuers"].add(issuer)

    # urlscan fingerprints
    urlscan = pivot_data.get("urlscan", {})
    if urlscan:
        for ip in urlscan.get("ips_seen", []):
            parts = ip.split(".")
            if len(parts) == 4:
                fps["ip_subnets"].add(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")
        for asn in urlscan.get("asns_seen", []):
            fps["asns"].add(asn)

    # passivedns fingerprints
    pdns = pivot_data.get("passivedns", {})
    if pdns:
        for ip in pdns.get("unique_ips", []):
            parts = ip.split(".")
            if len(parts) == 4:
                fps["ip_subnets"].add(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")

    return fps


def _similarity_score(fp_a: dict, fp_b: dict) -> tuple:
    """
    Score similarity between two fingerprint sets.
    Returns (score, evidence_list).
    """
    score    = 0
    evidence = []

    # Exact registrant hash match — very strong signal
    if (fp_a.get("registrant_hash") and
        fp_a["registrant_hash"] == fp_b.get("registrant_hash")):
        score += 40
        evidence.append("identical WHOIS registrant fingerprint")

    # Shared nameserver — strong signal
    ns_shared = fp_a["nameservers"] & fp_b["nameservers"]
    if ns_shared:
        score += 25
        evidence.append(f"shared nameserver(s): {', '.join(sorted(ns_shared)[:2])}")

    # Shared IP subnet — medium signal
    # Filter mega-provider subnets
    mega_subnets = {
        "104.18.0.0/16", "172.67.0.0/16",  # Cloudflare
        "13.107.0.0/16", "40.76.0.0/16",   # Microsoft
    }
    subnets_a = fp_a["ip_subnets"] - mega_subnets
    subnets_b = fp_b["ip_subnets"] - mega_subnets
    shared_subnets = subnets_a & subnets_b
    if shared_subnets:
        score += 20
        evidence.append(f"shared IP /24 subnet(s): {', '.join(sorted(shared_subnets)[:2])}")

    # Shared cert issuer — weak signal (many sites use Let's Encrypt)
    issuer_shared = fp_a["cert_issuers"] & fp_b["cert_issuers"]
    # Only score if it's NOT Let's Encrypt (too common)
    meaningful_issuers = {i for i in issuer_shared
                         if "let's encrypt" not in i.lower()
                         and "letsencrypt" not in i.lower()}
    if meaningful_issuers:
        score += 10
        evidence.append(f"shared cert issuer: {', '.join(list(meaningful_issuers)[:1])}")

    # Shared ASN — weak signal (many sites share ASNs)
    mega_asns = {"AS13335", "AS16509", "AS15169", "AS8075", "AS20940"}
    asns_a = fp_a["asns"] - mega_asns
    asns_b = fp_b["asns"] - mega_asns
    shared_asns = asns_a & asns_b
    if shared_asns:
        score += 10
        evidence.append(f"shared ASN: {', '.join(sorted(shared_asns)[:2])}")

    # Same registrar — very weak
    if (fp_a.get("registrar") and
        fp_a["registrar"] == fp_b.get("registrar") and
        fp_a["registrar"] not in ("GoDaddy", "Namecheap", "Google", "Cloudflare")):
        score += 5
        evidence.append(f"shared registrar: {fp_a['registrar']}")

    return min(score, 100), evidence


def cluster_campaign(seeds: list, pivot_results_map: dict) -> dict:
    """
    Cluster multiple seeds into operator groups.

    seeds: list of domain/IP strings
    pivot_results_map: dict mapping seed -> pivot_results dict

    Returns cluster analysis with operator groups.
    """
    result = {
        "seeds":    seeds,
        "clusters": [],
        "matrix":   {},
        "summary":  ""
    }

    if len(seeds) < 2:
        result["summary"] = "Need at least 2 seeds for campaign clustering"
        return result

    # Extract fingerprints for each seed
    fingerprints = {}
    for seed in seeds:
        pivot_data = pivot_results_map.get(seed, {})
        fingerprints[seed] = _extract_fingerprints(pivot_data)

    # Build similarity matrix
    matrix = {}
    for i, seed_a in enumerate(seeds):
        matrix[seed_a] = {}
        for j, seed_b in enumerate(seeds):
            if seed_a == seed_b:
                matrix[seed_a][seed_b] = (100, ["same seed"])
                continue
            if j < i:
                # Use already-computed score
                score, ev = matrix[seed_b][seed_a]
                matrix[seed_a][seed_b] = (score, ev)
                continue
            score, evidence = _similarity_score(
                fingerprints[seed_a],
                fingerprints[seed_b]
            )
            matrix[seed_a][seed_b] = (score, evidence)

    result["matrix"] = {
        s: {t: {"score": v[0], "evidence": v[1]}
            for t, v in row.items()}
        for s, row in matrix.items()
    }

    # Simple greedy clustering
    clustered  = set()
    clusters   = []

    for seed in seeds:
        if seed in clustered:
            continue

        cluster = {
            "seeds":       [seed],
            "score":       100,
            "verdict":     "SINGLE",
            "shared_evidence": []
        }
        clustered.add(seed)

        for other in seeds:
            if other == seed or other in clustered:
                continue
            score, evidence = matrix[seed][other]
            if score >= 30:
                cluster["seeds"].append(other)
                cluster["shared_evidence"].extend(
                    [e for e in evidence if e not in cluster["shared_evidence"]]
                )
                clustered.add(other)

        # Score the cluster
        if len(cluster["seeds"]) == 1:
            cluster["verdict"] = "ISOLATED"
            cluster["score"]   = 0
        else:
            # Average pairwise score within cluster
            pairs = []
            for a in cluster["seeds"]:
                for b in cluster["seeds"]:
                    if a != b:
                        pairs.append(matrix[a][b][0])
            avg = sum(pairs) / len(pairs) if pairs else 0
            cluster["score"] = int(avg)

            if avg >= 60:
                cluster["verdict"] = "SAME_OPERATOR"
            elif avg >= 30:
                cluster["verdict"] = "RELATED"
            else:
                cluster["verdict"] = "WEAK_LINK"

        clusters.append(cluster)

    result["clusters"] = clusters

    # Summary
    same_op = [c for c in clusters if c["verdict"] == "SAME_OPERATOR"]
    related  = [c for c in clusters if c["verdict"] == "RELATED"]
    isolated = [c for c in clusters if c["verdict"] == "ISOLATED"]

    parts = []
    if same_op:
        total_seeds = sum(len(c["seeds"]) for c in same_op)
        parts.append(f"{total_seeds} seeds linked to same operator")
    if related:
        total_seeds = sum(len(c["seeds"]) for c in related)
        parts.append(f"{total_seeds} seeds with weak links")
    if isolated:
        parts.append(f"{len(isolated)} isolated seed(s)")

    result["summary"] = " | ".join(parts) if parts else "No clustering possible"

    return result
