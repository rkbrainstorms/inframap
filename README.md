# inframap

**Open-source infrastructure fingerprinting & attribution engine for CTI analysts.**

Pivot across certificate transparency logs, WHOIS, urlscan.io, AbuseIPDB, and BGP data — using only **free, no-enterprise APIs** — and get a structured attribution report with explicit confidence tiers.

Built for the security research community. No paywalls, no enterprise subscriptions required.

```
  _        __                          
 (_)_ __  / _|_ __ __ _ _ __ ___   __ _ _ __  
 | | '_ \| |_| '__/ _` | '_ ` _ \ / _` | '_ \ 
 | | | | |  _| | | (_| | | | | | | (_| | |_) |
 |_|_| |_|_| |_|  \__,_|_| |_| |_|\__,_| .__/ 
                                         |_|    
  infrastructure fingerprinting & attribution engine
```

---

## The problem it solves

Every CTI analyst manually pivots across 5–8 separate tools — crt.sh, WHOIS, urlscan.io, AbuseIPDB, BGP.he.net — with no connective tissue between them. The moment you leave one tool, you lose the thread.

inframap chains these pivots automatically and applies an **attribution confidence layer** on top — not just raw enrichment, but scored, tiered findings with documented evidence basis. The output is paste-ready for investigation reports.

---

## Features

- **Certificate transparency clustering** — groups certs by issuer/timing, detects fast-spin and wildcard abuse, supports `%.onion` wildcard queries
- **WHOIS fingerprint hashing** — normalised RDAP-based registrant fingerprinting for cluster matching across domains
- **urlscan.io submission graph** — searches existing scan history for IP/domain, extracts infrastructure and page metadata
- **ASN / hosting risk scoring** — BGP.he.net + AbuseIPDB combined into a single hosting risk score with bulletproof hoster detection
- **Attribution confidence tiers** — `CONFIRMED`, `ANALYST ASSESSMENT`, `CIRCUMSTANTIAL` with evidence basis documented
- **Multiple output formats** — terminal table, CSV, JSON, Markdown (paste into reports directly)
- **Defanged IOC output** — all IOCs defanged automatically, paste-safe
- **Depth-2 pivoting** — optionally pivot on discovered IPs/domains from the first pass

---

## Installation

```bash
git clone https://github.com/rhishav/inframap.git
cd inframap
python inframap.py --help       # no dependencies beyond Python 3.6+
```

No pip install required. Uses only Python stdlib + `urllib` (built-in).

---

## Usage

### Basic — domain only (no keys needed)
```bash
python inframap.py -d evil-domain.com
```

### With free API keys (recommended)
```bash
python inframap.py -d evil-domain.com \
  --urlscan-key YOUR_KEY \
  --abuseip-key YOUR_KEY
```

### IP pivot
```bash
python inframap.py -i 1.2.3.4 --abuseip-key YOUR_KEY
```

### Export to Markdown (paste into your report)
```bash
python inframap.py -d evil-domain.com -o markdown --out-file evidence.md
```

### Export to CSV (for ingestion into ThreatFox, MISP, etc.)
```bash
python inframap.py -d evil-domain.com -o csv --out-file iocs.csv
```

### Depth-2 pivot (pivot on discovered infrastructure)
```bash
python inframap.py -d evil-domain.com --depth 2
```

### Quiet mode + JSON (for scripting/piping)
```bash
python inframap.py -d evil-domain.com -q -o json | jq .attribution
```

### Skip specific sources
```bash
python inframap.py -d evil-domain.com --skip bgphe abuseip
```

### Environment variables (avoid passing keys on CLI)
```bash
export URLSCAN_API_KEY=your_key
export ABUSEIPDB_API_KEY=your_key
python inframap.py -d evil-domain.com
```

---

## API keys

All keys are **free tier**. inframap works without any keys (keyless mode), but results are richer with them.

| Source | Key required? | Free tier | Get key |
|--------|--------------|-----------|---------|
| crt.sh | No | Unlimited | — |
| RDAP (IANA) | No | Unlimited | — |
| BGP.he.net | No | Unlimited | — |
| urlscan.io | Optional | 1,000 searches/day | [urlscan.io/user/signup](https://urlscan.io/user/signup) |
| AbuseIPDB | Optional (for IP) | 1,000 checks/day | [abuseipdb.com/register](https://www.abuseipdb.com/register) |

---

## Output example

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  INFRAMAP — ATTRIBUTION REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Seed domain        evil-domain.com
  Sources used       crt.sh, RDAP, urlscan.io
  Generated          2026-04-04 12:00:00 UTC

  ┌─ ATTRIBUTION CONFIDENCE ────────────────────────────────────────┐
  │  ANALYST ASSESSMENT                                             │
  │  [████████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░]  48/100  │
  └─────────────────────────────────────────────────────────────────┘

  FINDINGS
  ──────────────────────────────────────────────────────────────────
  CONFIDENCE               SOURCE         FINDING
  ──────────────────────────────────────────────────────────────────
  CONFIRMED                crt.sh         rapid cert issuance cluster (5 certs/month)
  ANALYST ASSESSMENT       RDAP           newly registered domain (12 days old)
  ANALYST ASSESSMENT       RDAP           registrant behind privacy proxy

  DEFANGED IOCs
  ──────────────────────────────────────────────────────────────────
  TYPE               SOURCE         DEFANGED VALUE
  ──────────────────────────────────────────────────────────────────
  domain             seed           evil-domain[.]com
  domain             crt.sh         staging.evil-domain[.]com
  nameserver         RDAP           ns1.topdns[.]com
```

---

## Attribution confidence tiers

| Tier | Label | Meaning |
|------|-------|---------|
| HIGH (70–100) | CONFIRMED | Multiple independent corroborating sources |
| MEDIUM (40–69) | ANALYST ASSESSMENT | Single-source or inferred, documented evidence basis |
| LOW (1–39) | CIRCUMSTANTIAL | Pattern match only, treat as investigative lead |
| NONE (0) | INSUFFICIENT DATA | No data returned — check API keys or seeds |

---

## Architecture

```
inframap.py              CLI entry point, orchestration
inframap/
  pivots/
    crtsh.py             Certificate transparency log queries (crt.sh)
    rdap.py              Structured WHOIS via IANA RDAP
    urlscan.py           urlscan.io existing scan search
    abuseip.py           AbuseIPDB IP reputation
    bgphe.py             BGP.he.net ASN & hosting analysis
  engine/
    cluster.py           Cert clustering, WHOIS fingerprinting, ASN scoring
    confidence.py        Attribution confidence engine & report builder
  output/
    table.py             ANSI terminal table output
    export.py            CSV, JSON, Markdown export
```

---

## Roadmap

- [ ] `--compare` mode: diff two domains' fingerprints (shared operator detection)
- [ ] Mermaid/DOT infrastructure graph output
- [ ] Shodan free API integration (when available)
- [ ] PassiveDNS via `hackertarget.com` free API
- [ ] YARA rule generation from cert cluster patterns
- [ ] Web UI (lightweight Flask, optional)

---

## Contributing

PRs welcome. Please keep the zero-dependency philosophy — stdlib + `urllib` only for core pivots. Optional integrations (e.g. rich for terminal output) should be gracefully handled when not installed.

Open an issue if you've found a free/open data source that should be added.

---

## Legal & ethics

inframap queries only **passive, public data sources**. It does not scan, probe, or interact with target infrastructure directly. All IOC output is defanged by default.

Use responsibly. For defensive research and threat intelligence purposes only.

---

## License

MIT License — free to use, modify, and distribute.
