# inframap

**Open-source infrastructure fingerprinting & attribution engine for CTI analysts.**

Chain certificate transparency logs, passive DNS, WHOIS fingerprinting, urlscan.io, AbuseIPDB, and BGP data into a single attribution report — using only **free, no-enterprise APIs**.

Built for the security research community. No paywalls. No subscriptions. Just analyst tradecraft as code.

```
  _        __                          
 (_)_ __  / _|_ __ __ _ _ __ ___   __ _ _ __  
 | | '_ \| |_| '__/ _` | '_ ` _ \ / _` | '_ \ 
 | | | | |  _| | | (_| | | | | | | (_| | |_) |
 |_|_| |_|_| |_|  \__,_|_| |_| |_|\__,_| .__/ 
                                         |_|    
  infrastructure fingerprinting & attribution engine
  free & open source | no enterprise APIs required
```

![inframap demo](demo.gif)

---

## The problem it solves

Every CTI analyst manually pivots across 5–8 separate tools — crt.sh, WHOIS, urlscan.io, AbuseIPDB, BGP.he.net, passive DNS — with no connective tissue between them. The moment you leave one tool, you lose the thread.

inframap chains these pivots automatically and applies an **attribution confidence layer** on top — not just raw enrichment, but scored, tiered findings with documented evidence basis. The output is paste-ready for investigation reports.

---

## Features

- **Certificate transparency clustering** — groups certs by issuer/timing, detects fast-spin and wildcard abuse, supports `%.onion` wildcard queries
- **WHOIS fingerprint hashing** — normalised RDAP-based registrant fingerprinting for cluster matching across domains
- **Passive DNS** — HackerTarget reverse IP lookups reveal co-hosted domains and infrastructure reuse
- **urlscan.io pivot** — searches existing scan history, extracts IPs, ASNs, page metadata
- **Phishing kit detection** — scans urlscan.io page titles for credential harvesting patterns, AiTM indicators
- **ASN / hosting risk scoring** — BGP.he.net + AbuseIPDB combined into a single hosting risk score
- **Attribution confidence tiers** — `CONFIRMED`, `ANALYST ASSESSMENT`, `CIRCUMSTANTIAL` with evidence basis documented
- **Shared operator comparison** — `--compare` two domains and get a scored shared-operator verdict
- **Multiple output formats** — terminal table, CSV, JSON, Markdown (paste into reports directly)
- **Defanged IOC output** — all IOCs defanged automatically, paste-safe
- **Zero dependencies** — pure Python stdlib + urllib, no pip install required for core use

---

## Installation

### Option 1 — Clone and run (no install needed)
```bash
git clone https://github.com/rkbrainstorms/inframap.git
cd inframap
python3 inframap.py --help
```

### Option 2 — pip install
```bash
pip install git+https://github.com/rkbrainstorms/inframap.git
inframap --help
```

---

## Usage

### Basic scan — domain only, no keys needed
```bash
python3 inframap.py -d evil-domain.com
```

### Full scan with free API keys
```bash
python3 inframap.py -d evil-domain.com \
  --urlscan-key YOUR_KEY \
  --abuseip-key YOUR_KEY
```

### Compare two domains for shared operator
```bash
python3 inframap.py --compare domain1.com domain2.com
```

### Phishing kit detection
```bash
python3 inframap.py -d evil-domain.com --phishing
```

### IP pivot
```bash
python3 inframap.py -i 1.2.3.4 --abuseip-key YOUR_KEY
```

### Export to Markdown (paste into report)
```bash
python3 inframap.py -d evil-domain.com -o markdown --out-file evidence.md
```

### Export to CSV
```bash
python3 inframap.py -d evil-domain.com -o csv --out-file iocs.csv
```

### Depth-2 pivot
```bash
python3 inframap.py -d evil-domain.com --depth 2
```

### Quiet mode for scripting
```bash
python3 inframap.py -d evil-domain.com -q -o json | jq .attribution
```

### Skip specific sources
```bash
python3 inframap.py -d evil-domain.com --skip bgphe abuseip
```

### Environment variables
```bash
export URLSCAN_API_KEY=your_key
export ABUSEIPDB_API_KEY=your_key
python3 inframap.py -d evil-domain.com
```

---

## Real-world example

Running against a known AiTM phishing platform:

```
python3 inframap.py -d onmicrosoft.co --no-color

  ┌─ ATTRIBUTION CONFIDENCE ──────────────────────────────────┐
  │  CONFIRMED                                                 │
  │  [███████████████████████████████████████████████░░░]  95/100  │
  └────────────────────────────────────────────────────────────┘

  certs: 207  ·  domains: 85  ·  urlscan hits: 105
  HackerTarget: 1500 co-hosted domains on same infrastructure

  FINDINGS
  CONFIRMED        crt.sh       fast-spin: ≥5 certs issued in one month
  CONFIRMED        crt.sh       rapid issuance cluster detected
  CONFIRMED        urlscan.io   105 existing scans found
  ANALYST ASSESS.  HackerTarget 1500 co-hosted domains on same infrastructure
```

---

## API keys

All keys are **free tier**. inframap works without any keys (keyless mode).

| Source | Key required? | Free tier | Get key |
|--------|--------------|-----------|---------|
| crt.sh | No | Unlimited | — |
| RDAP (IANA) | No | Unlimited | — |
| BGP.he.net | No | Unlimited | — |
| HackerTarget | No | 100 queries/day | — |
| urlscan.io | Optional | 1,000 searches/day | [urlscan.io/user/signup](https://urlscan.io/user/signup) |
| AbuseIPDB | Optional (IP) | 1,000 checks/day | [abuseipdb.com/register](https://www.abuseipdb.com/register) |

---

## Attribution confidence tiers

| Tier | Label | Meaning |
|------|-------|---------|
| HIGH (70–100) | CONFIRMED | Multiple independent corroborating sources |
| MEDIUM (40–69) | ANALYST ASSESSMENT | Single-source or inferred, documented evidence basis |
| LOW (1–39) | CIRCUMSTANTIAL | Pattern match only, treat as investigative lead |
| NONE (0) | INSUFFICIENT DATA | No data returned — check keys or seeds |

---

## Architecture

```
inframap.py                      Entry point wrapper
inframap/
  inframap.py                    CLI orchestration
  __main__.py                    pip entry point
  pivots/
    crtsh.py                     Certificate transparency
    rdap.py                      Structured WHOIS via RDAP
    urlscan.py                   urlscan.io scan history
    abuseip.py                   AbuseIPDB IP reputation
    bgphe.py                     BGP.he.net ASN analysis
    passivedns.py                HackerTarget passive DNS
    phishdetect.py               Phishing kit detection
  engine/
    cluster.py                   Cert & WHOIS clustering
    confidence.py                Attribution confidence engine
    compare.py                   Shared operator comparison
  output/
    table.py                     ANSI terminal output
    export.py                    CSV, JSON, Markdown export
```

---

## Contributing

PRs welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

Core philosophy: **zero external dependencies**. stdlib + urllib only.

---

## Legal & ethics

inframap queries only **passive, public data sources**. It does not scan, probe, or interact with target infrastructure directly. All IOC output is defanged by default.

Use responsibly. For defensive research and threat intelligence purposes only.

---

## License

MIT License

*Built by [@rkbrainstorms](https://github.com/rkbrainstorms)*
