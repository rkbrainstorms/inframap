# inframap

[![CI](https://github.com/rkbrainstorms/inframap/actions/workflows/ci.yml/badge.svg)](https://github.com/rkbrainstorms/inframap/actions/workflows/ci.yml)

Infrastructure fingerprinting and attribution engine for CTI analysts. Chains crt.sh, RDAP, passive DNS, urlscan.io, Shodan InternetDB, ThreatFox, URLhaus, AbuseIPDB, and BGP data into a single investigation workflow — free APIs only, no enterprise subscriptions.

```
  _        __                          
 (_)_ __  / _|_ __ __ _ _ __ ___   __ _ _ __  
 | | '_ \| |_| '__/ _` | '_ ` _ \ / _` | '_ \ 
 | | | | |  _| | | (_| | | | | | | (_| | |_) |
 |_|_| |_|_| |_|  \__,_|_| |_| |_|\__,_| .__/ 
                                         |_|    
```

![inframap demo](demo.gif)

---

## Why this exists

CTI analysts pivot across 6-8 separate tools for every investigation — crt.sh, WHOIS, urlscan.io, BGP lookups, passive DNS, abuse databases. Each pivot is manual. Each tool loses the context from the last one. Writing the report at the end takes hours.

inframap chains all of that into one command and generates the report automatically.

---

## What it does

**Standard investigation:**
```bash
python3 inframap.py -d onmicrosoft.co --threatcheck --live --report
```

Output (real run against a known AiTM phishing platform):
```
  ┌─ ATTRIBUTION CONFIDENCE ──────────────────────────────────┐
  │  CONFIRMED                                                 │
  │  [███████████████████████████████████████████████░░░]  95/100  │
  └────────────────────────────────────────────────────────────┘

  certs: 207  ·  domains: 85  ·  urlscan hits: 100

  FINDINGS
  CONFIRMED   crt.sh          fast-spin: ≥5 certs in one month
  CONFIRMED   crt.sh          rapid issuance cluster
  CONFIRMED   urlscan.io      100 scans found
  CONFIRMED   liveness-check  25/30 IOCs currently LIVE

  IOC LIVENESS
  LIVE: 25  DEAD: 5  UNKNOWN: 0
  ● banquelaurentienne[.]mail[.]onmicrosoft[.]co   TCP:443 (176ms)
  ● citadellabs[.]mail[.]onmicrosoft[.]co          TCP:443 (182ms)
  ● kpmg[.]mail[.]onmicrosoft[.]co                TCP:443 (178ms)

[✓] investigation report written to inframap_report_onmicrosoft_co.md
```

**Compare two domains for shared operator:**
```bash
python3 inframap.py --compare domain1.com domain2.com
```

**Proactive hunting — find newly registered suspicious domains:**
```bash
python3 inframap.py --hunt --keyword "outlook-verify" --days 14
```

**Phishing kit detection:**
```bash
python3 inframap.py -d evil-domain.com --phishing
```

---

## Installation

```bash
git clone https://github.com/rkbrainstorms/inframap.git
cd inframap
python3 inframap.py --help
```

No dependencies beyond Python 3.6+. Everything uses stdlib.

```bash
# Or install via pip
pip install git+https://github.com/rkbrainstorms/inframap.git
inframap --help
```

---

## All flags

```
python3 inframap.py -d DOMAIN               # basic scan
python3 inframap.py -i IP                   # IP pivot
python3 inframap.py --compare A B           # shared operator score
python3 inframap.py --hunt --keyword WORD   # proactive hunting
python3 inframap.py -d DOMAIN --phishing    # phishing kit detection
python3 inframap.py -d DOMAIN --live        # check IOC liveness
python3 inframap.py -d DOMAIN --threatcheck # ThreatFox + URLhaus match
python3 inframap.py -d DOMAIN --report      # generate prose report
python3 inframap.py -d DOMAIN -o markdown   # markdown export
python3 inframap.py -d DOMAIN -o csv        # CSV export
python3 inframap.py -d DOMAIN -o json       # JSON export
python3 inframap.py -d DOMAIN --depth 2     # pivot on discovered infra
python3 inframap.py -d DOMAIN -q -o json | jq .  # pipe-friendly
```

---

## Data sources

All free. Most need no account.

| Source | What it provides | Key needed? |
|--------|-----------------|-------------|
| crt.sh | Certificate transparency logs | No |
| CertSpotter | CT fallback when crt.sh is down | No |
| Google CT | CT fallback #2 | No |
| RDAP (IANA) | Structured WHOIS | No |
| BGP.he.net | ASN, routing, hosting analysis | No |
| HackerTarget | Passive DNS, reverse IP | No |
| Mnemonic PDNS | Passive DNS fallback | No |
| Shodan InternetDB | Open ports, CVEs, tags | No |
| ThreatFox | Known malware IOC database | No |
| URLhaus | Malware URL database | No |
| urlscan.io | Scan history, page metadata | Optional (1k/day free) |
| AbuseIPDB | IP abuse scoring | Optional (1k/day free) |

---

## Attribution tiers

| Score | Label | Meaning |
|-------|-------|---------|
| 70–100 | CONFIRMED | Multiple independent sources corroborate |
| 40–69 | ANALYST ASSESSMENT | Documented evidence basis, single-source |
| 1–39 | CIRCUMSTANTIAL | Pattern match, treat as lead |
| 0 | INSUFFICIENT DATA | Check keys or try different seed |

---

## Architecture

```
inframap.py
inframap/
  pivots/
    crtsh.py          CT logs (crt.sh + CertSpotter + Google CT fallback)
    rdap.py           Structured WHOIS
    urlscan.py        urlscan.io
    abuseip.py        AbuseIPDB
    bgphe.py          BGP.he.net
    passivedns.py     HackerTarget + Mnemonic PDNS
    phishdetect.py    Phishing kit detection
    internetdb.py     Shodan InternetDB
    threatmatch.py    ThreatFox + URLhaus
    liveness.py       IOC liveness checking
    hunt.py           Proactive hunting
    certfallback.py   CertSpotter + Google CT
  engine/
    cluster.py        Cert + WHOIS clustering
    confidence.py     Attribution scoring
    compare.py        Shared operator comparison
  output/
    table.py          Terminal output
    export.py         CSV, JSON, Markdown
    report.py         Prose report generation
```

---

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) first. Zero external dependencies is non-negotiable — stdlib only.

---

## Legal

Queries passive, public data sources only. Does not scan or probe target infrastructure. All IOC output defanged by default.

---

MIT License · Built by [@rkbrainstorms](https://github.com/rkbrainstorms)
