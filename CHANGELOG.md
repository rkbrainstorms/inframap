# Changelog

All notable changes to inframap are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.2.0] — 2026-04-07

### Added
- **Passive DNS pivot** via HackerTarget free API — reveals co-hosted domains and historical IP resolutions, no key required
- **`--compare` mode** — compare two domains for shared operator using WHOIS fingerprint, nameserver overlap, passive DNS IP overlap, and cert SAN matching. Outputs a 0–100 shared-operator confidence score
- **Phishing kit detection** (`--phishing`) — scans urlscan.io page titles for credential harvesting patterns, Microsoft/Google impersonation, and AiTM platform indicators
- **pip installable** — `pip install git+https://github.com/rkbrainstorms/inframap.git` now works. `inframap` command available after install
- `inframap/__main__.py` entry point for `python3 -m inframap` usage
- `pyproject.toml` with full package metadata and PyPI classifiers

### Changed
- Main CLI logic moved to `inframap/inframap.py` for proper package structure
- Root `inframap.py` is now a thin wrapper (backward compatible)
- Sources list in banner now includes `passivedns`

---

## [1.1.0] — 2026-04-07

### Fixed
- **Confidence scoring false positives** — google.com no longer scores 100/100. Known-clean domains (Google, Microsoft, Cloudflare, etc.) are capped at 30/100 using exact domain match, not substring
- **Typosquat false negatives** — `onmicrosoft.co` and similar typosquats no longer dampened by brand matching
- **`None` abuse_score comparison crash** — `TypeError: '>= not supported between NoneType and int'` fixed
- **Missing `domain_stripped` variable** — NameError in confidence engine fixed
- **crt.sh timeouts** — retry logic with exponential backoff (3 attempts) added, default timeout increased to 15s
- **Auto IP pivot** — AbuseIPDB and BGP.he.net now automatically run on IPs discovered from urlscan, even without `-i` flag
- **ASN names** — urlscan results now show `AS15169 (GOOGLE)` instead of just `AS15169`
- **Domain age** — RDAP now calculates and displays domain age in days, highlighted red if < 30 days
- **Registrar** — now shown in summary line

### Added
- `--version` flag — `python3 inframap.py --version` returns `inframap 1.1.0`

---

## [1.0.0] — 2026-04-07

### Added
- Initial release
- Certificate transparency clustering via crt.sh (no key required)
- WHOIS fingerprint hashing via IANA RDAP (no key required)
- urlscan.io scan history search (free key optional)
- AbuseIPDB IP reputation scoring (free key optional)
- BGP.he.net ASN and hosting risk analysis (no key required)
- Attribution confidence tiers: CONFIRMED / ANALYST ASSESSMENT / CIRCUMSTANTIAL
- Terminal table output with ANSI colors
- CSV, JSON, and Markdown export formats
- Defanged IOC output
- `--depth 2` pivot mode
- `--skip` to exclude specific sources
- `--quiet` mode for scripting
- `--no-color` for plain output
- Environment variable support for API keys
