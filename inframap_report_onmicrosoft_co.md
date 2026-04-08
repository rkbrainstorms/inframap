# Threat Infrastructure Investigation Report

**Classification:** TLP:AMBER — Share with trusted parties only  
**Generated:** 2026-04-08 05:25:02 UTC  
**Tool:** inframap v1.4.0 (github.com/rkbrainstorms/inframap)  
**Sources:** crt.sh, RDAP, urlscan.io, BGP.he.net, HackerTarget, Shodan InternetDB

---

## Executive Summary

Investigation of `onmicrosoft.co` identified **confirmed malicious infrastructure** with a confidence score of **95/100** based on multiple independent corroborating sources. Certificate transparency analysis identified **207 certificates** covering **85 unique domains**. The infrastructure has been scanned **100 times** on urlscan.io, indicating active security community interest. Liveness checks confirm **25 of 30 IOCs are currently active**.

## Attribution Assessment

| Field | Value |
|-------|-------|
| Confidence tier | **CONFIRMED** |
| Score | 95/100 |
| Seed | `onmicrosoft.co` |
| ASN | AS13335 (Cloudflare, Inc.) |
| Hosting risk | CLEAN |

## Technical Findings

### CONFIRMED

- **crt.sh**: 1 cert cluster(s) with rapid issuance (≥3 certs/month)
- **crt.sh**: fast-spin detected: ≥5 certs issued in one month (rapid infra standup)
- **urlscan.io**: 100 existing scan(s) found on urlscan.io
- **liveness-check**: 25/30 IOCs are currently LIVE

### ANALYST ASSESSMENT

- **crt.sh**: 1 wildcard SAN entries detected

## Infrastructure Summary

### Certificate Transparency

Certificate transparency logs reveal **207 certificates** covering **85 unique domain names**. 

### urlscan.io Analysis

urlscan.io records **100 historical scans** of this infrastructure. 
Scans originated from: CA, NL, VG.

### Infrastructure Liveness

At the time of investigation, **25 of 30 IOCs (83%) are currently active**. 5 IOCs are offline. 

Currently active infrastructure:
- `onmicrosoft[.]co`
- `1lynden[.]mail[.]onmicrosoft[.]co`
- `access[.]trzcianka[.]onmicrosoft[.]co`
- `akwrc[.]onmicrosoft[.]co`
- `autodiscover[.]rosefinancial0[.]onmicrosoft[.]co`
- `actopantortillas[.]onmicrosoft[.]co`
- `anyconnect[.]trzcianka[.]onmicrosoft[.]co`
- `banquelaurentienne[.]mail[.]onmicrosoft[.]co`
- `brightopaints[.]onmicrosoft[.]co`
- `bbpsmv[.]onmicrosoft[.]co`

## Defanged IOC Table

> All values defanged. Re-fang before operationalising in detection rules.

| Type | Defanged Value | Source |
|------|----------------|--------|
| domain | `onmicrosoft[.]co` | seed |
| domain | `*[.]onmicrosoft[.]co` | crt.sh |
| domain | `1lynden[.]mail[.]onmicrosoft[.]co` | crt.sh |
| domain | `access[.]trzcianka[.]onmicrosoft[.]co` | crt.sh |
| domain | `actopantortillas[.]onmicrosoft[.]co` | crt.sh |
| domain | `akwrc[.]onmicrosoft[.]co` | crt.sh |
| domain | `anyconnect[.]trzcianka[.]onmicrosoft[.]co` | crt.sh |
| domain | `anywhere[.]trzcianka[.]onmicrosoft[.]co` | crt.sh |
| domain | `apps[.]trzcianka[.]onmicrosoft[.]co` | crt.sh |
| domain | `araujofa[.]onmicrosoft[.]co` | crt.sh |
| domain | `autodiscover[.]rosefinancial0[.]onmicrosoft[.]co` | crt.sh |
| domain | `banquelaurentienne[.]mail[.]onmicrosoft[.]co` | crt.sh |
| domain | `bbab[.]centricaplc[.]onmicrosoft[.]co` | crt.sh |
| domain | `bbpsmv[.]onmicrosoft[.]co` | crt.sh |
| domain | `beaconedubh[.]onmicrosoft[.]co` | crt.sh |
| domain | `bmvbmorning[.]onmicrosoft[.]co` | crt.sh |
| domain | `brightopaints[.]onmicrosoft[.]co` | crt.sh |
| domain | `bsystemsmex[.]onmicrosoft[.]co` | crt.sh |
| domain | `c2pht[.]onmicrosoft[.]co` | crt.sh |
| domain | `cabreraburkellc[.]onmicrosoft[.]co` | crt.sh |
| domain | `ccfth[.]onmicrosoft[.]co` | crt.sh |
| domain | `ccna24[.]onmicrosoft[.]co` | crt.sh |
| domain | `ccna79[.]onmicrosoft[.]co` | crt.sh |
| domain | `cisapp[.]trzcianka[.]onmicrosoft[.]co` | crt.sh |
| domain | `citadellabs[.]mail[.]onmicrosoft[.]co` | crt.sh |
| domain | `citrix[.]trzcianka[.]onmicrosoft[.]co` | crt.sh |
| domain | `clientesvpn[.]trzcianka[.]onmicrosoft[.]co` | crt.sh |
| domain | `connect[.]trzcianka[.]onmicrosoft[.]co` | crt.sh |
| domain | `consorciospls[.]onmicrosoft[.]co` | crt.sh |
| domain | `dcvm[.]barakyuvalgmail[.]onmicrosoft[.]co` | crt.sh |
| domain | `domain[.]onmicrosoft[.]co` | crt.sh |
| domain | `edu[.]onmicrosoft[.]co` | crt.sh |
| domain | `email[.]trzcianka[.]onmicrosoft[.]co` | crt.sh |
| domain | `enterpriseenrollment[.]intuneprojektoutlook[.]onmicrosoft[.]co` | crt.sh |
| domain | `garrett4578[.]onmicrosoft[.]co` | crt.sh |
| domain | `geoharbourmideast[.]onmicrosoft[.]co` | crt.sh |
| domain | `gmwords[.]onmicrosoft[.]co` | crt.sh |
| domain | `greatschool66[.]onmicrosoft[.]co` | crt.sh |
| domain | `gvsitita[.]onmicrosoft[.]co` | crt.sh |
| domain | `iededgardovivescampoedu[.]onmicrosoft[.]co` | crt.sh |
| domain | `jatmarteleng[.]onmicrosoft[.]co` | crt.sh |
| domain | `kpmg[.]mail[.]onmicrosoft[.]co` | crt.sh |
| domain | `krodest[.]onmicrosoft[.]co` | crt.sh |
| domain | `l114[.]onmicrosoft[.]co` | crt.sh |
| domain | `labelexellence2020[.]onmicrosoft[.]co` | crt.sh |
| domain | `leopayuksoltutions[.]onmicrosoft[.]co` | crt.sh |
| domain | `linabiotec[.]onmicrosoft[.]co` | crt.sh |
| domain | `mailgate[.]araujofa[.]onmicrosoft[.]co` | crt.sh |
| domain | `mokotow[.]onmicrosoft[.]co` | crt.sh |
| domain | `mramon[.]onmicrosoft[.]co` | crt.sh |
| domain | `msedu7676[.]onmicrosoft[.]co` | crt.sh |
| domain | `netorg6592179[.]onmicrosoft[.]co` | passivedns |
| domain | `netorgft10094199[.]onmicrosoft[.]co` | passivedns |
| domain | `netorgft1044529[.]onmicrosoft[.]co` | passivedns |
| domain | `netorgft10932598[.]onmicrosoft[.]co` | passivedns |
| domain | `netorgft12608179[.]onmicrosoft[.]co` | passivedns |
| domain | `netorgft12912218[.]onmicrosoft[.]co` | passivedns |
| ip | `104[.]18[.]28[.]29` | urlscan.io |
| ip | `208[.]91[.]196[.]145` | urlscan.io |
| ip | `212[.]92[.]104[.]11` | urlscan.io |
| ip | `212[.]92[.]104[.]116` | urlscan.io |
| ip | `212[.]92[.]104[.]2` | urlscan.io |
| ip | `212[.]92[.]104[.]4` | urlscan.io |
| ip | `23[.]227[.]38[.]65` | urlscan.io |
| ip | `23[.]227[.]38[.]74` | urlscan.io |
| asn | `AS13335` | urlscan.io |
| asn | `AS40034` | urlscan.io |
| asn | `AS43350` | urlscan.io |

## Recommended Actions

1. Block all identified IPs and domains at perimeter controls (firewall, proxy, DNS)
2. Submit IOCs to internal SIEM/SOAR for alert correlation
3. Check email gateway logs for messages originating from or linking to identified infrastructure
4. Monitor identified infrastructure for changes (new subdomains, IP changes)
5. Share IOCs with industry peers via appropriate TLP channels
6. Prioritise blocking of currently-live IOCs — infrastructure is active
7. Re-run investigation in 72 hours to track infrastructure changes

## Analyst Notes

> This report was auto-generated by inframap v1.4.0 on 2026-04-08 05:25:02 UTC. All findings should be validated by a qualified analyst before operational use. Confidence scores are based on publicly available passive data sources only.

---

*Generated by [inframap](https://github.com/rkbrainstorms/inframap) — open-source infrastructure attribution for the CTI community*