"""
inframap test suite.
Tests core logic without making any network requests.
Run with: python3 -m pytest tests/ -v
      or: python3 tests/test_inframap.py
"""

import sys
import os
import unittest
import hashlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from inframap.pivots.crtsh      import _extract_org, _cluster_by_timing, _parse_cert
from inframap.pivots.rdap       import _fingerprint, _calc_age, _parse_vcard
from inframap.pivots.bgphe      import _score_bulletproof, KNOWN_CLEAN_ASNS
from inframap.pivots.passivedns import _looks_like_ip
from inframap.engine.confidence import _defang, _dedup_iocs, KNOWN_CLEAN_DOMAINS
from inframap.engine.compare    import compare_domains, _is_privacy


class TestDefanging(unittest.TestCase):

    def test_domain_defang(self):
        self.assertEqual(_defang("evil.com", "domain"), "evil[.]com")

    def test_ip_defang(self):
        self.assertEqual(_defang("1.2.3.4", "ip"), "1[.]2[.]3[.]4")

    def test_email_defang(self):
        result = _defang("attacker@evil.com", "email")
        self.assertIn("[@]", result)
        self.assertIn("[.]", result)

    def test_nameserver_defang(self):
        self.assertEqual(_defang("ns1.evil.com", "nameserver"), "ns1[.]evil[.]com")

    def test_asn_no_defang(self):
        self.assertEqual(_defang("AS12345", "asn"), "AS12345")


class TestBrandDampening(unittest.TestCase):

    def test_known_clean_domains_loaded(self):
        self.assertGreater(len(KNOWN_CLEAN_DOMAINS), 10)
        self.assertIn("google", KNOWN_CLEAN_DOMAINS)
        self.assertIn("microsoft", KNOWN_CLEAN_DOMAINS)

    def test_typosquat_not_in_clean_list(self):
        """onmicrosoft.co should NOT be dampened — it's a typosquat"""
        domain = "onmicrosoft.co"
        domain_stripped = domain.lower().lstrip("www.")
        dampened = False
        for clean in KNOWN_CLEAN_DOMAINS:
            if domain_stripped == clean + ".com" or \
               domain_stripped == clean + ".org" or \
               domain_stripped == clean + ".net" or \
               domain_stripped.endswith("." + clean + ".com"):
                dampened = True
                break
        self.assertFalse(dampened, "onmicrosoft.co should NOT be dampened")

    def test_legit_domain_is_dampened(self):
        """google.com SHOULD be dampened"""
        domain = "google.com"
        domain_stripped = domain.lower().lstrip("www.")
        dampened = False
        for clean in KNOWN_CLEAN_DOMAINS:
            if domain_stripped == clean + ".com":
                dampened = True
                break
        self.assertTrue(dampened, "google.com SHOULD be dampened")

    def test_phishing_domain_not_dampened(self):
        """google-login.com should NOT be dampened"""
        domain = "google-login.com"
        domain_stripped = domain.lower()
        dampened = False
        for clean in KNOWN_CLEAN_DOMAINS:
            if domain_stripped == clean + ".com" or \
               domain_stripped.endswith("." + clean + ".com"):
                dampened = True
                break
        self.assertFalse(dampened, "google-login.com should NOT be dampened")


class TestIOCDedup(unittest.TestCase):

    def test_dedup_removes_duplicates(self):
        iocs = [
            {"type": "domain", "value": "evil.com", "defanged": "evil[.]com", "source": "crt.sh"},
            {"type": "domain", "value": "evil.com", "defanged": "evil[.]com", "source": "rdap"},
        ]
        result = _dedup_iocs(iocs)
        self.assertEqual(len(result), 1)

    def test_seed_takes_priority(self):
        iocs = [
            {"type": "domain", "value": "evil.com", "defanged": "evil[.]com", "source": "crt.sh"},
            {"type": "domain", "value": "evil.com", "defanged": "evil[.]com", "source": "seed"},
        ]
        result = _dedup_iocs(iocs)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["source"], "seed")

    def test_different_iocs_kept(self):
        iocs = [
            {"type": "domain", "value": "evil.com",   "defanged": "evil[.]com",   "source": "seed"},
            {"type": "domain", "value": "evil2.com",  "defanged": "evil2[.]com",  "source": "crt.sh"},
            {"type": "ip",     "value": "1.2.3.4",    "defanged": "1[.]2[.]3[.]4","source": "urlscan"},
        ]
        result = _dedup_iocs(iocs)
        self.assertEqual(len(result), 3)


class TestCrtshParsing(unittest.TestCase):

    def test_extract_org_from_dn(self):
        dn = "C=US, O=Let's Encrypt, CN=R3"
        self.assertEqual(_extract_org(dn), "Let's Encrypt")

    def test_extract_org_fallback(self):
        dn = "CN=SomeCA"
        result = _extract_org(dn)
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)

    def test_cluster_suspicious_flag(self):
        """3+ certs in same cluster should be flagged suspicious"""
        certs = [
            {"id": i, "issuer_org": "Let's Encrypt",
             "not_before": "2024-01-15", "not_after": "2024-04-15",
             "names": [f"sub{i}.evil.com"], "cluster_fp": "abc123"}
            for i in range(5)
        ]
        clusters = _cluster_by_timing(certs)
        self.assertTrue(any(c["suspicious"] for c in clusters))


class TestRdapFingerprinting(unittest.TestCase):

    def test_fingerprint_returns_string(self):
        rdap_data = {
            "registrar": "Namecheap",
            "registrant": {"email": "test@evil.com", "org": "Evil Corp", "name": ""},
            "nameservers": ["ns1.evil.com", "ns2.evil.com"],
            "privacy": False,
            "whois_fp": None
        }
        fp = _fingerprint(rdap_data)
        self.assertIsInstance(fp, str)
        self.assertEqual(len(fp), 16)

    def test_same_registrant_same_fingerprint(self):
        rdap_a = {
            "registrar": "Namecheap",
            "registrant": {"email": "attacker@proton.me", "org": "", "name": ""},
            "nameservers": ["ns1.topdns.com"],
            "privacy": False,
            "whois_fp": None
        }
        rdap_b = dict(rdap_a)  # identical
        self.assertEqual(_fingerprint(rdap_a), _fingerprint(rdap_b))

    def test_different_registrant_different_fingerprint(self):
        rdap_a = {
            "registrar": "Namecheap",
            "registrant": {"email": "a@proton.me", "org": "", "name": ""},
            "nameservers": ["ns1.evil.com"],
            "privacy": False,
            "whois_fp": None
        }
        rdap_b = {
            "registrar": "GoDaddy",
            "registrant": {"email": "b@gmail.com", "org": "", "name": ""},
            "nameservers": ["ns1.other.com"],
            "privacy": False,
            "whois_fp": None
        }
        self.assertNotEqual(_fingerprint(rdap_a), _fingerprint(rdap_b))

    def test_domain_age_calculation(self):
        dates = {"registration": "2020-01-01T00:00:00Z"}
        age = _calc_age(dates)
        self.assertIsNotNone(age)
        self.assertGreater(age, 365)

    def test_domain_age_missing(self):
        age = _calc_age({})
        self.assertIsNone(age)


class TestCompareEngine(unittest.TestCase):

    def test_identical_domains_score_high(self):
        rdap = {
            "domain": "test.com",
            "registrar": "Namecheap",
            "registrant": {"email": "attacker@proton.me", "org": "Evil Corp", "name": ""},
            "nameservers": ["ns1.topdns.com", "ns2.topdns.com"],
            "privacy": False,
            "whois_fp": hashlib.sha256(b"test").hexdigest()[:16]
        }
        result = compare_domains(rdap, rdap)
        self.assertGreaterEqual(result["shared_score"], 60)

    def test_different_domains_score_low(self):
        rdap_a = {
            "domain": "google.com",
            "registrar": "MarkMonitor",
            "registrant": {"email": "dns-admin@google.com", "org": "Google LLC", "name": ""},
            "nameservers": ["ns1.google.com"],
            "privacy": False,
            "whois_fp": "aaaa1111bbbb2222"
        }
        rdap_b = {
            "domain": "evil.com",
            "registrar": "Namecheap",
            "registrant": {"email": "x@proton.me", "org": "", "name": ""},
            "nameservers": ["ns1.topdns.com"],
            "privacy": False,
            "whois_fp": "cccc3333dddd4444"
        }
        result = compare_domains(rdap_a, rdap_b)
        self.assertLess(result["shared_score"], 40)

    def test_privacy_proxy_detected(self):
        self.assertTrue(_is_privacy("whoisguard protected"))
        self.assertTrue(_is_privacy("privacy proxy service"))
        self.assertFalse(_is_privacy("Google LLC"))
        self.assertFalse(_is_privacy("Evil Corp Inc"))


class TestBGPScoring(unittest.TestCase):

    def test_known_bp_asn_scores_high(self):
        result = {
            "asn": "AS9009",  # M247 — in known BP list
            "asn_name": "M247",
            "peer_count": 50,
            "country": "GB",
            "is_known_bp": False,
            "bp_score": 0,
            "bp_indicators": []
        }
        _score_bulletproof(result)
        self.assertGreaterEqual(result["bp_score"], 40)
        self.assertTrue(result["is_known_bp"])

    def test_clean_asn_scores_low(self):
        result = {
            "asn": "AS15169",  # Google
            "asn_name": "GOOGLE",
            "peer_count": 500,
            "country": "US",
            "is_known_bp": False,
            "bp_score": 0,
            "bp_indicators": []
        }
        _score_bulletproof(result)
        self.assertLess(result["bp_score"], 30)


class TestIPValidation(unittest.TestCase):

    def test_valid_ipv4(self):
        self.assertTrue(_looks_like_ip("1.2.3.4"))
        self.assertTrue(_looks_like_ip("192.168.1.1"))
        self.assertTrue(_looks_like_ip("255.255.255.255"))

    def test_invalid_ip(self):
        self.assertFalse(_looks_like_ip("not-an-ip"))
        self.assertFalse(_looks_like_ip("256.1.1.1"))
        self.assertFalse(_looks_like_ip("evil.com"))
        self.assertFalse(_looks_like_ip(""))


if __name__ == "__main__":
    print("Running inframap test suite...")
    print("=" * 60)
    loader  = unittest.TestLoader()
    suite   = loader.loadTestsFromModule(sys.modules[__name__])
    runner  = unittest.TextTestRunner(verbosity=2)
    result  = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
