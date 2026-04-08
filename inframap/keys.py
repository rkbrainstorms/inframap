"""
inframap key management — secure API key storage and retrieval.

Keys are NEVER passed on the command line (visible in ps aux, bash history).
Stored in ~/.config/inframap/keys.conf with chmod 600 permissions.
Also supports environment variables.

Storage priority:
  1. Environment variables (INFRAMAP_URLSCAN_KEY etc.)
  2. Config file (~/.config/inframap/keys.conf)
  3. Legacy env vars (URLSCAN_API_KEY etc.) for backward compat

Tiers:
  TIER 1 — no key needed, always runs
  TIER 2 — free account key, better results
  TIER 3 — premium key, best results (future)
"""

import os
import stat
import configparser
from pathlib import Path


CONFIG_DIR  = Path.home() / ".config" / "inframap"
CONFIG_FILE = CONFIG_DIR / "keys.conf"

ENV_MAP = {
    "urlscan":    ["INFRAMAP_URLSCAN_KEY",    "URLSCAN_API_KEY"],
    "abuseipdb":  ["INFRAMAP_ABUSEIPDB_KEY",  "ABUSEIPDB_API_KEY"],
    "threatfox":  ["INFRAMAP_THREATFOX_KEY",  "THREATFOX_API_KEY"],
    "urlhaus":    ["INFRAMAP_URLHAUS_KEY",     "URLHAUS_API_KEY"],
    "virustotal": ["INFRAMAP_VT_KEY",          "VT_API_KEY"],
    "shodan":     ["INFRAMAP_SHODAN_KEY",      "SHODAN_API_KEY"],
}

SOURCES = {
    "crtsh":        {"tier": 1, "key": None,         "desc": "Certificate transparency (crt.sh)"},
    "certspotter":  {"tier": 1, "key": None,         "desc": "CT fallback (CertSpotter)"},
    "google_ct":    {"tier": 1, "key": None,         "desc": "CT fallback (Google CT)"},
    "rdap":         {"tier": 1, "key": None,         "desc": "Structured WHOIS (RDAP)"},
    "bgphe":        {"tier": 1, "key": None,         "desc": "ASN/hosting (BGP.he.net)"},
    "hackertarget": {"tier": 1, "key": None,         "desc": "Passive DNS (HackerTarget, 100/day)"},
    "mnemonic":     {"tier": 1, "key": None,         "desc": "Passive DNS fallback (Mnemonic)"},
    "internetdb":   {"tier": 1, "key": None,         "desc": "Open ports/tags (Shodan InternetDB)"},
    "liveness":     {"tier": 1, "key": None,         "desc": "IOC liveness checking"},
    "urlscan":      {"tier": 2, "key": "urlscan",    "desc": "Scan history (urlscan.io, 1000/day free)"},
    "abuseipdb":    {"tier": 2, "key": "abuseipdb",  "desc": "IP reputation (AbuseIPDB, 1000/day free)"},
    "threatfox":    {"tier": 2, "key": "threatfox",  "desc": "Malware IOC DB (ThreatFox, free account)"},
    "urlhaus":      {"tier": 2, "key": "urlhaus",    "desc": "Malware URL DB (URLhaus, free account)"},
    "virustotal":   {"tier": 3, "key": "virustotal", "desc": "File/URL reputation (VirusTotal, premium)"},
    "shodan":       {"tier": 3, "key": "shodan",     "desc": "Internet scanner (Shodan, premium)"},
}

KEY_URLS = {
    "urlscan":    "https://urlscan.io/user/signup",
    "abuseipdb":  "https://www.abuseipdb.com/register",
    "threatfox":  "https://auth.abuse.ch/",
    "urlhaus":    "https://auth.abuse.ch/",
    "virustotal": "https://www.virustotal.com/gui/join-us",
    "shodan":     "https://account.shodan.io/register",
}


class KeyManager:
    def __init__(self):
        self._keys = {}
        self._load_env()
        self._load_config()

    def _load_env(self):
        for key_name, env_vars in ENV_MAP.items():
            for env_var in env_vars:
                val = os.environ.get(env_var)
                if val and val.strip():
                    self._keys[key_name] = val.strip()
                    break

    def _load_config(self):
        if not CONFIG_FILE.exists():
            return
        # Warn if permissions are too open
        mode = oct(stat.S_IMODE(CONFIG_FILE.stat().st_mode))
        if mode not in ("0o600", "0o400"):
            print(f"  [!] Warning: {CONFIG_FILE} permissions are {mode}. "
                  f"Run: chmod 600 {CONFIG_FILE}")
        config = configparser.ConfigParser()
        try:
            config.read(CONFIG_FILE)
            for key_name in ENV_MAP.keys():
                if key_name not in self._keys:
                    val = config.get("keys", key_name, fallback=None)
                    if val and val.strip() and "your_key_here" not in val:
                        self._keys[key_name] = val.strip()
        except Exception:
            pass

    def get(self, key_name):
        return self._keys.get(key_name)

    def has(self, key_name):
        return bool(self._keys.get(key_name))

    def mask(self, key_name):
        key = self._keys.get(key_name)
        if not key:
            return "not configured"
        if len(key) <= 8:
            return "****"
        return key[:4] + "****" + key[-4:]

    def status(self):
        result = {}
        for source, info in SOURCES.items():
            key_name = info.get("key")
            if key_name is None:
                result[source] = {
                    "tier": info["tier"], "desc": info["desc"],
                    "status": "NO KEY NEEDED", "available": True,
                }
            else:
                configured = self.has(key_name)
                result[source] = {
                    "tier": info["tier"], "desc": info["desc"],
                    "status": "CONFIGURED" if configured else "NOT SET",
                    "masked": self.mask(key_name) if configured else None,
                    "get_key": KEY_URLS.get(key_name),
                    "available": configured,
                }
        return result

    def save_key(self, key_name, value):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        config = configparser.ConfigParser()
        if CONFIG_FILE.exists():
            config.read(CONFIG_FILE)
        if "keys" not in config:
            config["keys"] = {}
        config["keys"][key_name] = value
        self._keys[key_name] = value
        with open(CONFIG_FILE, "w") as f:
            config.write(f)
        CONFIG_FILE.chmod(0o600)

    def remove_key(self, key_name):
        config = configparser.ConfigParser()
        if CONFIG_FILE.exists():
            config.read(CONFIG_FILE)
            if "keys" in config and key_name in config["keys"]:
                del config["keys"][key_name]
                with open(CONFIG_FILE, "w") as f:
                    config.write(f)
                CONFIG_FILE.chmod(0o600)
        self._keys.pop(key_name, None)


def init_config():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if CONFIG_FILE.exists():
        return False
    template = """; inframap API keys — chmod 600 enforced automatically
; Get free keys:
;   urlscan   : https://urlscan.io/user/signup
;   abuseipdb : https://www.abuseipdb.com/register
;   threatfox : https://auth.abuse.ch/
;   urlhaus   : https://auth.abuse.ch/  (same account as threatfox)

[keys]
; urlscan    = your_key_here
; abuseipdb  = your_key_here
; threatfox  = your_key_here
; urlhaus    = your_key_here
"""
    with open(CONFIG_FILE, "w") as f:
        f.write(template)
    CONFIG_FILE.chmod(0o600)
    return True


_km = None

def get_key_manager():
    global _km
    if _km is None:
        _km = KeyManager()
    return _km
