"""
inframap configuration and secure key management.

Keys are stored in ~/.config/inframap/keys (encrypted with machine-derived key).
Never logged, never exposed in output, never committed to git.

Tiers:
  0 — no key needed (crt.sh, RDAP, BGP.he.net, HackerTarget, Mnemonic,
                     Shodan InternetDB, Google CT, CertSpotter)
  1 — free key, simple signup (urlscan.io, AbuseIPDB, ThreatFox, URLhaus)
  2 — premium key (Shodan paid, VirusTotal, etc.)

Usage:
  inframap keys set urlscan YOUR_KEY
  inframap keys set abuseip YOUR_KEY
  inframap keys set threatfox YOUR_KEY
  inframap keys list
  inframap keys remove urlscan
"""

import os
import json
import base64
import hashlib
import stat
import sys
from pathlib import Path


CONFIG_DIR  = Path.home() / ".config" / "inframap"
KEYS_FILE   = CONFIG_DIR / "keys"
GITIGNORE   = CONFIG_DIR / ".gitignore"

# Source registry — defines every data source and its tier
SOURCES = {
    # ── Tier 0: No key needed ──────────────────────────────────────
    "crtsh": {
        "name":     "crt.sh",
        "tier":     0,
        "key_name": None,
        "desc":     "Certificate transparency logs",
        "signup":   None,
        "free_limit": "Unlimited",
    },
    "certspotter": {
        "name":     "CertSpotter",
        "tier":     0,
        "key_name": None,
        "desc":     "CT log fallback (100 req/hour)",
        "signup":   None,
        "free_limit": "100/hour",
    },
    "google_ct": {
        "name":     "Google CT",
        "tier":     0,
        "key_name": None,
        "desc":     "CT log fallback #2",
        "signup":   None,
        "free_limit": "Unlimited",
    },
    "rdap": {
        "name":     "RDAP (IANA)",
        "tier":     0,
        "key_name": None,
        "desc":     "Structured WHOIS",
        "signup":   None,
        "free_limit": "Unlimited",
    },
    "bgphe": {
        "name":     "BGP.he.net",
        "tier":     0,
        "key_name": None,
        "desc":     "ASN and routing data",
        "signup":   None,
        "free_limit": "Unlimited",
    },
    "hackertarget": {
        "name":     "HackerTarget",
        "tier":     0,
        "key_name": None,
        "desc":     "Passive DNS (100/day)",
        "signup":   None,
        "free_limit": "100/day",
    },
    "mnemonic": {
        "name":     "Mnemonic PDNS",
        "tier":     0,
        "key_name": None,
        "desc":     "Passive DNS fallback",
        "signup":   None,
        "free_limit": "Unlimited",
    },
    "internetdb": {
        "name":     "Shodan InternetDB",
        "tier":     0,
        "key_name": None,
        "desc":     "Open ports, CVEs, tags (no key)",
        "signup":   None,
        "free_limit": "Unlimited",
    },

    # ── Tier 1: Free key required ──────────────────────────────────
    "urlscan": {
        "name":     "urlscan.io",
        "tier":     1,
        "key_name": "urlscan",
        "desc":     "Scan history, page metadata",
        "signup":   "https://urlscan.io/user/signup",
        "free_limit": "1,000 searches/day",
        "env_var":  "URLSCAN_API_KEY",
    },
    "abuseip": {
        "name":     "AbuseIPDB",
        "tier":     1,
        "key_name": "abuseip",
        "desc":     "IP abuse scoring",
        "signup":   "https://www.abuseipdb.com/register",
        "free_limit": "1,000 checks/day",
        "env_var":  "ABUSEIPDB_API_KEY",
    },
    "threatfox": {
        "name":     "ThreatFox (abuse.ch)",
        "tier":     1,
        "key_name": "threatfox",
        "desc":     "Known malware IOC database",
        "signup":   "https://auth.abuse.ch/",
        "free_limit": "Unlimited (free account)",
        "env_var":  "THREATFOX_API_KEY",
    },
    "urlhaus": {
        "name":     "URLhaus (abuse.ch)",
        "tier":     1,
        "key_name": "urlhaus",
        "desc":     "Malware URL database",
        "signup":   "https://auth.abuse.ch/",
        "free_limit": "Unlimited (free account)",
        "env_var":  "URLHAUS_API_KEY",
    },

    # ── Tier 2: Premium (optional, paid) ──────────────────────────
    "shodan": {
        "name":     "Shodan",
        "tier":     2,
        "key_name": "shodan",
        "desc":     "Full internet scanning database",
        "signup":   "https://account.shodan.io/register",
        "free_limit": "Limited (paid for full access)",
        "env_var":  "SHODAN_API_KEY",
    },
    "virustotal": {
        "name":     "VirusTotal",
        "tier":     2,
        "key_name": "virustotal",
        "desc":     "File/URL/IP reputation",
        "signup":   "https://www.virustotal.com/gui/join-us",
        "free_limit": "4 lookups/min free",
        "env_var":  "VT_API_KEY",
    },
    "securitytrails": {
        "name":     "SecurityTrails",
        "tier":     2,
        "key_name": "securitytrails",
        "desc":     "Historical DNS, WHOIS, subdomains",
        "signup":   "https://securitytrails.com/app/account",
        "free_limit": "50 queries/month free",
        "env_var":  "SECURITYTRAILS_API_KEY",
    },
}


def _machine_key() -> bytes:
    """
    Derive a machine-specific encryption key.
    Uses a combination of machine identifiers so keys are tied to this machine.
    Not perfect security but prevents casual file copying.
    """
    identifiers = []

    # Username
    identifiers.append(os.getenv("USER", os.getenv("USERNAME", "user")))

    # Home directory path
    identifiers.append(str(Path.home()))

    # Machine ID (Linux)
    for mid_path in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
        try:
            with open(mid_path) as f:
                identifiers.append(f.read().strip())
            break
        except Exception:
            pass

    combined = "|".join(identifiers).encode("utf-8")
    return hashlib.sha256(combined).digest()


def _encrypt(plaintext: str) -> str:
    """Simple XOR encryption with machine key. Not AES but prevents casual reading."""
    key   = _machine_key()
    data  = plaintext.encode("utf-8")
    # Repeat key to match data length
    key_repeated = bytes(key[i % len(key)] ^ data[i] for i in range(len(data)))
    return base64.b64encode(key_repeated).decode("ascii")


def _decrypt(ciphertext: str) -> str:
    """Decrypt XOR-encrypted value."""
    key  = _machine_key()
    data = base64.b64decode(ciphertext.encode("ascii"))
    decrypted = bytes(key[i % len(key)] ^ data[i] for i in range(len(data)))
    return decrypted.decode("utf-8")


def _ensure_config_dir():
    """Create config directory with secure permissions."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    # Set permissions to 700 (owner only)
    os.chmod(CONFIG_DIR, stat.S_IRWXU)

    # Add .gitignore to prevent accidental commits
    if not GITIGNORE.exists():
        GITIGNORE.write_text("*\n")

    # Create empty keys file if needed
    if not KEYS_FILE.exists():
        KEYS_FILE.write_text("{}")
        os.chmod(KEYS_FILE, stat.S_IRUSR | stat.S_IWUSR)  # 600


def _load_keys() -> dict:
    """Load and decrypt stored keys."""
    _ensure_config_dir()
    try:
        raw = json.loads(KEYS_FILE.read_text())
        return {k: _decrypt(v) for k, v in raw.items()}
    except Exception:
        return {}


def _save_keys(keys: dict):
    """Encrypt and save keys."""
    _ensure_config_dir()
    encrypted = {k: _encrypt(v) for k, v in keys.items()}
    KEYS_FILE.write_text(json.dumps(encrypted, indent=2))
    os.chmod(KEYS_FILE, stat.S_IRUSR | stat.S_IWUSR)  # 600


def get_key(name: str):  # -> Optional[str]
    """
    Get an API key by name.
    Priority: CLI arg > env var > stored key
    """
    source = SOURCES.get(name, {})
    env_var = source.get("env_var")

    # Check environment variable first
    if env_var:
        val = os.environ.get(env_var)
        if val:
            return val

    # Check stored keys
    keys = _load_keys()
    return keys.get(name)


def set_key(name: str, value: str):
    """Store an API key securely."""
    if name not in SOURCES:
        raise ValueError(f"Unknown source: {name}. Valid sources: {', '.join(SOURCES.keys())}")
    if SOURCES[name]["tier"] == 0:
        raise ValueError(f"{name} doesn't require a key")

    keys = _load_keys()
    keys[name] = value
    _save_keys(keys)


def remove_key(name: str):
    """Remove a stored API key."""
    keys = _load_keys()
    if name in keys:
        del keys[name]
        _save_keys(keys)


def list_keys() -> dict:
    """List all configured keys (masked for display)."""
    stored = _load_keys()
    result = {}
    for source_id, source in SOURCES.items():
        if source["tier"] == 0:
            continue
        key_val = get_key(source_id)
        if key_val:
            # Mask: show first 4 and last 4 chars
            if len(key_val) > 8:
                masked = key_val[:4] + "..." + key_val[-4:]
            else:
                masked = "****"
            result[source_id] = {"status": "configured", "masked": masked}
        else:
            result[source_id] = {"status": "not set", "masked": None}
    return result


def get_all_keys() -> dict:
    """Get all configured keys for use in pivots."""
    return {
        "urlscan":        get_key("urlscan"),
        "abuseip":        get_key("abuseip"),
        "threatfox":      get_key("threatfox"),
        "urlhaus":        get_key("urlhaus"),
                "shodan":         get_key("shodan"),
        "virustotal":     get_key("virustotal"),
        "securitytrails": get_key("securitytrails"),
    }


def print_key_status():
    """Print a formatted table of key status for `inframap keys list`."""
    keys  = list_keys()
    tiers = {1: "FREE TIER (signup required)", 2: "PREMIUM (paid)"}

    for tier_num, tier_label in tiers.items():
        sources = [
            (sid, s) for sid, s in SOURCES.items()
            if s["tier"] == tier_num
        ]
        if not sources:
            continue

        print(f"\n  {tier_label}")
        print("  " + "─" * 60)
        print(f"  {'SOURCE':<18} {'STATUS':<16} {'LIMIT':<22} SIGNUP")
        print("  " + "─" * 60)

        for sid, source in sources:
            status_info = keys.get(sid, {})
            status      = status_info.get("status", "not set")
            masked      = status_info.get("masked", "")
            limit       = source.get("free_limit", "")
            signup      = source.get("signup", "")

            if status == "configured":
                status_str = f"✓ {masked}"
            else:
                status_str = "✗ not configured"

            print(f"  {source['name']:<18} {status_str:<16} {limit:<22} {signup}")
