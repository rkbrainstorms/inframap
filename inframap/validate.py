"""
Input validation for inframap seeds.
Sanitizes all user input before passing to network functions.

Prevents:
- Malformed domains causing unexpected API behaviour
- IPv6/IPv4 confusion
- Shell injection via domain names
- Excessively long inputs causing timeouts
- Private IP ranges being checked externally
"""

import re
import ipaddress


MAX_DOMAIN_LEN = 253
MAX_LABEL_LEN  = 63

# Private/reserved IP ranges that should never be checked externally
PRIVATE_RANGES = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("255.255.255.255/32"),
]


def validate_domain(domain: str) -> tuple:
    """
    Validate a domain name.
    Returns (is_valid, cleaned_domain, error_message).
    """
    if not domain:
        return False, None, "domain cannot be empty"

    # Strip whitespace and lowercase
    domain = domain.strip().lower()

    # Remove http/https if accidentally included
    domain = re.sub(r'^https?://', '', domain)

    # Remove trailing slash
    domain = domain.rstrip('/')

    # Remove trailing dot (FQDN format)
    domain = domain.rstrip('.')

    # Length check
    if len(domain) > MAX_DOMAIN_LEN:
        return False, None, f"domain too long ({len(domain)} chars, max {MAX_DOMAIN_LEN})"

    # Character whitelist — domains can only contain alphanumeric, hyphens, dots
    if not re.match(r'^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$', domain):
        return False, None, f"domain contains invalid characters: {domain}"

    # Must have at least one dot
    if '.' not in domain:
        return False, None, f"'{domain}' doesn't look like a valid domain (no TLD)"

    # Check each label
    labels = domain.split('.')
    for label in labels:
        if len(label) > MAX_LABEL_LEN:
            return False, None, f"domain label too long: '{label}'"
        if label.startswith('-') or label.endswith('-'):
            return False, None, f"domain label cannot start/end with hyphen: '{label}'"
        if not label:
            return False, None, "domain contains empty label (double dot)"

    # TLD must be alphabetic
    tld = labels[-1]
    if not tld.isalpha():
        return False, None, f"TLD must be alphabetic: '{tld}'"

    # Minimum 2 labels (domain + TLD)
    if len(labels) < 2:
        return False, None, "domain must have at least a name and TLD"

    return True, domain, None


def validate_ip(ip: str) -> tuple:
    """
    Validate an IP address (v4 or v6).
    Returns (is_valid, cleaned_ip, error_message).
    Warns about private/reserved ranges.
    """
    if not ip:
        return False, None, "IP cannot be empty"

    ip = ip.strip()

    try:
        parsed = ipaddress.ip_address(ip)

        # Check for private ranges
        if isinstance(parsed, ipaddress.IPv4Address):
            for private_range in PRIVATE_RANGES:
                if parsed in private_range:
                    return False, None, (
                        f"{ip} is a private/reserved IP address. "
                        "inframap only queries public infrastructure."
                    )

        if parsed.is_loopback:
            return False, None, f"{ip} is a loopback address"

        if parsed.is_multicast:
            return False, None, f"{ip} is a multicast address"

        return True, str(parsed), None

    except ValueError:
        return False, None, f"'{ip}' is not a valid IP address"


def validate_email(email: str) -> tuple:
    """Validate an email address for WHOIS pivoting."""
    if not email:
        return False, None, "email cannot be empty"

    email = email.strip().lower()

    # Basic email validation
    if not re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', email):
        return False, None, f"'{email}' doesn't look like a valid email address"

    if len(email) > 254:
        return False, None, "email too long"

    return True, email, None


def validate_cert_hash(cert_hash: str) -> tuple:
    """Validate a certificate SHA-256 hash."""
    if not cert_hash:
        return False, None, "cert hash cannot be empty"

    cert_hash = cert_hash.strip().lower()

    # Remove 0x prefix if present
    cert_hash = cert_hash.lstrip('0x')

    if not re.match(r'^[0-9a-f]+$', cert_hash):
        return False, None, "cert hash must be hexadecimal"

    if len(cert_hash) not in (40, 64):  # SHA-1 or SHA-256
        return False, None, f"cert hash length {len(cert_hash)} unexpected (expected 40 or 64 hex chars)"

    return True, cert_hash, None


def validate_asn(asn: str) -> tuple:
    """Validate an ASN string like AS12345."""
    if not asn:
        return False, None, "ASN cannot be empty"

    asn = asn.strip().upper()

    if not asn.startswith("AS"):
        asn = "AS" + asn

    if not re.match(r'^AS\d{1,10}$', asn):
        return False, None, f"'{asn}' is not a valid ASN (expected format: AS12345)"

    return True, asn, None


def validate_keyword(keyword: str) -> tuple:
    """Validate a hunt keyword."""
    if not keyword:
        return False, None, "keyword cannot be empty"

    keyword = keyword.strip().lower()

    # Only allow safe characters for crt.sh queries
    if not re.match(r'^[a-z0-9\-\.]+$', keyword):
        return False, None, "keyword must contain only letters, numbers, hyphens, and dots"

    if len(keyword) < 3:
        return False, None, "keyword too short (minimum 3 characters)"

    if len(keyword) > 50:
        return False, None, "keyword too long (maximum 50 characters)"

    return True, keyword, None


def sanitize_api_key(key: str) -> str:
    """Strip whitespace and newlines from API keys."""
    if not key:
        return ""
    # Remove common accidental inclusions
    return key.strip().strip('"').strip("'").strip()


def validate_all_args(args) -> list:
    """
    Validate all provided arguments.
    Returns list of error strings (empty = all valid).
    """
    errors = []

    if hasattr(args, 'domain') and args.domain:
        valid, cleaned, err = validate_domain(args.domain)
        if not valid:
            errors.append(f"Invalid domain: {err}")
        else:
            args.domain = cleaned

    if hasattr(args, 'ip') and args.ip:
        valid, cleaned, err = validate_ip(args.ip)
        if not valid:
            errors.append(f"Invalid IP: {err}")
        else:
            args.ip = cleaned

    if hasattr(args, 'email') and args.email:
        valid, cleaned, err = validate_email(args.email)
        if not valid:
            errors.append(f"Invalid email: {err}")
        else:
            args.email = cleaned

    if hasattr(args, 'cert') and args.cert:
        valid, cleaned, err = validate_cert_hash(args.cert)
        if not valid:
            errors.append(f"Invalid cert hash: {err}")
        else:
            args.cert = cleaned

    if hasattr(args, 'asn') and args.asn:
        valid, cleaned, err = validate_asn(args.asn)
        if not valid:
            errors.append(f"Invalid ASN: {err}")
        else:
            args.asn = cleaned

    if hasattr(args, 'keyword') and args.keyword:
        valid, cleaned, err = validate_keyword(args.keyword)
        if not valid:
            errors.append(f"Invalid keyword: {err}")
        else:
            args.keyword = cleaned

    if hasattr(args, 'compare') and args.compare:
        for i, dom in enumerate(args.compare):
            valid, cleaned, err = validate_domain(dom)
            if not valid:
                errors.append(f"Invalid domain in --compare position {i+1}: {err}")
            else:
                args.compare[i] = cleaned

    if hasattr(args, 'timeout') and args.timeout:
        if args.timeout < 1 or args.timeout > 120:
            errors.append("Timeout must be between 1 and 120 seconds")

    if hasattr(args, 'days') and args.days:
        if args.days < 1 or args.days > 365:
            errors.append("Days must be between 1 and 365")

    return errors
