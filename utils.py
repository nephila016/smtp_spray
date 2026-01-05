#!/usr/bin/env python3
"""
Utility functions for SMTP Spray Tool.
- MX record lookup
- Email format validation
- Username generation
- Proxy support helpers
"""

import re
import socket
from typing import List, Optional, Tuple


# ============================================================================
# MX RECORD LOOKUP
# ============================================================================

def get_mx_records(domain: str) -> List[Tuple[int, str]]:
    """
    Get MX records for a domain.
    Returns list of (priority, hostname) tuples sorted by priority.

    Requires: pip install dnspython
    """
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, 'MX')
        records = []
        for rdata in answers:
            records.append((rdata.preference, str(rdata.exchange).rstrip('.')))
        return sorted(records, key=lambda x: x[0])
    except ImportError:
        print("dnspython not installed. Install with: pip install dnspython")
        return []
    except Exception as e:
        print(f"MX lookup failed: {e}")
        return []


def get_smtp_server_for_domain(domain: str) -> Optional[str]:
    """Get the primary SMTP server for a domain"""
    records = get_mx_records(domain)
    if records:
        return records[0][1]
    return None


# ============================================================================
# EMAIL/USERNAME UTILITIES
# ============================================================================

def is_valid_email(email: str) -> bool:
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def extract_domain(email: str) -> Optional[str]:
    """Extract domain from email address"""
    if '@' in email:
        return email.split('@')[1]
    return None


def generate_email_variants(name: str, domain: str) -> List[str]:
    """
    Generate common email format variants from a name.
    Input: "John Smith", "example.com"
    Output: ["john.smith@example.com", "jsmith@example.com", ...]
    """
    variants = []
    parts = name.lower().split()

    if len(parts) >= 2:
        first = parts[0]
        last = parts[-1]

        # Common formats
        variants.extend([
            f"{first}.{last}@{domain}",           # john.smith
            f"{first}{last}@{domain}",            # johnsmith
            f"{first[0]}{last}@{domain}",         # jsmith
            f"{first}{last[0]}@{domain}",         # johns
            f"{first[0]}.{last}@{domain}",        # j.smith
            f"{last}.{first}@{domain}",           # smith.john
            f"{last}{first[0]}@{domain}",         # smithj
            f"{first}_{last}@{domain}",           # john_smith
            f"{first}-{last}@{domain}",           # john-smith
            f"{first}@{domain}",                  # john
            f"{last}@{domain}",                   # smith
        ])
    elif len(parts) == 1:
        variants.append(f"{parts[0]}@{domain}")

    return variants


def generate_usernames_from_file(
    names_file: str,
    domain: str,
    output_file: Optional[str] = None
) -> List[str]:
    """
    Generate email addresses from a file of names.
    """
    emails = []
    with open(names_file, 'r') as f:
        for line in f:
            name = line.strip()
            if name and not name.startswith('#'):
                emails.extend(generate_email_variants(name, domain))

    # Remove duplicates while preserving order
    seen = set()
    unique_emails = []
    for email in emails:
        if email not in seen:
            seen.add(email)
            unique_emails.append(email)

    if output_file:
        with open(output_file, 'w') as f:
            f.write('\n'.join(unique_emails))

    return unique_emails


# ============================================================================
# COMMON SMTP SERVERS
# ============================================================================

COMMON_SMTP_SERVERS = {
    'gmail.com': ('smtp.gmail.com', 587),
    'outlook.com': ('smtp.office365.com', 587),
    'hotmail.com': ('smtp.office365.com', 587),
    'live.com': ('smtp.office365.com', 587),
    'yahoo.com': ('smtp.mail.yahoo.com', 587),
    'icloud.com': ('smtp.mail.me.com', 587),
    'aol.com': ('smtp.aol.com', 587),
    'zoho.com': ('smtp.zoho.com', 587),
    'protonmail.com': ('smtp.protonmail.com', 587),
    'mail.com': ('smtp.mail.com', 587),
}


def get_common_smtp_server(domain: str) -> Optional[Tuple[str, int]]:
    """Get SMTP server for common email providers"""
    return COMMON_SMTP_SERVERS.get(domain.lower())


# ============================================================================
# PASSWORD GENERATION
# ============================================================================

def generate_seasonal_passwords(
    years: List[int] = None,
    include_special: bool = True
) -> List[str]:
    """Generate season+year password combinations"""
    if years is None:
        from datetime import datetime
        current_year = datetime.now().year
        years = [current_year - 1, current_year, current_year + 1]

    seasons = ['Spring', 'Summer', 'Fall', 'Winter', 'Autumn']
    passwords = []

    for year in years:
        for season in seasons:
            passwords.append(f"{season}{year}")
            if include_special:
                passwords.append(f"{season}{year}!")
                passwords.append(f"{season}{year}@")
                passwords.append(f"{season}{year}#")

    return passwords


def generate_month_passwords(
    years: List[int] = None,
    include_special: bool = True
) -> List[str]:
    """Generate month+year password combinations"""
    if years is None:
        from datetime import datetime
        current_year = datetime.now().year
        years = [current_year - 1, current_year, current_year + 1]

    months = [
        'January', 'February', 'March', 'April', 'May', 'June',
        'July', 'August', 'September', 'October', 'November', 'December'
    ]
    passwords = []

    for year in years:
        for month in months:
            passwords.append(f"{month}{year}")
            if include_special:
                passwords.append(f"{month}{year}!")

    return passwords


def generate_company_passwords(
    company_name: str,
    years: List[int] = None,
    include_special: bool = True
) -> List[str]:
    """Generate company-name based passwords"""
    if years is None:
        from datetime import datetime
        current_year = datetime.now().year
        years = [current_year - 1, current_year, current_year + 1]

    passwords = []
    name = company_name.replace(' ', '')
    name_cap = name.capitalize()
    name_lower = name.lower()

    # Basic patterns
    passwords.extend([
        f"{name_cap}1",
        f"{name_cap}123",
        f"{name_cap}1234",
        f"{name_lower}1",
        f"{name_lower}123",
    ])

    # With years
    for year in years:
        passwords.extend([
            f"{name_cap}{year}",
            f"{name_lower}{year}",
        ])
        if include_special:
            passwords.extend([
                f"{name_cap}{year}!",
                f"{name_lower}{year}!",
                f"{name_cap}@{year}",
            ])

    # With special chars
    if include_special:
        passwords.extend([
            f"{name_cap}1!",
            f"{name_cap}123!",
            f"{name_cap}@123",
            f"{name_cap}#1",
        ])

    return passwords


# ============================================================================
# NETWORK UTILITIES
# ============================================================================

def check_port_open(host: str, port: int, timeout: float = 5.0) -> bool:
    """Check if a port is open on a host"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False


def scan_smtp_ports(host: str, timeout: float = 5.0) -> List[int]:
    """Scan common SMTP ports"""
    smtp_ports = [25, 465, 587, 2525]
    open_ports = []

    for port in smtp_ports:
        if check_port_open(host, port, timeout):
            open_ports.append(port)

    return open_ports


def get_banner(host: str, port: int, timeout: float = 5.0) -> Optional[str]:
    """Get SMTP banner from server"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        return banner.strip()
    except:
        return None


# ============================================================================
# CLI UTILITIES
# ============================================================================

def print_banner_info(host: str):
    """Print SMTP server information"""
    print(f"\n[*] Scanning {host} for SMTP services...")

    open_ports = scan_smtp_ports(host)
    if not open_ports:
        print(f"[-] No SMTP ports found open on {host}")
        return

    print(f"[+] Open SMTP ports: {open_ports}")

    for port in open_ports:
        banner = get_banner(host, port)
        if banner:
            print(f"[+] Port {port} banner: {banner}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python utils.py <domain_or_host>")
        print("\nExamples:")
        print("  python utils.py example.com     # MX lookup and port scan")
        print("  python utils.py mail.example.com  # Port scan and banner grab")
        sys.exit(1)

    target = sys.argv[1]

    # Check if it's a domain (for MX lookup)
    if '.' in target and not target.replace('.', '').isdigit():
        print(f"\n[*] MX Records for {target}:")
        mx_records = get_mx_records(target)
        if mx_records:
            for priority, server in mx_records:
                print(f"    Priority {priority}: {server}")
                print_banner_info(server)
        else:
            print(f"    No MX records found, trying direct connection...")
            print_banner_info(target)
    else:
        print_banner_info(target)
