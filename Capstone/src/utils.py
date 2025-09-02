# utils.py - helper functions will go here
"""
utils.py - Helper functions for IoT Vulnerability Scanner
"""

import socket
from datetime import datetime


# -------------------------------
# Networking Utilities
# -------------------------------

def check_port(ip, port, timeout=1):
    """
    Check if a single port is open on given IP.
    Returns True if open, False otherwise.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def resolve_domain(domain):
    """
    Resolve domain name to IP address.
    Returns IP string or None if failed.
    """
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


# -------------------------------
# Report & Logging Utilities
# -------------------------------

def timestamp():
    """Return current timestamp as string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def save_file(path, content, mode="w"):
    """Save text content to file safely."""
    with open(path, mode, encoding="utf-8") as f:
        f.write(content)


def banner():
    """Return ASCII banner string."""
    return r"""
    ========================================
     IoT Vulnerability Scanner - Capstone
    ========================================
    """


# -------------------------------
# Data Utilities
# -------------------------------

def clean_date(date_value):
    """
    Normalize WHOIS date fields into string.
    Handles list or None.
    """
    if isinstance(date_value, list):
        return [str(d) for d in date_value]
    return str(date_value) if date_value else "N/A"
