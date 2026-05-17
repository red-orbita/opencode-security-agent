#!/usr/bin/env python3
"""
Shared utilities for IOC import scripts.

Centralizes load/save/merge logic that was duplicated across
import_urlhaus.py, import_threatfox.py, import_otx.py, etc.
"""

import json
from pathlib import Path
from urllib.parse import urlparse

IOCS_PATH = Path(__file__).parent.parent / "references" / "iocs.json"


def load_iocs(path=None):
    """Load iocs.json and return as dict."""
    p = path or IOCS_PATH
    if p.exists():
        return json.loads(p.read_text())
    return {}


def save_iocs(iocs, path=None):
    """Write iocs dict to iocs.json."""
    p = path or IOCS_PATH
    p.write_text(json.dumps(iocs, indent=2) + "\n")


def merge_domains(iocs, new_domains):
    """Merge new domain entries into iocs['suspicious_network']['known_malicious_domains'].

    Each entry should be a dict with at least a 'domain' key.
    Returns the number of newly added entries.
    """
    existing = iocs.setdefault("suspicious_network", {})
    known = existing.setdefault("known_malicious_domains", [])
    existing_set = {e["domain"].lower() for e in known}

    added = 0
    for entry in new_domains:
        if entry["domain"].lower() not in existing_set:
            known.append(entry)
            existing_set.add(entry["domain"].lower())
            added += 1
    return added


def extract_domain(url):
    """Extract domain from a URL, skipping raw IPs."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if not host or host.replace(".", "").isdigit():
            return None
        return host.lower()
    except Exception:
        return None
