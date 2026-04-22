#!/usr/bin/env python3
"""
Template for importing IOCs from an external threat intelligence API.

Usage:
  curl -s <API_ENDPOINT> | python3 scripts/import_template.py

Copy this file to scripts/import_<provider>.py and adapt the parsing logic
in main() for your specific API's response format.
"""

import json
import sys
from pathlib import Path

IOCS_PATH = Path(__file__).parent.parent / "references" / "iocs.json"


def load_iocs():
    if IOCS_PATH.exists():
        return json.loads(IOCS_PATH.read_text())
    return {}


def save_iocs(iocs):
    IOCS_PATH.write_text(json.dumps(iocs, indent=2) + "\n")


def merge_domains(iocs, new_domains):
    """Merge new malicious domains into the IOC library.

    Each entry should be: {"domain": "...", "incident": "...", "reference": "..."}
    Returns the count of newly added entries.
    """
    existing = iocs.setdefault("suspicious_network", {})
    known = existing.setdefault("known_malicious_domains", [])
    existing_domains = {e["domain"].lower() for e in known}

    added = 0
    for entry in new_domains:
        if entry["domain"].lower() not in existing_domains:
            known.append(entry)
            existing_domains.add(entry["domain"].lower())
            added += 1

    return added


def merge_ips(iocs, new_patterns):
    """Merge new suspicious IP regex patterns.

    Each pattern should be a regex string matching malicious IPs/URLs.
    Returns the count of newly added patterns.
    """
    existing = iocs.setdefault("suspicious_network", {})
    patterns = existing.setdefault("suspicious_patterns", [])

    added = 0
    for p in new_patterns:
        if p not in patterns:
            patterns.append(p)
            added += 1

    return added


def merge_pastebin_services(iocs, new_services):
    """Merge new pastebin-style exfiltration services."""
    existing = iocs.setdefault("suspicious_network", {})
    services = existing.setdefault("pastebin_style", [])

    added = 0
    for s in new_services:
        if s.lower() not in [x.lower() for x in services]:
            services.append(s)
            added += 1

    return added


def main():
    # Read API response from stdin
    data = json.load(sys.stdin)

    iocs = load_iocs()

    # ---------------------------------------------------------------
    # ADAPT THIS SECTION FOR YOUR API
    # Parse the API response and build lists of IOCs to merge.
    # ---------------------------------------------------------------
    new_domains = []
    for item in data.get("results", []):
        new_domains.append({
            "domain": item["indicator"],
            "incident": f"Imported from API on {item.get('date', 'unknown')}",
            "reference": item.get("reference", ""),
        })

    added = merge_domains(iocs, new_domains)
    # ---------------------------------------------------------------

    save_iocs(iocs)
    print(f"Merged {added} new IOCs into {IOCS_PATH}", file=sys.stderr)


if __name__ == "__main__":
    main()
