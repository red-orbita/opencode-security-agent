#!/usr/bin/env python3
"""
Import malicious IPs from AbuseIPDB into iocs.json.

Requires ABUSEIPDB_KEY environment variable. Free tier: 1,000 checks/day.

Usage:
  # Bulk export blacklisted IPs (confidence > 90%)
  curl -s -G "https://api.abuseipdb.com/api/v2/blacklist" \
    -H "Key: $ABUSEIPDB_KEY" \
    -H "Accept: application/json" \
    -d "confidenceMinimum=90" \
    -d "limit=500" \
    | python3 scripts/import_abuseipdb.py
"""

import json
import re
import sys
from pathlib import Path

IOCS_PATH = Path(__file__).parent.parent / "references" / "iocs.json"


def load_iocs():
    if IOCS_PATH.exists():
        return json.loads(IOCS_PATH.read_text())
    return {}


def save_iocs(iocs):
    IOCS_PATH.write_text(json.dumps(iocs, indent=2) + "\n")


def merge_patterns(iocs, new_patterns):
    """Merge new suspicious IP regex patterns."""
    existing = iocs.setdefault("suspicious_network", {})
    patterns = existing.setdefault("suspicious_patterns", [])

    added = 0
    for p in new_patterns:
        if p not in patterns:
            patterns.append(p)
            added += 1
    return added


def ip_to_regex(ip):
    """Convert an IP address to an escaped regex pattern."""
    return re.escape(ip)


def main():
    data = json.load(sys.stdin)
    iocs = load_iocs()

    # AbuseIPDB blacklist: {"data": [{"ipAddress": "...", "abuseConfidenceScore": N}, ...]}
    items = data.get("data", [])
    if not isinstance(items, list):
        print(f"AbuseIPDB: unexpected response format", file=sys.stderr)
        sys.exit(1)

    new_patterns = []
    for entry in items:
        ip = entry.get("ipAddress", "")
        confidence = entry.get("abuseConfidenceScore", 0)
        if ip and confidence >= 90:
            pattern = ip_to_regex(ip)
            new_patterns.append(pattern)

    added = merge_patterns(iocs, new_patterns)
    save_iocs(iocs)

    print(
        f"AbuseIPDB: processed {len(items)} IPs, "
        f"added {added} new patterns to iocs.json",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
