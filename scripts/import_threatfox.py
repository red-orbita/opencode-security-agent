#!/usr/bin/env python3
"""
Import IOCs from ThreatFox (abuse.ch) into iocs.json.

ThreatFox is free and requires no API key.

Usage:
  # Recent IOCs (last 7 days)
  curl -s -X POST "https://threatfox-api.abuse.ch/api/v1/" \
    -H "Content-Type: application/json" \
    -d '{"query": "get_iocs", "days": 7}' \
    | python3 scripts/import_threatfox.py

  # IOCs by tag
  curl -s -X POST "https://threatfox-api.abuse.ch/api/v1/" \
    -H "Content-Type: application/json" \
    -d '{"query": "taginfo", "tag": "cobalt-strike", "limit": 50}' \
    | python3 scripts/import_threatfox.py
"""

import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

IOCS_PATH = Path(__file__).parent.parent / "references" / "iocs.json"


def load_iocs():
    if IOCS_PATH.exists():
        return json.loads(IOCS_PATH.read_text())
    return {}


def save_iocs(iocs):
    IOCS_PATH.write_text(json.dumps(iocs, indent=2) + "\n")


def merge_domains(iocs, new_domains):
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


def extract_domain(ioc_value):
    """Extract domain from a ThreatFox IOC value.

    ThreatFox IOCs can be: domain:port, URL, IP:port, or hash.
    We only want domains (not IPs or hashes).
    """
    # Strip port if present (e.g. "evil.com:443")
    host = ioc_value.split(":")[0].strip()

    # Skip if it looks like a hash (hex string > 30 chars)
    if re.match(r"^[a-fA-F0-9]{32,}$", host):
        return None

    # Skip raw IPs
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
        return None

    # If it looks like a URL, parse it
    if "://" in host:
        try:
            parsed = urlparse(host)
            host = parsed.hostname or ""
        except Exception:
            return None

    # Basic domain validation
    if "." in host and len(host) > 3:
        return host.lower()

    return None


def main():
    raw = sys.stdin.read().strip()
    if not raw:
        print("ThreatFox: empty input (API may be down or returned an error)", file=sys.stderr)
        sys.exit(0)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"ThreatFox: invalid JSON response: {e}", file=sys.stderr)
        sys.exit(0)
    iocs = load_iocs()

    # ThreatFox response: {"query_status": "ok", "data": [...]}
    items = data.get("data", [])
    if not isinstance(items, list):
        print(f"ThreatFox: unexpected response format (query_status: {data.get('query_status')})",
              file=sys.stderr)
        sys.exit(1)

    new_domains = []
    seen = set()
    skipped_types = 0

    for entry in items:
        ioc_value = entry.get("ioc", "")
        ioc_type = entry.get("ioc_type", "")
        malware = entry.get("malware_printable", "unknown")
        threat_type = entry.get("threat_type", "")
        tags = entry.get("tags") or []
        tag_str = ", ".join(tags) if tags else "untagged"
        ref = entry.get("reference", "https://threatfox.abuse.ch/")
        confidence = entry.get("confidence_level", 0)

        # Only process domain and URL types
        if ioc_type not in ("domain", "url"):
            skipped_types += 1
            continue

        domain = extract_domain(ioc_value)
        if not domain or domain in seen:
            continue
        seen.add(domain)

        new_domains.append({
            "domain": domain,
            "incident": f"ThreatFox: {malware} ({threat_type}, confidence: {confidence}%, tags: {tag_str})",
            "reference": ref if ref else "https://threatfox.abuse.ch/",
        })

    added = merge_domains(iocs, new_domains)
    save_iocs(iocs)

    print(
        f"ThreatFox: processed {len(items)} IOCs, extracted {len(seen)} unique domains "
        f"(skipped {skipped_types} non-domain types), added {added} new to iocs.json",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
