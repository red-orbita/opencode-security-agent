#!/usr/bin/env python3
"""
Import IOCs from a MISP (Malware Information Sharing Platform) instance into iocs.json.

Requires MISP_URL and MISP_API_KEY environment variables.

Usage:
  # Search for IOCs related to MCP/skill attacks
  curl -s -X POST "$MISP_URL/events/restSearch" \
    -H "Authorization: $MISP_API_KEY" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d '{"tags": ["mcp", "supply-chain"], "published": true, "limit": 50}' \
    | python3 scripts/import_misp.py
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from ioc_utils import load_iocs, save_iocs, merge_domains


def is_ip(value):
    """Check if value looks like a raw IP address."""
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value))


def main():
    raw = sys.stdin.read().strip()
    if not raw:
        print("MISP: empty input (API may be down or returned an error)", file=sys.stderr)
        sys.exit(0)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"MISP: invalid JSON response: {e}", file=sys.stderr)
        sys.exit(0)
    iocs = load_iocs()

    # MISP restSearch returns {"response": [{"Event": {...}}, ...]}
    # or {"response": {"Attribute": [...]}} for attribute searches
    new_domains = []
    seen = set()

    response = data.get("response", [])

    # Handle event-based response
    if isinstance(response, list):
        for item in response:
            event = item.get("Event", {})
            event_info = event.get("info", "unknown event")
            attributes = event.get("Attribute", [])
            for attr in attributes:
                attr_type = attr.get("type", "")
                value = attr.get("value", "").strip()

                if attr_type == "domain" and value and not is_ip(value):
                    if value.lower() not in seen:
                        seen.add(value.lower())
                        new_domains.append({
                            "domain": value.lower(),
                            "incident": f"MISP event: {event_info}",
                            "reference": f"MISP event ID: {event.get('id', 'unknown')}",
                        })

    # Handle attribute-based response
    elif isinstance(response, dict):
        attributes = response.get("Attribute", [])
        for attr in attributes:
            attr_type = attr.get("type", "")
            value = attr.get("value", "").strip()

            if attr_type in ("domain", "hostname") and value and not is_ip(value):
                if value.lower() not in seen:
                    seen.add(value.lower())
                    new_domains.append({
                        "domain": value.lower(),
                        "incident": f"MISP attribute (event {attr.get('event_id', 'unknown')})",
                        "reference": f"MISP event ID: {attr.get('event_id', 'unknown')}",
                    })

    added = merge_domains(iocs, new_domains)
    save_iocs(iocs)

    print(
        f"MISP: extracted {len(seen)} unique domains, "
        f"added {added} new to iocs.json",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
