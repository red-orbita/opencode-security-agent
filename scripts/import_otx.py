#!/usr/bin/env python3
"""
Import IOCs from AlienVault OTX (Open Threat Exchange) into iocs.json.

Requires OTX_API_KEY environment variable.

Usage:
  # Fetch subscribed pulses (last 30 days)
  curl -s -H "X-OTX-API-KEY: $OTX_API_KEY" \
    "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50" \
    | python3 scripts/import_otx.py
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


def main():
    data = json.load(sys.stdin)
    iocs = load_iocs()

    # OTX subscribed pulses: {"results": [{"indicators": [...], ...}, ...]}
    new_domains = []
    seen = set()

    pulses = data.get("results", [])
    for pulse in pulses:
        pulse_name = pulse.get("name", "unknown pulse")
        indicators = pulse.get("indicators", [])
        for ind in indicators:
            ind_type = ind.get("type", "")
            value = ind.get("indicator", "")
            if ind_type == "domain" and value and value.lower() not in seen:
                seen.add(value.lower())
                new_domains.append({
                    "domain": value.lower(),
                    "incident": f"OTX pulse: {pulse_name}",
                    "reference": f"https://otx.alienvault.com/indicator/domain/{value}",
                })

    added = merge_domains(iocs, new_domains)
    save_iocs(iocs)

    print(
        f"OTX: processed {len(pulses)} pulses, extracted {len(seen)} unique domains, "
        f"added {added} new to iocs.json",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
