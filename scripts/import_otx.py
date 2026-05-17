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

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from ioc_utils import load_iocs, save_iocs, merge_domains


def main():
    raw = sys.stdin.read().strip()
    if not raw:
        print("OTX: empty input (API may be down or returned an error)", file=sys.stderr)
        sys.exit(0)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"OTX: invalid JSON response: {e}", file=sys.stderr)
        sys.exit(0)
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
