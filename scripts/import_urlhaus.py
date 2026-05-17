#!/usr/bin/env python3
"""
Import malicious URLs from URLhaus (abuse.ch) into iocs.json.

URLhaus is free and requires no API key.

Usage:
  # Recent URLs (last 100)
  curl -s "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/" \
    | python3 scripts/import_urlhaus.py

  # Or pipe any URLhaus API JSON response
  curl -s -X POST "https://urlhaus-api.abuse.ch/v1/url/" \
    -d "url=https://suspicious.example" \
    | python3 scripts/import_urlhaus.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from ioc_utils import load_iocs, save_iocs, merge_domains, extract_domain


def main():
    raw = sys.stdin.read().strip()
    if not raw:
        print("URLhaus: empty input (API may be down or returned an error)", file=sys.stderr)
        sys.exit(0)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"URLhaus: invalid JSON response: {e}", file=sys.stderr)
        sys.exit(0)
    iocs = load_iocs()

    # URLhaus returns {"urls": [...]} for recent/bulk queries
    # or {"url_status": "...", ...} for single-URL lookups
    urls_list = data.get("urls", [])
    if not urls_list and data.get("url_status"):
        # Single URL response
        urls_list = [data]

    new_domains = []
    seen = set()
    for entry in urls_list:
        url = entry.get("url", "")
        domain = extract_domain(url)
        if not domain or domain in seen:
            continue
        seen.add(domain)

        status = entry.get("url_status", "unknown")
        threat = entry.get("threat", "malware_download")
        tags = entry.get("tags") or []
        tag_str = ", ".join(tags) if tags else "untagged"
        ref = entry.get("urlhaus_reference", "https://urlhaus.abuse.ch/")

        new_domains.append({
            "domain": domain,
            "incident": f"URLhaus: {threat} ({status}, tags: {tag_str})",
            "reference": ref,
        })

    added = merge_domains(iocs, new_domains)
    save_iocs(iocs)

    total_urls = len(urls_list)
    print(
        f"URLhaus: processed {total_urls} URLs, extracted {len(seen)} unique domains, "
        f"added {added} new to iocs.json",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
