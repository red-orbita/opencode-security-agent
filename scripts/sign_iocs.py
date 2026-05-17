#!/usr/bin/env python3
"""
Sign iocs.json with a SHA-256 checksum for integrity verification.

Usage:
  python3 scripts/sign_iocs.py                  # update checksum in-place
  python3 scripts/sign_iocs.py --verify          # verify without modifying

The checksum is computed over the JSON content (sorted keys, compact format)
excluding the checksum_sha256 field itself. This allows sentinel_preflight.py
to detect tampering of the IOC database.
"""

import hashlib
import json
import sys
from pathlib import Path

IOCS_PATH = Path(__file__).parent.parent / "references" / "iocs.json"


def compute_checksum(data):
    """Compute SHA-256 of the IOC data without the checksum field."""
    clean = {k: v for k, v in data.items() if k != "checksum_sha256"}
    content = json.dumps(clean, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(content.encode()).hexdigest()


def main():
    if not IOCS_PATH.exists():
        print(f"Error: {IOCS_PATH} not found", file=sys.stderr)
        sys.exit(1)

    data = json.loads(IOCS_PATH.read_text())

    if "--verify" in sys.argv:
        stored = data.get("checksum_sha256")
        if not stored:
            print("No checksum found in iocs.json. Run without --verify to add one.")
            sys.exit(1)
        actual = compute_checksum(data)
        if actual == stored:
            print(f"OK: checksum matches ({actual[:16]}...)")
            sys.exit(0)
        else:
            print(f"FAIL: checksum mismatch", file=sys.stderr)
            print(f"  stored:   {stored}", file=sys.stderr)
            print(f"  computed: {actual}", file=sys.stderr)
            sys.exit(1)

    # Update checksum
    checksum = compute_checksum(data)
    data["checksum_sha256"] = checksum
    IOCS_PATH.write_text(json.dumps(data, indent=2) + "\n")
    print(f"Updated checksum in iocs.json: {checksum[:16]}...")


if __name__ == "__main__":
    main()
