#!/usr/bin/env bash
set -euo pipefail
# Update IOC database from multiple threat intelligence sources.
#
# Usage:
#   bash scripts/update_iocs.sh
#
# Required env vars (set only the ones you have API keys for):
#   OTX_API_KEY      - AlienVault OTX (free, unlimited)
#   ABUSEIPDB_KEY    - AbuseIPDB (free, 1000/day)
#
# No API key needed for: URLhaus, ThreatFox (abuse.ch)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ERRORS=0
echo "=== IOC Database Update - $(date -Iseconds) ==="
echo ""
# --- URLhaus (no API key) ---
echo "[1/4] URLhaus (abuse.ch)..."
if curl -sf "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/" \
    | python3 "$SCRIPT_DIR/import_urlhaus.py"; then
    echo "      OK"
else
    echo "      FAILED (non-fatal)"
    ERRORS=$((ERRORS + 1))
fi
echo ""
# --- ThreatFox (no API key) ---
echo "[2/4] ThreatFox (abuse.ch)..."
if curl -sf -X POST "https://threatfox-api.abuse.ch/api/v1/" \
    -H "Content-Type: application/json" \
    -d '{"query": "get_iocs", "days": 7}' \
    | python3 "$SCRIPT_DIR/import_threatfox.py"; then
    echo "      OK"
else
    echo "      FAILED (non-fatal)"
    ERRORS=$((ERRORS + 1))
fi
echo ""
# --- AlienVault OTX ---
echo "[3/4] AlienVault OTX..."
if [ -n "${OTX_API_KEY:-}" ]; then
    if curl -sf -H "X-OTX-API-KEY: $OTX_API_KEY" \
        "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50" \
        | python3 "$SCRIPT_DIR/import_otx.py"; then
        echo "      OK"
    else
        echo "      FAILED (non-fatal)"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo "      SKIPPED (OTX_API_KEY not set)"
fi
echo ""
# --- AbuseIPDB ---
echo "[4/4] AbuseIPDB..."
if [ -n "${ABUSEIPDB_KEY:-}" ]; then
    if curl -sf -G "https://api.abuseipdb.com/api/v2/blacklist" \
        -H "Key: $ABUSEIPDB_KEY" \
        -H "Accept: application/json" \
        -d "confidenceMinimum=90" \
        -d "limit=500" \
        | python3 "$SCRIPT_DIR/import_abuseipdb.py"; then
        echo "      OK"
    else
        echo "      FAILED (non-fatal)"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo "      SKIPPED (ABUSEIPDB_KEY not set)"
fi
echo ""
echo "=== Done ($ERRORS errors) ==="
exit 0
