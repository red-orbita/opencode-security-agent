#!/usr/bin/env bash
set -euo pipefail
# Update IOC database from multiple threat intelligence sources.
#
# Usage:
#   bash scripts/update_iocs.sh
#
# Required env vars (set only the ones you have API keys for):
#   URLHAUS_AUTH_KEY   - URLhaus abuse.ch (free, required since 2025)
#   THREATFOX_AUTH_KEY - ThreatFox abuse.ch (free, required since 2025)
#   OTX_API_KEY        - AlienVault OTX (free, unlimited)
#   ABUSEIPDB_KEY      - AbuseIPDB (free, 1000/day)
#
# All sources require API keys. Get free abuse.ch keys at: https://auth.abuse.ch/
#
# NOTE: If the OpenCode Security Agent runtime plugin is active, curl POST
# calls may be blocked by the dangerous_commands pattern. Run this script
# directly with bash (not through the OpenCode agent) or add the threat
# intel API domains to .security/sentinel-allowlist.json.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CURL_TIMEOUT=30
TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE"' EXIT
# Find .env by walking up from script directory
_find_env() {
    local dir="$1"
    while [ "$dir" != "/" ]; do
        if [ -f "$dir/.env" ]; then
            echo "$dir/.env"
            return 0
        fi
        dir="$(dirname "$dir")"
    done
    return 1
}
# Wrapper: fetch URL, save to TMPFILE, show errors on failure
# Usage: _fetch <description> <curl_args...>
_fetch() {
    local desc="$1"; shift
    local http_code
    http_code=$(curl --max-time "$CURL_TIMEOUT" -s -o "$TMPFILE" -w "%{http_code}" "$@" 2>&1) || {
        echo "      curl error (network/timeout)" >&2
        return 1
    }
    if [ "$http_code" -lt 200 ] || [ "$http_code" -ge 300 ]; then
        echo "      HTTP $http_code from $desc" >&2
        [ -s "$TMPFILE" ] && head -c 200 "$TMPFILE" >&2 && echo "" >&2
        return 1
    fi
    if [ ! -s "$TMPFILE" ]; then
        echo "      Empty response from $desc" >&2
        return 1
    fi
    return 0
}
if ENV_FILE=$(_find_env "$SCRIPT_DIR"); then
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
    echo "Loaded API keys from $ENV_FILE"
else
    echo "No .env found (walking up from $SCRIPT_DIR). Set env vars manually."
fi
ERRORS=0
echo "=== IOC Database Update - $(date -Iseconds) ==="
echo ""
# --- URLhaus (requires Auth-Key since 2025) ---
echo "[1/4] URLhaus (abuse.ch)..."
if [ -n "${URLHAUS_AUTH_KEY:-}" ]; then
    if _fetch "URLhaus" \
        -H "Auth-Key: $URLHAUS_AUTH_KEY" \
        "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/"; then
        if python3 "$SCRIPT_DIR/import_urlhaus.py" < "$TMPFILE"; then
            echo "      OK"
        else
            echo "      FAILED (import error)"
            ERRORS=$((ERRORS + 1))
        fi
    else
        echo "      FAILED (fetch error, non-fatal)"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo "      SKIPPED (URLHAUS_AUTH_KEY not set)"
    echo "      Get a free key at: https://auth.abuse.ch/"
fi
echo ""
# --- ThreatFox (requires Auth-Key since 2025) ---
echo "[2/4] ThreatFox (abuse.ch)..."
if [ -n "${THREATFOX_AUTH_KEY:-}" ]; then
if _fetch "ThreatFox" \
    -X POST "https://threatfox-api.abuse.ch/api/v1/" \
    -H "Auth-Key: $THREATFOX_AUTH_KEY" \
    -H "Content-Type: application/json" \
    -d '{"query": "get_iocs", "days": 7}'; then
    if python3 "$SCRIPT_DIR/import_threatfox.py" < "$TMPFILE"; then
        echo "      OK"
    else
        echo "      FAILED (import error)"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo "      FAILED (fetch error, non-fatal)"
    ERRORS=$((ERRORS + 1))
fi
else
    echo "      SKIPPED (THREATFOX_AUTH_KEY not set)"
    echo "      Get a free key at: https://auth.abuse.ch/"
fi
echo ""
# --- AlienVault OTX ---
echo "[3/4] AlienVault OTX..."
if [ -n "${OTX_API_KEY:-}" ]; then
    if _fetch "OTX" \
        -H "X-OTX-API-KEY: $OTX_API_KEY" \
        "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50"; then
        if python3 "$SCRIPT_DIR/import_otx.py" < "$TMPFILE"; then
            echo "      OK"
        else
            echo "      FAILED (import error)"
            ERRORS=$((ERRORS + 1))
        fi
    else
        echo "      FAILED (fetch error, non-fatal)"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo "      SKIPPED (OTX_API_KEY not set)"
fi
echo ""
# --- AbuseIPDB ---
echo "[4/4] AbuseIPDB..."
if [ -n "${ABUSEIPDB_KEY:-}" ]; then
    if _fetch "AbuseIPDB" \
        -G "https://api.abuseipdb.com/api/v2/blacklist" \
        -H "Key: $ABUSEIPDB_KEY" \
        -H "Accept: application/json" \
        -d "confidenceMinimum=90" \
        -d "limit=500"; then
        if python3 "$SCRIPT_DIR/import_abuseipdb.py" < "$TMPFILE"; then
            echo "      OK"
        else
            echo "      FAILED (import error)"
            ERRORS=$((ERRORS + 1))
        fi
    else
        echo "      FAILED (fetch error, non-fatal)"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo "      SKIPPED (ABUSEIPDB_KEY not set)"
fi
echo ""
echo "=== Done ($ERRORS errors) ==="
exit 0
