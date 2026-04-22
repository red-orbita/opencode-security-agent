#!/usr/bin/env bash
# OpenCode Security Agent — Semgrep static scanner for skills and MCP servers.
#
# Scans target directories with custom MCP/skill-specific rules, plus optional
# community rules from semgrep/semgrep-rules.
#
# Usage:
#   bash scripts/scan_semgrep.sh <target-path>              # scan a skill/MCP directory
#   bash scripts/scan_semgrep.sh <target-path> --json       # JSON output
#   bash scripts/scan_semgrep.sh <target-path> --sarif      # SARIF output (GitHub Security tab)
#   bash scripts/scan_semgrep.sh <target-path> --no-community  # skip community rules
#   bash scripts/scan_semgrep.sh --self-test                 # validate custom rules
#
# Exit codes:
#   0  No findings
#   1  Findings detected
#   2  Semgrep not installed or rule error

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
RULES_DIR="$REPO_DIR/rules/semgrep"
CUSTOM_RULES="$RULES_DIR"
COMMUNITY_RULES="$RULES_DIR/community"

# ─── Flags ───────────────────────────────────────────────────────────────

TARGET=""
OUTPUT_FORMAT="text"
USE_COMMUNITY=true
SELF_TEST=false

for arg in "$@"; do
  case "$arg" in
    --json) OUTPUT_FORMAT="json" ;;
    --sarif) OUTPUT_FORMAT="sarif" ;;
    --community) USE_COMMUNITY=true ;;
    --no-community) USE_COMMUNITY=false ;;
    --self-test) SELF_TEST=true ;;
    -h|--help)
      echo "Usage: bash scripts/scan_semgrep.sh <target-path> [--json] [--no-community]"
      echo "       bash scripts/scan_semgrep.sh --self-test"
      echo ""
      echo "Options:"
      echo "  --json           Output results in JSON format"
      echo "  --sarif          Output in SARIF format (for GitHub Security tab)"
      echo "  --no-community   Skip bundled community rules (semgrep/semgrep-rules)"
      echo "  --self-test      Validate all rules without scanning"
      echo ""
      echo "Exit codes:"
      echo "  0  No findings (or rules valid in --self-test)"
      echo "  1  Findings detected"
      echo "  2  Semgrep not installed or configuration error"
      exit 0
      ;;
    *)
      if [[ -z "$TARGET" ]]; then
        TARGET="$arg"
      else
        echo "Unknown argument: $arg" >&2; exit 2
      fi
      ;;
  esac
done

# ─── Check semgrep is installed ─────────────────────────────────────────

if ! command -v semgrep >/dev/null 2>&1; then
  echo "ERROR: semgrep is not installed." >&2
  echo "" >&2
  echo "Install with:" >&2
  echo "  pip install semgrep        # or" >&2
  echo "  brew install semgrep       # macOS" >&2
  echo "  pipx install semgrep       # isolated install" >&2
  exit 2
fi

# ─── Self-test mode ─────────────────────────────────────────────────────

if [[ "$SELF_TEST" == true ]]; then
  echo "Validating Semgrep rules ..."
  echo ""
  rule_count=0
  errors=0

  # Custom rules
  echo "Custom rules ($CUSTOM_RULES):"
  for rule_file in "$CUSTOM_RULES"/*.yaml; do
    [[ -f "$rule_file" ]] || continue
    rule_count=$((rule_count + 1))
    basename_file="$(basename "$rule_file")"
    if semgrep --validate --config "$rule_file" >/dev/null 2>&1; then
      echo "  OK  $basename_file"
    else
      echo "  FAIL  $basename_file" >&2
      semgrep --validate --config "$rule_file" 2>&1 | sed 's/^/       /' >&2
      errors=$((errors + 1))
    fi
  done

  # Community rules
  if [[ -d "$COMMUNITY_RULES" ]]; then
    echo ""
    echo "Community rules ($COMMUNITY_RULES):"
    for dir in "$COMMUNITY_RULES"/*/; do
      [[ -d "$dir" ]] || continue
      dirname_base="$(basename "$dir")"
      [[ "$dirname_base" == "LICENSE" ]] && continue
      yaml_count=$(find "$dir" -name "*.yaml" 2>/dev/null | wc -l)
      rule_count=$((rule_count + yaml_count))
      if semgrep --validate --config "$dir" >/dev/null 2>&1; then
        echo "  OK  $dirname_base/ ($yaml_count rules)"
      else
        echo "  FAIL  $dirname_base/" >&2
        semgrep --validate --config "$dir" 2>&1 | sed 's/^/       /' >&2
        errors=$((errors + 1))
      fi
    done
  fi

  echo ""
  if [[ $errors -eq 0 ]]; then
    echo "$rule_count rule files validated successfully."
    exit 0
  else
    echo "$errors error(s) found across $rule_count rule files." >&2
    exit 2
  fi
fi

# ─── Validate target ────────────────────────────────────────────────────

if [[ -z "$TARGET" ]]; then
  echo "ERROR: No target path specified." >&2
  echo "Usage: bash scripts/scan_semgrep.sh <target-path> [--json] [--community]" >&2
  exit 2
fi

if [[ ! -e "$TARGET" ]]; then
  echo "ERROR: Target path does not exist: $TARGET" >&2
  exit 2
fi

# ─── Build semgrep command ───────────────────────────────────────────────

SEMGREP_ARGS=(
  --config "$CUSTOM_RULES"
  --no-git-ignore
  --metrics off
  --error
)

if [[ "$USE_COMMUNITY" == true ]] && [[ -d "$COMMUNITY_RULES" ]]; then
  SEMGREP_ARGS+=(--config "$COMMUNITY_RULES")
fi

if [[ "$OUTPUT_FORMAT" == "json" ]]; then
  SEMGREP_ARGS+=(--json)
elif [[ "$OUTPUT_FORMAT" == "sarif" ]]; then
  SEMGREP_ARGS+=(--sarif)
fi

# ─── Run scan ────────────────────────────────────────────────────────────

echo "OpenCode Security Agent — Semgrep Static Scanner"
echo "================================================="
echo ""
echo "Target:     $TARGET"
CUSTOM_COUNT=$(ls "$CUSTOM_RULES"/*.yaml 2>/dev/null | wc -l)
COMMUNITY_COUNT=$(find "$COMMUNITY_RULES" -name "*.yaml" 2>/dev/null | wc -l)
echo "Rules:      $CUSTOM_COUNT custom + $COMMUNITY_COUNT community"
if [[ "$USE_COMMUNITY" == false ]]; then
  echo "Community:  disabled (use default or --community to enable)"
fi
echo ""
echo "Running semgrep ..."
echo ""

# semgrep exits 1 when findings are detected -- we want to capture that
set +e
semgrep "${SEMGREP_ARGS[@]}" "$TARGET"
EXIT_CODE=$?
set -e

echo ""
if [[ $EXIT_CODE -eq 0 ]]; then
  echo "No findings. Target appears clean."
elif [[ $EXIT_CODE -eq 1 ]]; then
  echo "Findings detected. Review the output above."
else
  echo "Semgrep exited with code $EXIT_CODE (possible configuration error)." >&2
fi

exit $EXIT_CODE
