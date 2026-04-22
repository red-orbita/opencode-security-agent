#!/usr/bin/env bash
# OpenCode Security Agent — uninstall plugin + skill.
#
# Removes the security agent plugin and skill files.

set -euo pipefail

SCOPE="user"
for arg in "$@"; do
  case "$arg" in
    --user) SCOPE="user" ;;
    --project) SCOPE="project" ;;
    *) echo "Unknown flag: $arg" >&2; exit 2 ;;
  esac
done

if [[ "$SCOPE" == "user" ]]; then
  PLUGIN_DIR="$HOME/.config/opencode/plugins"
  SKILL_DIR="$HOME/.config/opencode/skills/security-agent"
else
  PLUGIN_DIR="$(pwd)/.opencode/plugins"
  SKILL_DIR="$(pwd)/.opencode/skills/security-agent"
fi

# Remove plugin files
rm -f "$PLUGIN_DIR/security-agent.ts"
rm -f "$PLUGIN_DIR/sentinel_preflight.py"
rm -f "$PLUGIN_DIR/iocs.json"

# Remove skill
rm -rf "$SKILL_DIR"

echo "OpenCode Security Agent removed."
echo "Restart OpenCode for changes to take effect."
