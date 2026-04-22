#!/usr/bin/env bash
# OpenCode Security Agent — install plugin + skill.
#
# Copies the plugin and skill files to OpenCode's config directories.
#
# Scope:
#   --user     (default) Install globally at ~/.config/opencode/
#   --project  Install only for the current project at .opencode/
#
# Requires: python3

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
SCOPE="user"

for arg in "$@"; do
  case "$arg" in
    --user) SCOPE="user" ;;
    --project) SCOPE="project" ;;
    -h|--help)
      echo "Usage: $0 [--user|--project]"
      exit 0
      ;;
    *)
      echo "Unknown flag: $arg" >&2; exit 2 ;;
  esac
done

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required but not found on PATH." >&2
  exit 1
fi

if [[ "$SCOPE" == "user" ]]; then
  PLUGIN_DIR="$HOME/.config/opencode/plugins"
  SKILL_DIR="$HOME/.config/opencode/skills/security-agent"
else
  PLUGIN_DIR="$(pwd)/.opencode/plugins"
  SKILL_DIR="$(pwd)/.opencode/skills/security-agent"
fi

# Create directories
mkdir -p "$PLUGIN_DIR"
mkdir -p "$SKILL_DIR"

# Copy plugin files
cp "$REPO_DIR/plugins/security-agent.ts" "$PLUGIN_DIR/"
cp "$REPO_DIR/plugins/sentinel_preflight.py" "$PLUGIN_DIR/"
chmod +x "$PLUGIN_DIR/sentinel_preflight.py"

# Copy IOCs alongside plugin (for the Python script to find)
cp "$REPO_DIR/references/iocs.json" "$PLUGIN_DIR/"

# Copy skill
cp "$REPO_DIR/skills/security-agent/SKILL.md" "$SKILL_DIR/"

echo "OpenCode Security Agent installed successfully!"
echo ""
echo "  Plugin: $PLUGIN_DIR/security-agent.ts"
echo "  Hook:   $PLUGIN_DIR/sentinel_preflight.py"
echo "  IOCs:   $PLUGIN_DIR/iocs.json"
echo "  Skill:  $SKILL_DIR/SKILL.md"
echo ""
echo "Restart OpenCode for the plugin to take effect."
echo "To uninstall: run scripts/uninstall.sh"
