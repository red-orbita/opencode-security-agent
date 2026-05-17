#!/usr/bin/env python3
"""
Claude Code hooks adapter for sentinel_preflight.

Claude Code supports PreToolUse hooks that receive JSON on stdin:
{
  "hook_type": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {"command": "..."}
}

And expect JSON on stdout:
  {"decision": "allow"}
  {"decision": "block", "reason": "..."}

This adapter translates between Claude Code's hook protocol and
sentinel_preflight's decide() function.

Setup in claude_code_config.json or .claude/hooks.json:
{
  "hooks": {
    "PreToolUse": [
      {
        "command": "python3 /path/to/claude_code_hook.py",
        "timeout": 5000
      }
    ]
  }
}
"""

import json
import sys
import time

# Ensure the plugins directory is importable
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "plugins"))

from sentinel_preflight import decide, __version__


def main():
    if "--version" in sys.argv:
        print(f"sentinel_preflight (claude-code adapter) {__version__}")
        sys.exit(0)

    t0 = time.monotonic()

    raw = sys.stdin.read()
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        print(json.dumps({"decision": "allow"}))
        return

    # Claude Code sends hook_type, tool_name, tool_input at top level.
    # sentinel_preflight.decide() expects the same keys, so it works directly.
    decision, reason = decide(payload)
    elapsed = round((time.monotonic() - t0) * 1000, 2)

    if decision == "block":
        print(json.dumps({
            "decision": "block",
            "reason": reason or "Blocked by Sentinel Security Agent",
        }))
    else:
        # Claude Code only supports allow/block; "warn" maps to allow.
        print(json.dumps({"decision": "allow"}))


if __name__ == "__main__":
    main()
