#!/usr/bin/env python3
"""
OpenCode Security Agent — Skill Validation Gate

Mandatory validation of skill files before they are loaded by the agent.
Performs:
  1. Unicode smuggling scan (invisible characters in .md/.yaml/.json files)
  2. Semgrep static analysis (if semgrep is available)
  3. Structural integrity checks (suspicious patterns in skill metadata)

Usage:
  python3 plugins/skill_validator.py <skill-path>    # validate a skill directory or file
  python3 plugins/skill_validator.py --batch <dir>   # validate all skills in a directory

Exit codes:
  0  Skill is clean
  1  Skill has security issues (blocked)
  2  Configuration error

Protocol: outputs JSON on stdout with verdict and details.
"""

__version__ = "1.0.0"

import json
import os
import re
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Unicode smuggling detection (reuse ranges from sentinel_preflight)
# ---------------------------------------------------------------------------

_UNICODE_SMUGGLING_RANGES = [
    (0xE0000, 0xE007F),   # Tags block (invisible instructions)
    (0xE0100, 0xE01EF),   # Variation Selectors Supplement
    (0x200B, 0x200F),     # Zero-width & directional marks
    (0x2028, 0x2029),     # Line/paragraph separators
    (0x202A, 0x202E),     # Bidirectional overrides
    (0x2060, 0x2064),     # Word joiner, invisible operators
    (0x2066, 0x2069),     # Bidirectional isolates
    (0xFEFF, 0xFEFF),     # BOM / zero-width no-break space
    (0x00AD, 0x00AD),     # Soft hyphen
    (0xFFF9, 0xFFFB),     # Interlinear annotations
]

_SMUGGLING_PATTERN = re.compile(
    "[" + "".join(
        f"\\U{lo:08X}-\\U{hi:08X}" if lo != hi else f"\\U{lo:08X}"
        for lo, hi in _UNICODE_SMUGGLING_RANGES
    ) + "]"
)

# Suspicious patterns in skill content (prompt injection in skill files)
_SKILL_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(in\s+)?(a\s+)?new\s+mode", re.IGNORECASE),
    re.compile(r"IMPORTANT:\s*Execute", re.IGNORECASE),
    re.compile(r"IMPORTANT:\s*Run", re.IGNORECASE),
    re.compile(r"system\s*prompt\s*override", re.IGNORECASE),
    re.compile(r"curl\s+.*\|\s*bash", re.IGNORECASE),
    re.compile(r"wget\s+.*\|\s*sh", re.IGNORECASE),
    re.compile(r"eval\s*\(.*fetch", re.IGNORECASE),
    re.compile(r"<script[^>]*>", re.IGNORECASE),
    re.compile(r"exfiltrate|exfiltration", re.IGNORECASE),
    re.compile(r"send\s+(all\s+)?(data|credentials|tokens|keys)\s+to", re.IGNORECASE),
    re.compile(r"base64\s*-d\s*\|", re.IGNORECASE),
    re.compile(r"nc\s+-[a-z]*\s+\d+\.\d+\.\d+\.\d+", re.IGNORECASE),  # netcat reverse shell
    re.compile(r"send\s+(all\s+)?(credentials|tokens|keys|secrets)\s+(to|at)", re.IGNORECASE),
    re.compile(r"(credentials|tokens|api.?keys?).*https?://", re.IGNORECASE),
]

# File extensions to scan
_SCANNABLE_EXTENSIONS = {
    ".md", ".yaml", ".yml", ".json", ".txt", ".toml",
    ".py", ".js", ".ts", ".sh", ".bash",
}


def scan_file_unicode(file_path: Path) -> list[dict]:
    """Scan a single file for Unicode smuggling. Returns list of findings."""
    findings = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return findings

    matches = _SMUGGLING_PATTERN.findall(content)
    if not matches:
        return findings

    # Classify
    has_tags = any(0xE0000 <= ord(c) <= 0xE007F for c in matches)
    has_bidi = any(
        0x202A <= ord(c) <= 0x202E or 0x2066 <= ord(c) <= 0x2069
        for c in matches
    )

    if has_tags:
        severity = "critical"
        detail = (
            f"Unicode Tag characters (U+E0000-U+E007F) detected — "
            f"invisible instructions smuggling vector. "
            f"Found {len(matches)} hidden character(s)."
        )
    elif has_bidi:
        severity = "high"
        detail = (
            f"Bidirectional override characters detected — "
            f"can hide malicious text. Found {len(matches)} character(s)."
        )
    else:
        severity = "medium"
        detail = (
            f"Invisible Unicode characters detected — "
            f"may hide instructions. Found {len(matches)} character(s)."
        )

    findings.append({
        "file": str(file_path),
        "check": "unicode_smuggling",
        "severity": severity,
        "detail": detail,
        "count": len(matches),
    })
    return findings


def scan_file_injection(file_path: Path) -> list[dict]:
    """Scan a single file for prompt injection patterns."""
    findings = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return findings

    for pattern in _SKILL_INJECTION_PATTERNS:
        match = pattern.search(content)
        if match:
            # Find line number
            line_num = content[:match.start()].count("\n") + 1
            findings.append({
                "file": str(file_path),
                "check": "prompt_injection_in_skill",
                "severity": "high",
                "detail": f"Suspicious pattern at line {line_num}: '{match.group()}'",
                "line": line_num,
            })

    return findings


def run_semgrep(target_path: Path) -> list[dict]:
    """Run semgrep scan if available. Returns findings or empty list."""
    script_dir = Path(__file__).parent.parent / "scripts" / "scan_semgrep.sh"
    if not script_dir.exists():
        return []

    try:
        result = subprocess.run(
            ["bash", str(script_dir), str(target_path), "--json"],
            capture_output=True,
            timeout=60,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    if result.returncode == 2:
        # Semgrep not installed or config error — skip gracefully
        return []

    if result.returncode == 0:
        return []  # No findings

    # Parse JSON output for findings
    findings = []
    try:
        data = json.loads(result.stdout.decode())
        for r in data.get("results", []):
            findings.append({
                "file": r.get("path", ""),
                "check": f"semgrep:{r.get('check_id', 'unknown')}",
                "severity": r.get("extra", {}).get("severity", "warning"),
                "detail": r.get("extra", {}).get("message", "Semgrep finding"),
                "line": r.get("start", {}).get("line", 0),
            })
    except (json.JSONDecodeError, KeyError):
        findings.append({
            "file": str(target_path),
            "check": "semgrep",
            "severity": "medium",
            "detail": "Semgrep found issues but output could not be parsed",
        })

    return findings


def validate_skill(target: Path) -> dict:
    """
    Validate a skill path (file or directory).
    Returns a verdict dict with: verdict, findings, summary.
    """
    findings = []

    if target.is_file():
        files = [target]
    elif target.is_dir():
        files = [
            f for f in target.rglob("*")
            if f.is_file() and f.suffix in _SCANNABLE_EXTENSIONS
        ]
    else:
        return {
            "verdict": "error",
            "findings": [],
            "summary": f"Path does not exist: {target}",
        }

    # 1. Unicode smuggling scan
    for f in files:
        findings.extend(scan_file_unicode(f))

    # 2. Prompt injection pattern scan
    for f in files:
        findings.extend(scan_file_injection(f))

    # 3. Semgrep (if available)
    semgrep_findings = run_semgrep(target)
    findings.extend(semgrep_findings)

    # Determine verdict
    if not findings:
        return {
            "verdict": "clean",
            "findings": [],
            "summary": f"Skill validated: {len(files)} file(s) scanned, no issues found.",
        }

    max_severity = max(
        findings,
        key=lambda f: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(
            f.get("severity", "low"), 0
        ),
    )["severity"]

    if max_severity in ("critical", "high"):
        verdict = "blocked"
    else:
        verdict = "warning"

    return {
        "verdict": verdict,
        "findings": findings,
        "summary": (
            f"Skill validation {'FAILED' if verdict == 'blocked' else 'WARNING'}: "
            f"{len(findings)} issue(s) found in {len(files)} file(s). "
            f"Max severity: {max_severity}."
        ),
    }


def main():
    if "--version" in sys.argv:
        print(f"skill_validator {__version__}")
        sys.exit(0)

    batch_mode = "--batch" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("--")]

    if not args:
        print("Usage: python3 skill_validator.py <skill-path>", file=sys.stderr)
        print("       python3 skill_validator.py --batch <skills-dir>", file=sys.stderr)
        sys.exit(2)

    target = Path(args[0])

    if batch_mode and target.is_dir():
        # Validate each subdirectory as a separate skill
        results = []
        for skill_dir in sorted(target.iterdir()):
            if skill_dir.is_dir() and not skill_dir.name.startswith("."):
                result = validate_skill(skill_dir)
                result["skill"] = skill_dir.name
                results.append(result)
        print(json.dumps({"results": results}, indent=2))
        has_blocked = any(r["verdict"] == "blocked" for r in results)
        sys.exit(1 if has_blocked else 0)
    else:
        result = validate_skill(target)
        print(json.dumps(result, indent=2))
        sys.exit(1 if result["verdict"] == "blocked" else 0)


if __name__ == "__main__":
    main()
