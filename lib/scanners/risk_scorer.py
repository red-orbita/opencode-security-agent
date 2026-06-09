#!/usr/bin/env python3
"""
OpenCode Security Agent — Risk Scoring Engine

Calculates a formal 0-100 risk score based on security findings, with
severity-based weighting and contextual multipliers.

Scoring algorithm (inspired by NVIDIA SkillSpector):
  - CRITICAL findings: +50 points each (capped contribution)
  - HIGH findings: +25 points each
  - MEDIUM findings: +10 points each
  - LOW findings: +5 points each

Multipliers:
  - Executable scripts present: 1.3x
  - Network capability + credential access: 1.5x (exfiltration combo)
  - Multiple analyzers flagged same file: 1.2x
  - No permissions declared: 1.1x

Final score is clamped to [0, 100].

Severity labels:
  0-20:   LOW       → SAFE
  21-50:  MEDIUM    → CAUTION
  51-80:  HIGH      → DO NOT INSTALL
  81-100: CRITICAL  → DO NOT INSTALL

Zero external dependencies. Python 3.8+ compatible.
"""

import sys
from typing import List, Dict, Any, Tuple


# ---------------------------------------------------------------------------
# Scoring weights
# ---------------------------------------------------------------------------

_SEVERITY_POINTS = {
    "critical": 50,
    "high": 25,
    "medium": 10,
    "low": 5,
}

_SEVERITY_CAPS = {
    "critical": 100,  # Max contribution from critical findings
    "high": 75,       # Max contribution from high findings
    "medium": 40,     # Max contribution from medium findings
    "low": 20,        # Max contribution from low findings
}

_SEVERITY_LABELS = [
    (0, 20, "LOW", "SAFE"),
    (21, 50, "MEDIUM", "CAUTION"),
    (51, 80, "HIGH", "DO NOT INSTALL"),
    (81, 100, "CRITICAL", "DO NOT INSTALL"),
]


# ---------------------------------------------------------------------------
# Multiplier detection
# ---------------------------------------------------------------------------

def _detect_multipliers(findings: List[Dict[str, Any]],
                        has_executables: bool = False) -> List[Tuple[str, float]]:
    """Detect contextual risk multipliers from findings."""
    multipliers = []

    # 1. Executable scripts present
    if has_executables:
        multipliers.append(("executable_scripts", 1.3))

    # 2. Exfiltration combo: network + credential access
    has_network = any(
        f.get("rule_id", "").startswith(("E1", "TT4", "TT3")) or
        "network" in f.get("message", "").lower()
        for f in findings
    )
    has_creds = any(
        f.get("rule_id", "").startswith(("E2", "PE3", "TT3")) or
        "credential" in f.get("message", "").lower() or
        "environ" in f.get("message", "").lower()
        for f in findings
    )
    if has_network and has_creds:
        multipliers.append(("exfiltration_combo", 1.5))

    # 3. Multiple analyzers flagged same file
    files_by_analyzer: Dict[str, set] = {}
    for f in findings:
        analyzer = f.get("analyzer", "unknown")
        file_path = f.get("file", "")
        if file_path:
            files_by_analyzer.setdefault(file_path, set()).add(analyzer)

    multi_flagged = sum(1 for analyzers in files_by_analyzer.values()
                        if len(analyzers) >= 2)
    if multi_flagged > 0:
        multipliers.append(("cross_analyzer_correlation", 1.2))

    # 4. No permissions declared (LP3)
    if any(f.get("rule_id") == "LP3" for f in findings):
        multipliers.append(("no_permissions_declared", 1.1))

    # 5. Dangerous execution chain (AST8)
    if any(f.get("rule_id") == "AST8" for f in findings):
        multipliers.append(("dangerous_chain", 1.3))

    return multipliers


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def calculate_score(
    findings: List[Dict[str, Any]],
    has_executables: bool = False,
) -> Dict[str, Any]:
    """
    Calculate risk score from a list of findings.

    Args:
        findings: List of finding dicts (must have 'severity' key)
        has_executables: Whether the scanned target contains executable files

    Returns:
        Dict with: score, severity, recommendation, breakdown, multipliers
    """
    if not findings:
        return {
            "score": 0,
            "severity": "LOW",
            "recommendation": "SAFE",
            "breakdown": {},
            "multipliers": [],
            "finding_count": 0,
        }

    # Count findings by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Calculate base score with caps
    base_score = 0.0
    breakdown = {}
    for sev, count in severity_counts.items():
        if count > 0:
            raw_points = count * _SEVERITY_POINTS[sev]
            capped_points = min(raw_points, _SEVERITY_CAPS[sev])
            base_score += capped_points
            breakdown[sev] = {
                "count": count,
                "points_per": _SEVERITY_POINTS[sev],
                "raw_total": raw_points,
                "capped_at": _SEVERITY_CAPS[sev],
                "contribution": capped_points,
            }

    # Apply multipliers
    multipliers = _detect_multipliers(findings, has_executables)
    final_score = base_score
    for name, factor in multipliers:
        final_score *= factor

    # Clamp to 0-100
    final_score = max(0, min(100, int(round(final_score))))

    # Determine severity label
    severity_label = "LOW"
    recommendation = "SAFE"
    for low, high, label, rec in _SEVERITY_LABELS:
        if low <= final_score <= high:
            severity_label = label
            recommendation = rec
            break

    return {
        "score": final_score,
        "severity": severity_label,
        "recommendation": recommendation,
        "breakdown": breakdown,
        "multipliers": [(name, factor) for name, factor in multipliers],
        "finding_count": len(findings),
        "base_score": int(round(base_score)),
    }


def format_score_report(score_result: Dict[str, Any]) -> str:
    """Format a score result into a human-readable string."""
    lines = []
    lines.append(f"  Risk Score: {score_result['score']}/100")
    lines.append(f"  Severity:   {score_result['severity']}")
    lines.append(f"  Verdict:    {score_result['recommendation']}")
    lines.append(f"  Findings:   {score_result['finding_count']}")

    if score_result.get("multipliers"):
        lines.append(f"  Multipliers:")
        for name, factor in score_result["multipliers"]:
            lines.append(f"    - {name}: x{factor}")

    if score_result.get("breakdown"):
        lines.append(f"  Breakdown:")
        for sev, info in score_result["breakdown"].items():
            lines.append(
                f"    - {sev.upper()}: {info['count']} finding(s) "
                f"= {info['contribution']} pts"
            )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI interface
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    # Read findings from stdin (JSON array)
    if not sys.stdin.isatty():
        try:
            findings = json.loads(sys.stdin.read())
        except json.JSONDecodeError:
            print("Error: invalid JSON on stdin", file=sys.stderr)
            sys.exit(2)
    else:
        print("Usage: cat findings.json | python3 risk_scorer.py", file=sys.stderr)
        sys.exit(2)

    has_exec = "--executable" in sys.argv
    result = calculate_score(findings, has_executables=has_exec)
    print(json.dumps(result, indent=2))
    sys.exit(0)
