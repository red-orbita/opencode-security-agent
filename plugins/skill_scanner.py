#!/usr/bin/env python3
"""
OpenCode Security Agent — Deep Skill Scanner (Orchestrator)

Comprehensive pre-installation security scanner for AI agent skills and MCP
servers. Combines all analysis modules into a single pipeline that produces
a unified risk assessment.

Inspired by NVIDIA SkillSpector, but built with our principles:
  - Zero external dependencies (Python stdlib only)
  - Zero LLM cost (pure static analysis)
  - Fast execution (<2s for typical skills)
  - Clear, actionable output

Pipeline stages:
  1. AST Behavioral Analysis (dangerous calls)
  2. Taint Tracking (source→sink data flows)
  3. MCP Least Privilege (permissions vs code)
  4. MCP Tool Poisoning (hidden instructions in metadata)
  5. YARA-like Signatures (malware, webshells, cryptominers)
  6. Agent Ecosystem Signatures (skill manipulation, context poisoning, MCP shadowing)
  7. OSV.dev CVE Lookup (known vulnerable dependencies)
  8. Risk Scoring (0-100 score with multipliers)

Usage:
  python3 plugins/skill_scanner.py <path>              # scan a skill/MCP
  python3 plugins/skill_scanner.py <path> --json       # JSON output
  python3 plugins/skill_scanner.py <path> --sarif      # SARIF output
  python3 plugins/skill_scanner.py <path> --no-network # skip OSV.dev lookup
  python3 plugins/skill_scanner.py <path> --quick      # AST + YARA only (fastest)

Exit codes:
  0  SAFE (score 0-20)
  1  Issues found (score 21+)
  2  Configuration/usage error

Protocol: outputs JSON on stdout (or formatted text to stderr + JSON to stdout).
"""

__version__ = "1.0.0"

import json
import os
import sys
import time
from pathlib import Path
from typing import List, Dict, Any, Optional

# Add lib/ to path for scanner imports
_LIB_DIR = Path(__file__).parent.parent / "lib"
if str(_LIB_DIR) not in sys.path:
    sys.path.insert(0, str(_LIB_DIR))

from scanners.ast_analyzer import analyze_file as ast_analyze_file
from scanners.ast_analyzer import analyze_directory as ast_analyze_dir
from scanners.taint_tracker import analyze_file as taint_analyze_file
from scanners.taint_tracker import analyze_directory as taint_analyze_dir
from scanners.mcp_privilege import analyze_mcp_permissions
from scanners.mcp_poisoning import analyze_directory as poison_analyze_dir
from scanners.mcp_poisoning import analyze_skill_file as poison_analyze_file
from scanners.agent_signatures import analyze_file as agent_analyze_file
from scanners.agent_signatures import analyze_directory as agent_analyze_dir
from scanners.osv_checker import check_dependencies
from scanners.yara_patterns import analyze_file as yara_analyze_file
from scanners.yara_patterns import analyze_directory as yara_analyze_dir
from scanners.risk_scorer import calculate_score, format_score_report


# ---------------------------------------------------------------------------
# Component discovery
# ---------------------------------------------------------------------------

_EXECUTABLE_EXTENSIONS = {".py", ".js", ".ts", ".sh", ".bash", ".rb", ".pl"}
_SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".sh", ".bash", ".rb", ".pl",
    ".md", ".yaml", ".yml", ".json", ".toml", ".txt",
    ".php", ".ps1", ".bat", ".cmd", ".vbs",
}


def discover_components(target: Path) -> Dict[str, Any]:
    """Discover all scannable components in the target."""
    components = {
        "files": [],
        "has_executables": False,
        "total_lines": 0,
        "python_files": [],
        "config_files": [],
    }

    if target.is_file():
        all_files = [target]
    elif target.is_dir():
        all_files = [
            f for f in target.rglob("*")
            if f.is_file()
            and f.suffix in _SCANNABLE_EXTENSIONS
            and "node_modules" not in str(f)
            and ".git" not in str(f)
            and "__pycache__" not in str(f)
        ]
    else:
        return components

    for f in all_files:
        is_executable = f.suffix in _EXECUTABLE_EXTENSIONS or os.access(f, os.X_OK)
        try:
            line_count = len(f.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            line_count = 0

        components["files"].append({
            "path": str(f),
            "name": f.name,
            "type": f.suffix.lstrip(".") or "unknown",
            "lines": line_count,
            "executable": is_executable,
        })

        if is_executable:
            components["has_executables"] = True
        components["total_lines"] += line_count

        if f.suffix == ".py":
            components["python_files"].append(f)
        if f.suffix in (".json", ".yaml", ".yml", ".toml"):
            components["config_files"].append(f)

    return components


# ---------------------------------------------------------------------------
# Scanner pipeline
# ---------------------------------------------------------------------------

def run_scan(
    target: Path,
    use_network: bool = True,
    quick_mode: bool = False,
) -> Dict[str, Any]:
    """
    Run the full scan pipeline on a target.

    Args:
        target: Path to skill directory or file
        use_network: Whether to query OSV.dev (default True)
        quick_mode: Only run AST + YARA (fastest mode)

    Returns:
        Complete scan result dict
    """
    start_time = time.time()
    findings: List[Dict[str, Any]] = []
    analyzers_run = []

    # Discover components
    components = discover_components(target)

    # --- Stage 1: AST Behavioral Analysis ---
    if target.is_dir():
        ast_findings = ast_analyze_dir(target)
    elif target.suffix == ".py":
        ast_findings = ast_analyze_file(target)
    else:
        ast_findings = []
    findings.extend(ast_findings)
    analyzers_run.append(("ast_behavioral", len(ast_findings)))

    # --- Stage 2: YARA-like Signatures ---
    if target.is_dir():
        yara_findings = yara_analyze_dir(target)
    elif target.is_file():
        yara_findings = yara_analyze_file(target)
    else:
        yara_findings = []
    findings.extend(yara_findings)
    analyzers_run.append(("yara_patterns", len(yara_findings)))

    if quick_mode:
        # Skip remaining stages in quick mode
        elapsed = time.time() - start_time
        score_result = calculate_score(findings, components["has_executables"])
        return _build_result(
            target, findings, components, score_result,
            analyzers_run, elapsed, quick_mode=True,
        )

    # --- Stage 3: Taint Tracking ---
    if target.is_dir():
        taint_findings = taint_analyze_dir(target)
    elif target.suffix == ".py":
        taint_findings = taint_analyze_file(target)
    else:
        taint_findings = []
    findings.extend(taint_findings)
    analyzers_run.append(("taint_tracker", len(taint_findings)))

    # --- Stage 4: MCP Least Privilege ---
    mcp_findings = analyze_mcp_permissions(target)
    findings.extend(mcp_findings)
    analyzers_run.append(("mcp_privilege", len(mcp_findings)))

    # --- Stage 5: MCP Tool Poisoning ---
    if target.is_dir():
        poison_findings = poison_analyze_dir(target)
    elif target.is_file():
        poison_findings = poison_analyze_file(target)
    else:
        poison_findings = []
    findings.extend(poison_findings)
    analyzers_run.append(("mcp_poisoning", len(poison_findings)))

    # --- Stage 6: Agent Ecosystem Signatures ---
    if target.is_dir():
        agent_findings = agent_analyze_dir(target)
    elif target.is_file():
        agent_findings = agent_analyze_file(target)
    else:
        agent_findings = []
    findings.extend(agent_findings)
    analyzers_run.append(("agent_signatures", len(agent_findings)))

    # --- Stage 7: OSV.dev CVE Lookup ---
    if use_network and target.is_dir():
        osv_findings = check_dependencies(target, offline=False)
    elif target.is_dir():
        osv_findings = check_dependencies(target, offline=True)
    else:
        osv_findings = []
    findings.extend(osv_findings)
    analyzers_run.append(("osv_checker", len(osv_findings)))

    # --- Stage 7: Risk Scoring ---
    elapsed = time.time() - start_time
    score_result = calculate_score(findings, components["has_executables"])

    return _build_result(
        target, findings, components, score_result,
        analyzers_run, elapsed,
    )


def _build_result(
    target: Path,
    findings: List[Dict[str, Any]],
    components: Dict[str, Any],
    score_result: Dict[str, Any],
    analyzers_run: List[tuple],
    elapsed: float,
    quick_mode: bool = False,
) -> Dict[str, Any]:
    """Build the final result dict."""
    return {
        "version": __version__,
        "target": str(target),
        "scan_time": round(elapsed, 3),
        "quick_mode": quick_mode,
        "components": {
            "total_files": len(components["files"]),
            "total_lines": components["total_lines"],
            "has_executables": components["has_executables"],
            "files": components["files"],
        },
        "risk_score": score_result["score"],
        "risk_severity": score_result["severity"],
        "risk_recommendation": score_result["recommendation"],
        "score_details": score_result,
        "findings": findings,
        "finding_count": len(findings),
        "analyzers": [
            {"name": name, "findings": count}
            for name, count in analyzers_run
        ],
    }


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def format_terminal(result: Dict[str, Any]) -> str:
    """Format result for terminal display."""
    lines = []
    lines.append("")
    lines.append("=" * 60)
    lines.append("  OpenCode Security Agent — Deep Skill Scanner v" + __version__)
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"  Target: {result['target']}")
    lines.append(f"  Scan time: {result['scan_time']}s")
    if result["quick_mode"]:
        lines.append(f"  Mode: QUICK (AST + YARA only)")
    lines.append("")
    lines.append("  --- Risk Assessment ---")
    lines.append(format_score_report(result["score_details"]))
    lines.append("")

    # Components
    lines.append(f"  --- Components ({result['components']['total_files']}) ---")
    for comp in result["components"]["files"][:20]:
        exec_marker = " [EXEC]" if comp["executable"] else ""
        lines.append(f"    {comp['name']:30s} {comp['type']:10s} {comp['lines']:>5d} lines{exec_marker}")
    if result["components"]["total_files"] > 20:
        lines.append(f"    ... and {result['components']['total_files'] - 20} more files")
    lines.append("")

    # Findings
    if result["findings"]:
        lines.append(f"  --- Findings ({result['finding_count']}) ---")
        lines.append("")
        for f in sorted(result["findings"],
                        key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
                            x.get("severity", "low"), 4)):
            sev = f.get("severity", "unknown").upper()
            rule = f.get("rule_id", "?")
            msg = f.get("message", "")
            line = f.get("line", 0)
            file_path = f.get("file", "")
            file_name = Path(file_path).name if file_path else ""
            confidence = f.get("confidence", 0)

            lines.append(f"  [{sev}] {rule}: {msg}")
            if file_name and line:
                lines.append(f"         Location: {file_name}:{line}")
            if f.get("code"):
                lines.append(f"         Code: {f['code'][:80]}")
            lines.append(f"         Confidence: {confidence}%")
            lines.append("")
    else:
        lines.append("  No issues found.")
        lines.append("")

    # Analyzers summary
    lines.append("  --- Analyzers ---")
    for a in result["analyzers"]:
        status = f"{a['findings']} finding(s)" if a["findings"] else "clean"
        lines.append(f"    {a['name']:25s} {status}")
    lines.append("")
    lines.append("=" * 60)

    return "\n".join(lines)


def format_sarif(result: Dict[str, Any]) -> Dict[str, Any]:
    """Format result as SARIF 2.1.0 for CI/CD integration."""
    rules = {}
    sarif_results = []

    for f in result["findings"]:
        rule_id = f.get("rule_id", "UNKNOWN")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": f.get("message", "")[:100]},
                "defaultConfiguration": {
                    "level": _sarif_level(f.get("severity", "medium")),
                },
            }

        sarif_result = {
            "ruleId": rule_id,
            "level": _sarif_level(f.get("severity", "medium")),
            "message": {"text": f.get("message", "")},
            "locations": [],
        }

        if f.get("file"):
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                }
            }
            if f.get("line", 0) > 0:
                location["physicalLocation"]["region"] = {
                    "startLine": f["line"],
                }
            sarif_result["locations"].append(location)

        sarif_results.append(sarif_result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "OpenCode Security Agent - Deep Scanner",
                    "version": __version__,
                    "informationUri": "https://github.com/red-orbita/opencode-security-agent",
                    "rules": list(rules.values()),
                }
            },
            "results": sarif_results,
        }],
    }


def _sarif_level(severity: str) -> str:
    """Convert severity to SARIF level."""
    mapping = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    return mapping.get(severity.lower(), "warning")


# ---------------------------------------------------------------------------
# CLI interface
# ---------------------------------------------------------------------------

def main():
    if "--version" in sys.argv:
        print(f"skill_scanner {__version__}")
        sys.exit(0)

    if "--help" in sys.argv or "-h" in sys.argv:
        print(__doc__)
        sys.exit(0)

    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a.lstrip("-") for a in sys.argv[1:] if a.startswith("--")}

    if not args:
        print("Usage: python3 skill_scanner.py <path> [options]", file=sys.stderr)
        print("Options: --json, --sarif, --no-network, --quick", file=sys.stderr)
        sys.exit(2)

    target = Path(args[0])
    if not target.exists():
        print(f"Error: {target} not found", file=sys.stderr)
        sys.exit(2)

    use_network = "no-network" not in flags
    quick_mode = "quick" in flags
    output_json = "json" in flags
    output_sarif = "sarif" in flags

    # Run scan
    result = run_scan(target, use_network=use_network, quick_mode=quick_mode)

    # Output
    if output_sarif:
        sarif = format_sarif(result)
        print(json.dumps(sarif, indent=2))
    elif output_json:
        print(json.dumps(result, indent=2))
    else:
        # Terminal output to stderr, JSON to stdout
        terminal_output = format_terminal(result)
        print(terminal_output, file=sys.stderr)
        print(json.dumps({
            "risk_score": result["risk_score"],
            "risk_severity": result["risk_severity"],
            "risk_recommendation": result["risk_recommendation"],
            "finding_count": result["finding_count"],
            "scan_time": result["scan_time"],
        }))

    # Exit code based on score
    sys.exit(1 if result["risk_score"] > 20 else 0)


if __name__ == "__main__":
    main()
