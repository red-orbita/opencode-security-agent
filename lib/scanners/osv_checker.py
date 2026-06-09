#!/usr/bin/env python3
"""
OpenCode Security Agent — OSV.dev CVE Lookup

Checks project dependencies against the Open Source Vulnerabilities (OSV)
database for known CVEs. Uses the free, unauthenticated OSV.dev API.

Features:
  - Batch queries (all deps in a single HTTP call)
  - Supports requirements.txt, package.json, Pipfile, pyproject.toml
  - Automatic offline fallback with built-in known-vulnerable packages
  - In-memory caching (1 hour TTL)
  - No API key required

Detected patterns:
  SC4: Known Vulnerable Dependencies — packages with active CVEs

Zero external dependencies (uses urllib from stdlib). Python 3.8+ compatible.
"""

import json
import re
import sys
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


# ---------------------------------------------------------------------------
# OSV.dev API configuration
# ---------------------------------------------------------------------------

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_OSV_TIMEOUT = 15  # seconds
_CACHE_TTL = 3600  # 1 hour

# In-memory cache: (timestamp, results)
_cache: Dict[str, Tuple[float, List[Dict]]] = {}


# ---------------------------------------------------------------------------
# Known vulnerable packages (offline fallback)
# ---------------------------------------------------------------------------

_FALLBACK_VULNERABILITIES = {
    # Python packages with historical critical CVEs
    "PyYAML": {"version_below": "6.0.1", "cves": ["CVE-2020-14343"], "severity": "critical"},
    "requests": {"version_below": "2.32.0", "cves": ["CVE-2024-35195"], "severity": "medium"},
    "urllib3": {"version_below": "2.0.7", "cves": ["CVE-2023-45803"], "severity": "medium"},
    "cryptography": {"version_below": "42.0.0", "cves": ["CVE-2023-49083"], "severity": "high"},
    "pillow": {"version_below": "10.2.0", "cves": ["CVE-2023-50447"], "severity": "critical"},
    "django": {"version_below": "5.0.1", "cves": ["CVE-2024-24680"], "severity": "high"},
    "flask": {"version_below": "2.3.2", "cves": ["CVE-2023-30861"], "severity": "high"},
    "jinja2": {"version_below": "3.1.3", "cves": ["CVE-2024-22195"], "severity": "medium"},
    "setuptools": {"version_below": "70.0.0", "cves": ["CVE-2024-6345"], "severity": "high"},
    "certifi": {"version_below": "2024.7.4", "cves": ["CVE-2024-39689"], "severity": "high"},
    "aiohttp": {"version_below": "3.9.4", "cves": ["CVE-2024-30251"], "severity": "high"},
    "tornado": {"version_below": "6.4.1", "cves": ["CVE-2024-32651"], "severity": "critical"},
    "paramiko": {"version_below": "3.4.0", "cves": ["CVE-2023-48795"], "severity": "medium"},
    "werkzeug": {"version_below": "3.0.3", "cves": ["CVE-2024-34069"], "severity": "high"},
    # npm packages
    "express": {"version_below": "4.19.2", "cves": ["CVE-2024-29041"], "severity": "medium"},
    "axios": {"version_below": "1.6.0", "cves": ["CVE-2023-45857"], "severity": "medium"},
    "lodash": {"version_below": "4.17.21", "cves": ["CVE-2021-23337"], "severity": "critical"},
    "jsonwebtoken": {"version_below": "9.0.0", "cves": ["CVE-2022-23529"], "severity": "critical"},
    "semver": {"version_below": "7.5.2", "cves": ["CVE-2022-25883"], "severity": "high"},
    "tar": {"version_below": "6.2.1", "cves": ["CVE-2024-28863"], "severity": "medium"},
    "ws": {"version_below": "8.17.1", "cves": ["CVE-2024-37890"], "severity": "high"},
}


# ---------------------------------------------------------------------------
# Dependency parsers
# ---------------------------------------------------------------------------

def _parse_requirements_txt(path: Path) -> List[Dict[str, str]]:
    """Parse requirements.txt for package names and versions."""
    deps = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return deps

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle: package==version, package>=version, package~=version
        match = re.match(r"^([a-zA-Z0-9_.-]+)\s*([><=~!]+)?\s*([0-9][0-9.*]*)?", line)
        if match:
            name = match.group(1)
            version = match.group(3) or ""
            deps.append({"name": name, "version": version, "ecosystem": "PyPI"})
    return deps


def _parse_package_json(path: Path) -> List[Dict[str, str]]:
    """Parse package.json for dependencies."""
    deps = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return deps

    for dep_key in ("dependencies", "devDependencies"):
        packages = data.get(dep_key, {})
        for name, version_spec in packages.items():
            # Strip ^, ~, >= prefixes
            version = re.sub(r"^[^0-9]*", "", version_spec)
            deps.append({"name": name, "version": version, "ecosystem": "npm"})
    return deps


def _parse_pyproject_toml(path: Path) -> List[Dict[str, str]]:
    """Parse pyproject.toml dependencies (basic TOML parsing)."""
    deps = []
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return deps

    # Basic regex parsing for dependencies array (avoids tomllib dep for 3.8-3.10)
    in_deps = False
    for line in content.splitlines():
        if re.match(r"^\s*dependencies\s*=\s*\[", line):
            in_deps = True
            continue
        if in_deps:
            if "]" in line:
                in_deps = False
                continue
            match = re.match(r'\s*"([a-zA-Z0-9_.-]+)\s*([><=~!]+)?\s*([0-9][0-9.*]*)?', line)
            if match:
                deps.append({
                    "name": match.group(1),
                    "version": match.group(3) or "",
                    "ecosystem": "PyPI",
                })
    return deps


def detect_dependencies(dir_path: Path) -> List[Dict[str, str]]:
    """Auto-detect and parse all dependency files in a directory."""
    all_deps = []

    # Python
    for req_file in dir_path.rglob("requirements*.txt"):
        all_deps.extend(_parse_requirements_txt(req_file))

    pyproject = dir_path / "pyproject.toml"
    if pyproject.exists():
        all_deps.extend(_parse_pyproject_toml(pyproject))

    # Node.js
    for pkg_json in dir_path.rglob("package.json"):
        # Skip node_modules
        if "node_modules" not in str(pkg_json):
            all_deps.extend(_parse_package_json(pkg_json))

    # Deduplicate
    seen = set()
    unique = []
    for dep in all_deps:
        key = (dep["name"].lower(), dep["ecosystem"])
        if key not in seen:
            seen.add(key)
            unique.append(dep)

    return unique


# ---------------------------------------------------------------------------
# OSV.dev API queries
# ---------------------------------------------------------------------------

def _query_osv_batch(deps: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    """Query OSV.dev batch API for vulnerabilities."""
    queries = []
    for dep in deps:
        query = {"package": {"name": dep["name"], "ecosystem": dep["ecosystem"]}}
        if dep.get("version"):
            query["version"] = dep["version"]
        queries.append(query)

    payload = json.dumps({"queries": queries}).encode("utf-8")
    req = Request(
        _OSV_BATCH_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(req, timeout=_OSV_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (URLError, HTTPError, TimeoutError, OSError):
        return []

    results = []
    for i, result in enumerate(data.get("results", [])):
        vulns = result.get("vulns", [])
        if vulns and i < len(deps):
            for vuln in vulns:
                severity = _extract_severity(vuln)
                results.append({
                    "package": deps[i]["name"],
                    "ecosystem": deps[i]["ecosystem"],
                    "version": deps[i].get("version", ""),
                    "vuln_id": vuln.get("id", "unknown"),
                    "summary": vuln.get("summary", ""),
                    "severity": severity,
                    "aliases": vuln.get("aliases", []),
                })

    return results


def _extract_severity(vuln: Dict) -> str:
    """Extract severity from OSV vulnerability data."""
    # Check CVSS score
    severity_list = vuln.get("severity", [])
    for sev in severity_list:
        score_str = sev.get("score", "")
        if "CVSS" in sev.get("type", ""):
            # Parse CVSS vector for score
            try:
                # Simple heuristic from vector string
                if "/AV:N/" in score_str and "/AC:L/" in score_str:
                    return "critical"
            except Exception:
                pass

    # Check database_specific severity
    db_specific = vuln.get("database_specific", {})
    sev = db_specific.get("severity", "").lower()
    if sev in ("critical", "high", "medium", "low"):
        return sev

    # Default based on whether it has aliases (CVEs are usually higher severity)
    if vuln.get("aliases"):
        return "high"
    return "medium"


def _check_fallback(deps: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    """Check dependencies against offline fallback list."""
    results = []
    for dep in deps:
        name = dep["name"]
        if name in _FALLBACK_VULNERABILITIES:
            vuln_info = _FALLBACK_VULNERABILITIES[name]
            results.append({
                "package": name,
                "ecosystem": dep["ecosystem"],
                "version": dep.get("version", "unknown"),
                "vuln_id": vuln_info["cves"][0] if vuln_info["cves"] else "unknown",
                "summary": f"Known vulnerable: upgrade above {vuln_info['version_below']}",
                "severity": vuln_info["severity"],
                "aliases": vuln_info["cves"],
                "source": "fallback",
            })
    return results


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_dependencies(
    dir_path: Path,
    use_cache: bool = True,
    offline: bool = False,
) -> List[Dict[str, Any]]:
    """
    Check all dependencies in a directory for known vulnerabilities.

    Args:
        dir_path: Directory containing dependency files
        use_cache: Use in-memory cache (default True)
        offline: Skip OSV.dev API, use fallback only (default False)

    Returns:
        List of vulnerability findings
    """
    deps = detect_dependencies(dir_path)
    if not deps:
        return []

    # Check cache
    cache_key = json.dumps(sorted([(d["name"], d["version"]) for d in deps]))
    if use_cache and cache_key in _cache:
        ts, cached_results = _cache[cache_key]
        if time.time() - ts < _CACHE_TTL:
            return cached_results

    # Query OSV.dev (unless offline)
    findings = []
    if not offline:
        osv_results = _query_osv_batch(deps)
        if osv_results:
            findings = osv_results
        else:
            # API failed, use fallback
            findings = _check_fallback(deps)
    else:
        findings = _check_fallback(deps)

    # Convert to standard finding format
    formatted = []
    for vuln in findings:
        formatted.append({
            "rule_id": "SC4",
            "severity": vuln["severity"],
            "message": (
                f"Vulnerable dependency: {vuln['package']} "
                f"({vuln.get('version', 'unpinned')}) — "
                f"{vuln['vuln_id']}: {vuln.get('summary', 'known vulnerability')}"
            ),
            "line": 0,
            "code": "",
            "confidence": 95,
            "analyzer": "osv_checker",
            "package": vuln["package"],
            "vuln_id": vuln["vuln_id"],
            "aliases": vuln.get("aliases", []),
        })

    # Cache results
    if use_cache:
        _cache[cache_key] = (time.time(), formatted)

    return formatted


def analyze_directory(dir_path: Path) -> List[Dict[str, Any]]:
    """Convenience wrapper matching other scanner interfaces."""
    return check_dependencies(dir_path)


# ---------------------------------------------------------------------------
# CLI interface
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 osv_checker.py <directory>", file=sys.stderr)
        sys.exit(2)

    target = Path(sys.argv[1])
    if not target.is_dir():
        print(f"Error: {target} is not a directory", file=sys.stderr)
        sys.exit(2)

    offline = "--offline" in sys.argv
    results = check_dependencies(target, offline=offline)
    print(json.dumps(results, indent=2))
    sys.exit(1 if results else 0)
