#!/usr/bin/env python3
"""
OpenCode Security Agent — MCP Least Privilege Analysis

Validates that MCP server/tool declarations match their actual code behavior.
Detects over-permissioned tools that request more access than needed, and
under-declared tools that use capabilities without declaring them.

Detected patterns (inspired by NVIDIA SkillSpector):
  LP1: Underdeclared Capability — code uses capabilities not in permissions
  LP2: Wildcard Permission — permission list contains wildcards
  LP3: Missing Permission Declaration — no permissions but code has capabilities
  LP4: Overdeclared Permission — permission declared but no matching code

Zero external dependencies. Python 3.8+ compatible.
"""

import ast
import json
import re
import sys
from pathlib import Path
from typing import List, Dict, Any, Set, Optional


# ---------------------------------------------------------------------------
# Capability detection: what code actually does
# ---------------------------------------------------------------------------

# Map of code patterns to capability categories
_CAPABILITY_PATTERNS = {
    "filesystem_read": {
        "calls": {"open", "pathlib.Path.read_text", "pathlib.Path.read_bytes",
                  "os.listdir", "os.scandir", "os.walk", "glob.glob",
                  "pathlib.Path.glob", "pathlib.Path.iterdir"},
        "regex": [
            re.compile(r"open\s*\(.+['\"]r['\"]", re.MULTILINE),
            re.compile(r"\.read_text\(\)", re.MULTILINE),
            re.compile(r"\.read_bytes\(\)", re.MULTILINE),
            re.compile(r"os\.(listdir|scandir|walk)\(", re.MULTILINE),
        ],
    },
    "filesystem_write": {
        "calls": {"pathlib.Path.write_text", "pathlib.Path.write_bytes",
                  "os.makedirs", "os.mkdir", "os.rename", "os.remove",
                  "shutil.copy", "shutil.move", "shutil.rmtree"},
        "regex": [
            re.compile(r"open\s*\(.+['\"][wa]['\"]", re.MULTILINE),
            re.compile(r"\.write_text\(", re.MULTILINE),
            re.compile(r"\.write_bytes\(", re.MULTILINE),
            re.compile(r"shutil\.(copy|move|rmtree)\(", re.MULTILINE),
        ],
    },
    "network": {
        "calls": {"urllib.request.urlopen", "requests.get", "requests.post",
                  "requests.put", "requests.delete", "requests.patch",
                  "http.client.HTTPConnection", "http.client.HTTPSConnection",
                  "socket.socket", "aiohttp.ClientSession"},
        "regex": [
            re.compile(r"requests\.(get|post|put|delete|patch)\(", re.MULTILINE),
            re.compile(r"urllib\.request\.urlopen\(", re.MULTILINE),
            re.compile(r"aiohttp\.ClientSession\(", re.MULTILINE),
            re.compile(r"httpx\.(get|post|put|AsyncClient)\(", re.MULTILINE),
        ],
    },
    "subprocess": {
        "calls": {"subprocess.run", "subprocess.call", "subprocess.Popen",
                  "subprocess.check_call", "subprocess.check_output",
                  "os.system", "os.popen"},
        "regex": [
            re.compile(r"subprocess\.(run|call|Popen|check_call|check_output)\(", re.MULTILINE),
            re.compile(r"os\.(system|popen)\(", re.MULTILINE),
        ],
    },
    "environment": {
        "calls": {"os.environ.get", "os.getenv", "os.environ.__getitem__"},
        "regex": [
            re.compile(r"os\.(environ|getenv)", re.MULTILINE),
        ],
    },
    "database": {
        "calls": {"sqlite3.connect", "psycopg2.connect", "mysql.connector.connect"},
        "regex": [
            re.compile(r"(sqlite3|psycopg2|mysql|pymongo|redis)\.(connect|Connection)\(", re.MULTILINE),
            re.compile(r"sqlalchemy\.create_engine\(", re.MULTILINE),
        ],
    },
    "crypto": {
        "calls": set(),
        "regex": [
            re.compile(r"(cryptography|Crypto|hashlib|hmac)\.", re.MULTILINE),
            re.compile(r"from\s+(cryptography|Crypto)", re.MULTILINE),
        ],
    },
}

# Wildcard permission indicators
_WILDCARD_INDICATORS = {"*", "all", "full", "any", "unrestricted", "admin"}


def _detect_code_capabilities(source: str) -> Set[str]:
    """Detect actual capabilities used in source code."""
    capabilities = set()
    for cap_name, patterns in _CAPABILITY_PATTERNS.items():
        for regex in patterns["regex"]:
            if regex.search(source):
                capabilities.add(cap_name)
                break
    return capabilities


def _extract_declared_permissions(metadata: Dict[str, Any]) -> Set[str]:
    """Extract declared permissions from MCP metadata."""
    permissions = set()

    # Common permission declaration locations
    perm_keys = ["permissions", "capabilities", "scopes", "access"]
    for key in perm_keys:
        value = metadata.get(key, None)
        if value is None:
            continue
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    permissions.add(item.lower())
                elif isinstance(item, dict):
                    permissions.add(item.get("name", "").lower())
        elif isinstance(value, dict):
            for k, v in value.items():
                if v:
                    permissions.add(k.lower())
        elif isinstance(value, str):
            permissions.add(value.lower())

    return permissions


def _normalize_permission(perm: str) -> Set[str]:
    """Normalize a permission string to capability categories."""
    mapping = {
        "read": {"filesystem_read"},
        "write": {"filesystem_write"},
        "file": {"filesystem_read", "filesystem_write"},
        "filesystem": {"filesystem_read", "filesystem_write"},
        "fs": {"filesystem_read", "filesystem_write"},
        "network": {"network"},
        "net": {"network"},
        "http": {"network"},
        "fetch": {"network"},
        "exec": {"subprocess"},
        "execute": {"subprocess"},
        "shell": {"subprocess"},
        "subprocess": {"subprocess"},
        "command": {"subprocess"},
        "env": {"environment"},
        "environment": {"environment"},
        "db": {"database"},
        "database": {"database"},
        "sql": {"database"},
        "crypto": {"crypto"},
    }

    normalized = set()
    perm_lower = perm.lower().strip()
    for keyword, caps in mapping.items():
        if keyword in perm_lower:
            normalized.update(caps)

    return normalized


def analyze_mcp_permissions(
    code_path: Path,
    metadata_path: Optional[Path] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Analyze MCP server permissions vs actual code capabilities.

    Args:
        code_path: Path to code directory or file
        metadata_path: Path to MCP manifest/config (JSON/YAML)
        metadata: Pre-parsed metadata dict (alternative to metadata_path)

    Returns:
        List of findings
    """
    findings = []

    # Gather all source code
    if code_path.is_file():
        sources = [code_path.read_text(encoding="utf-8", errors="replace")]
        py_files = [code_path]
    elif code_path.is_dir():
        py_files = list(code_path.rglob("*.py"))
        js_files = list(code_path.rglob("*.js")) + list(code_path.rglob("*.ts"))
        all_files = py_files + js_files
        sources = []
        for f in all_files:
            try:
                sources.append(f.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
    else:
        return []

    combined_source = "\n".join(sources)
    actual_capabilities = _detect_code_capabilities(combined_source)

    # Load metadata if path provided
    if metadata is None and metadata_path:
        try:
            raw = metadata_path.read_text(encoding="utf-8")
            metadata = json.loads(raw)
        except (OSError, json.JSONDecodeError):
            metadata = {}

    if metadata is None:
        metadata = {}

    # Auto-detect metadata from common MCP manifest locations
    if not metadata and code_path.is_dir():
        for manifest_name in ["mcp.json", "manifest.json", "package.json",
                              "tool.json", "server.json"]:
            manifest = code_path / manifest_name
            if manifest.exists():
                try:
                    metadata = json.loads(manifest.read_text())
                    break
                except (OSError, json.JSONDecodeError):
                    continue

    declared_permissions = _extract_declared_permissions(metadata)

    # LP3: No permissions declared but code has capabilities
    if not declared_permissions and actual_capabilities:
        findings.append({
            "rule_id": "LP3",
            "severity": "medium",
            "message": (
                f"No permissions declared but code uses: "
                f"{', '.join(sorted(actual_capabilities))}"
            ),
            "line": 0,
            "code": "",
            "confidence": 75,
            "analyzer": "mcp_privilege",
            "file": str(code_path),
            "capabilities_detected": sorted(actual_capabilities),
        })
        return findings

    # LP2: Wildcard permissions
    for perm in declared_permissions:
        if perm in _WILDCARD_INDICATORS:
            findings.append({
                "rule_id": "LP2",
                "severity": "medium",
                "message": f"Wildcard permission declared: '{perm}'",
                "line": 0,
                "code": "",
                "confidence": 90,
                "analyzer": "mcp_privilege",
                "file": str(metadata_path or code_path),
            })

    # Normalize declared permissions to capability categories
    declared_capabilities = set()
    for perm in declared_permissions:
        if perm not in _WILDCARD_INDICATORS:
            declared_capabilities.update(_normalize_permission(perm))

    # LP1: Underdeclared — code uses capability not in permissions
    if declared_permissions:  # Only check if permissions exist
        underdeclared = actual_capabilities - declared_capabilities
        for cap in underdeclared:
            findings.append({
                "rule_id": "LP1",
                "severity": "high",
                "message": (
                    f"Code uses '{cap}' capability not declared in permissions"
                ),
                "line": 0,
                "code": "",
                "confidence": 80,
                "analyzer": "mcp_privilege",
                "file": str(code_path),
            })

    # LP4: Overdeclared — permission declared but no matching code
    if declared_capabilities and actual_capabilities:
        overdeclared = declared_capabilities - actual_capabilities
        for cap in overdeclared:
            findings.append({
                "rule_id": "LP4",
                "severity": "low",
                "message": (
                    f"Permission '{cap}' declared but no matching code found"
                ),
                "line": 0,
                "code": "",
                "confidence": 60,
                "analyzer": "mcp_privilege",
                "file": str(metadata_path or code_path),
            })

    return findings


def analyze_directory(dir_path: Path) -> List[Dict[str, Any]]:
    """Convenience wrapper for directory analysis."""
    return analyze_mcp_permissions(dir_path)


# ---------------------------------------------------------------------------
# CLI interface
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 mcp_privilege.py <code-path> [metadata-path]",
              file=sys.stderr)
        sys.exit(2)

    code_path = Path(sys.argv[1])
    metadata_path = Path(sys.argv[2]) if len(sys.argv) > 2 else None

    results = analyze_mcp_permissions(code_path, metadata_path)
    print(json.dumps(results, indent=2))
    sys.exit(1 if results else 0)
