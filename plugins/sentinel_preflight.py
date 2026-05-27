#!/usr/bin/env python3
"""
OpenCode Security Agent -- tool.execute.before hook (Python engine).

Runs before every tool call made by OpenCode. Reads the tool call JSON from stdin,
checks it against bundled IOCs (paths, domains, command patterns, env vars, prompt
injection phrases) and the user's allowlist. Returns an allow / block decision as
JSON on stdout.

Zero LLM cost -- pure local pattern matching. Adds <50ms latency per tool call
in typical cases.

Protocol: The OpenCode plugin passes the tool call payload on stdin and expects
a JSON response on stdout. Exit 0 always; the "decision" field controls behavior.

Decision values:
  "allow"  -- tool call proceeds normally.
  "block"  -- tool call blocked. "reason" is shown to the user.
"""

__version__ = "1.5.0"

import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Structured logging for block/warn decisions (JSON Lines)
# ---------------------------------------------------------------------------
_LOG_DIR_CANDIDATES = [
    Path.home() / ".security" / "logs",
    Path(__file__).parent.parent / "logs",
]

_LOG_ENV_VAR = "SENTINEL_LOG_DIR"


def _get_log_path():
    """Determine the log file path. Returns None if logging is disabled."""
    if os.environ.get("SENTINEL_LOG_DISABLE", "").lower() in ("1", "true", "yes"):
        return None

    # Env var override
    env_dir = os.environ.get(_LOG_ENV_VAR)
    if env_dir:
        log_dir = Path(env_dir)
    else:
        # Use first candidate that exists or can be created
        log_dir = None
        for candidate in _LOG_DIR_CANDIDATES:
            if candidate.exists() or candidate.parent.exists():
                log_dir = candidate
                break
        if log_dir is None:
            return None

    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        return log_dir / "sentinel.jsonl"
    except OSError:
        return None


def _log_decision(tool_name, decision, reason, severity, elapsed_ms, tool_input=None):
    """Append a structured JSON log entry for block/warn decisions.

    Only logs block and warn decisions (allows are not logged to avoid noise).
    Log format: JSON Lines (one JSON object per line), ready for SIEM ingestion.
    """
    if decision == "allow":
        return

    log_path = _get_log_path()
    if log_path is None:
        return

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent": "sentinel_preflight",
        "version": __version__,
        "decision": decision,
        "severity": severity or "unknown",
        "tool_name": tool_name,
        "reason": reason or "",
        "elapsed_ms": elapsed_ms,
    }

    # Include sanitized tool_input summary (truncate large values)
    if tool_input:
        summary = {}
        for k, v in (tool_input if isinstance(tool_input, dict) else {}).items():
            sv = str(v)
            summary[k] = sv[:500] + "..." if len(sv) > 500 else sv
        entry["tool_input_summary"] = summary

    try:
        with open(log_path, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass  # Fail silently -- logging should never break the agent

# ---------------------------------------------------------------------------
# Module-level cache for IOCs and allowlist (mtime-based)
# ---------------------------------------------------------------------------
_cache = {
    "iocs": {"data": None, "path": None, "mtime": 0},
    "allowlist": {"data": None, "path": None, "mtime": 0},
}


def _find_file(candidates):
    """Return the first existing Path from candidates, or None."""
    for path in candidates:
        if path.exists():
            return path
    return None


def _load_cached(cache_key, candidates, default):
    """Load JSON from the first existing candidate, with mtime caching."""
    entry = _cache[cache_key]
    path = _find_file(candidates)
    if path is None:
        entry["data"] = default
        entry["path"] = None
        entry["mtime"] = 0
        return default

    current_mtime = path.stat().st_mtime
    if entry["path"] == path and entry["mtime"] == current_mtime and entry["data"] is not None:
        return entry["data"]

    try:
        raw = path.read_text()
        data = json.loads(raw)
    except Exception:
        data = default

    # Integrity check: if iocs.json has a checksum field, verify it
    if cache_key == "iocs" and isinstance(data, dict) and "checksum_sha256" in data:
        expected = data.pop("checksum_sha256")
        # Recompute checksum without the checksum field itself
        content_for_hash = json.dumps(data, sort_keys=True, separators=(",", ":"))
        actual = hashlib.sha256(content_for_hash.encode()).hexdigest()
        if actual != expected:
            print(
                f"[WARN] iocs.json integrity check failed "
                f"(expected={expected[:16]}... got={actual[:16]}...)",
                file=sys.stderr,
            )
            # Still load the data but log the warning -- fail-open

    entry["data"] = data
    entry["path"] = path
    entry["mtime"] = current_mtime
    return data


def load_iocs():
    """Load the bundled IOCs file. Falls back to empty if missing."""
    candidates = [
        Path(__file__).parent.parent / "references" / "iocs.json",
        Path(__file__).parent / "iocs.json",
        Path.home() / ".config" / "opencode" / "plugins" / "iocs.json",
        Path.home() / ".config" / "opencode" / "skills" / "security-agent" / "references" / "iocs.json",
        Path.cwd() / ".opencode" / "plugins" / "iocs.json",
    ]
    return _load_cached("iocs", candidates, {})


def load_user_allowlist():
    """Load user-specific allowlist if it exists."""
    candidates = [
        Path.cwd() / ".security" / "sentinel-allowlist.json",
        Path.home() / ".config" / "opencode" / "sentinel-allowlist.json",
    ]
    return _load_cached("allowlist", candidates, {"paths": [], "domains": [], "commands": []})


def expand_path(p):
    """Expand ~ and env vars in a path string."""
    return os.path.expandvars(os.path.expanduser(p))


def path_matches(actual, pattern):
    """Match actual path against a pattern.

    Matches on: exact match, directory containment (startswith + '/'),
    or path component match (pattern appears as a full component sequence).
    No pure substring fallback.
    """
    actual_expanded = expand_path(actual)
    pattern_expanded = expand_path(pattern)
    pattern_norm = pattern_expanded.rstrip("/")
    pattern_raw = pattern.rstrip("/")

    candidates = [actual, actual_expanded]
    for text in candidates:
        if not text:
            continue
        # Exact match
        if text == pattern_expanded or text == pattern:
            return True
        # Directory containment (pattern is a prefix up to a '/')
        if text.startswith(pattern_norm + "/") or text.startswith(pattern_raw + "/"):
            return True
        # Path component match: pattern components appear consecutively in text
        if pattern_norm and ("/" in pattern_norm or "/" in text):
            pattern_parts = pattern_norm.strip("/").split("/")
            text_parts = text.strip("/").split("/")
            # Check if pattern_parts is a contiguous subsequence of text_parts
            plen = len(pattern_parts)
            for i in range(len(text_parts) - plen + 1):
                if text_parts[i:i + plen] == pattern_parts:
                    return True
    return False


def is_allowlisted_path(path, allowlist_paths):
    return any(path_matches(path, p) for p in allowlist_paths)


def _extract_domain(url_or_domain):
    """Extract the hostname from a URL or return the input as-is if it's already a domain."""
    text = url_or_domain.strip().lower()
    # If it looks like a URL, parse it
    if "://" in text:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(text)
            return parsed.hostname or ""
        except Exception:
            return text
    # Strip leading user@
    if "@" in text:
        text = text.rsplit("@", 1)[-1]
    # Strip trailing path/port
    text = text.split("/")[0].split(":")[0]
    return text


def is_allowlisted_domain(url_or_domain, allowlist_domains):
    """Check if the domain in url_or_domain matches an allowlisted domain.

    Uses proper domain matching: the extracted hostname must either equal the
    allowlisted domain exactly, or be a subdomain of it (e.g. 'sub.github.com'
    matches 'github.com'). This prevents bypass via substring embedding
    (e.g. 'api.anthropic.com.attacker.com' no longer matches 'api.anthropic.com').
    """
    hostname = _extract_domain(url_or_domain)
    if not hostname:
        return False
    for d in allowlist_domains:
        d_lc = d.lower().strip()
        if not d_lc:
            continue
        # Exact match
        if hostname == d_lc:
            return True
        # Subdomain match: hostname ends with '.allowlisted_domain'
        if hostname.endswith("." + d_lc):
            return True
    return False


def _generate_typosquat_variants(domain):
    """Generate common typosquatting variants for a domain.

    Covers: character substitution (homoglyphs), character deletion,
    character transposition, hyphen insertion/removal, and TLD swaps.
    Returns a set of variant strings (lowercase, without TLD for prefix matching).
    """
    name, _, tld = domain.rpartition(".")
    if not name:
        return set()

    variants = set()

    # Homoglyph substitutions (common confusables)
    homoglyphs = {
        "a": ["4", "@"],
        "b": ["d", "6"],
        "c": ["k"],
        "d": ["b"],
        "e": ["3"],
        "g": ["q", "9"],
        "i": ["1", "l", "!"],
        "l": ["1", "i", "|"],
        "o": ["0"],
        "s": ["5", "$"],
        "t": ["7"],
        "u": ["v"],
        "v": ["u"],
        "z": ["2"],
    }
    for i, ch in enumerate(name):
        for replacement in homoglyphs.get(ch, []):
            variant = name[:i] + replacement + name[i + 1:]
            variants.add(variant)

    # Single character deletion
    for i in range(len(name)):
        variant = name[:i] + name[i + 1:]
        if len(variant) > 1:
            variants.add(variant)

    # Adjacent character transposition
    for i in range(len(name) - 1):
        variant = name[:i] + name[i + 1] + name[i] + name[i + 2:]
        variants.add(variant)

    # Hyphen insertion between every pair of characters
    for i in range(1, len(name)):
        variant = name[:i] + "-" + name[i:]
        variants.add(variant)

    # Hyphen removal (if present)
    if "-" in name:
        variants.add(name.replace("-", ""))

    # Common TLD swaps
    alt_tlds = ["com", "net", "org", "io", "co", "club", "xyz", "info", "biz", "app"]
    for alt in alt_tlds:
        if alt != tld:
            variants.add(f"{name}.{alt}")

    # Add original name for prefix matching (name + any TLD)
    return variants


def check_typosquatting(text, known_malicious_domains):
    """Check if text contains a typosquatting variant of a known malicious domain.

    Returns (reason, severity) or (None, None).
    Only matches variants that appear in URL-like context (preceded by ://, @, or
    followed by a dot+TLD pattern) to avoid false positives on common substrings.
    """
    text_lc = text.lower()
    for entry in known_malicious_domains:
        domain = entry.get("domain", "")
        if not domain:
            continue
        variants = _generate_typosquat_variants(domain)
        for variant in variants:
            # Skip if variant is the exact domain (already caught by exact match)
            if variant == domain:
                continue
            # Skip very short variants (< 4 chars) — too many false positives
            if len(variant) < 4:
                continue
            if variant not in text_lc:
                continue
            # Require URL-like context: variant must appear after ://, after @,
            # or be followed by . + TLD-like suffix, or be a full domain with TLD
            # This prevents matching "evi" inside "previous"
            if "." in variant:
                # Full domain variant (e.g., "giftshop.net") — match as-is
                return (
                    f"possible typosquatting of known-malicious domain '{domain}': "
                    f"found '{variant}' in text",
                    "high",
                )
            # Variant without TLD — must appear in URL context
            url_context_patterns = [
                rf"://[^/\s]*{re.escape(variant)}",  # after ://
                rf"@{re.escape(variant)}",  # after @
                rf"{re.escape(variant)}\.[a-z]{{2,10}}",  # followed by .tld
            ]
            for pat in url_context_patterns:
                if re.search(pat, text_lc):
                    return (
                        f"possible typosquatting of known-malicious domain '{domain}': "
                        f"found '{variant}' in URL context",
                        "high",
                    )
    return (None, None)


def check_sensitive_paths(tool_input, iocs, allowlist):
    """Return (hit_pattern, severity) or (None, None)."""
    patterns = iocs.get("sensitive_paths", {}).get("patterns", [])
    regexes = iocs.get("sensitive_paths", {}).get("regex_patterns", [])
    allowed = allowlist.get("paths", []) + iocs.get("allowlist", {}).get("paths", [])

    raw_haystack = _collect_strings(tool_input)
    # Also extract individual tokens from command strings (e.g. "cat ~/.aws/credentials")
    haystack = []
    for text in raw_haystack:
        haystack.append(text)
        if " " in text:
            haystack.extend(text.split())

    for text in haystack:
        if is_allowlisted_path(text, allowed):
            continue
        for p in patterns:
            if path_matches(text, p):
                return (f"sensitive path: {p}", "critical")
        for rx in regexes:
            if re.search(rx, text):
                return (f"sensitive path pattern: /{rx}/", "critical")
    return (None, None)


def check_sensitive_env(tool_input, iocs):
    """Detect reads of known-sensitive environment variables."""
    patterns = iocs.get("sensitive_env_vars", {}).get("patterns", [])
    regexes = iocs.get("sensitive_env_vars", {}).get("regex_patterns", [])

    haystack = _collect_strings(tool_input)
    for text in haystack:
        for var in patterns:
            if re.search(rf"\b{re.escape(var)}\b", text):
                return (f"sensitive env var: {var}", "high")
        for rx in regexes:
            if re.search(rx, text):
                return (f"env var pattern: /{rx}/", "high")
    return (None, None)


def check_suspicious_network(tool_input, iocs, allowlist):
    """Detect known-malicious or suspicious network destinations."""
    net = iocs.get("suspicious_network", {})
    known_malicious = net.get("known_malicious_domains", [])
    suspicious_tlds = net.get("suspicious_tlds", [])
    pastebin = net.get("pastebin_style", [])
    suspicious_patterns = net.get("suspicious_patterns", [])

    allowed_domains = allowlist.get("domains", []) + iocs.get("allowlist", {}).get("domains", [])

    haystack = _collect_strings(tool_input)

    for text in haystack:
        # Known malicious -- critical, no allowlist override
        for entry in known_malicious:
            domain = entry.get("domain", "").lower()
            if domain and domain in text.lower():
                return (f"known-malicious domain: {entry['domain']} ({entry.get('incident', 'confirmed incident')})", "critical")

        # Typosquatting detection -- high severity
        typo_reason, typo_severity = check_typosquatting(text, known_malicious)
        if typo_severity:
            return (typo_reason, typo_severity)

        # Allowlisted? Skip remaining checks.
        if is_allowlisted_domain(text, allowed_domains):
            continue

        # Pastebin-style services (extract all URLs from text for proper matching)
        urls_in_text = re.findall(r"https?://[^\s\"'<>]+", text)
        domains_to_check = [_extract_domain(u) for u in urls_in_text]
        # Also try the whole text as a domain in case it's bare
        domains_to_check.append(_extract_domain(text))
        for text_domain in domains_to_check:
            if not text_domain:
                continue
            for ps in pastebin:
                ps_lc = ps.lower()
                if text_domain == ps_lc or text_domain.endswith("." + ps_lc):
                    return (f"pastebin-style service: {ps}", "high")

        # Raw IPs in URLs
        for rx in suspicious_patterns:
            if re.search(rx, text):
                if "\\d+\\.\\d+\\.\\d+\\.\\d+" in rx:
                    return ("raw IP address in URL (no domain)", "high")
                return (f"suspicious network pattern: /{rx}/", "high")

        # Suspicious TLDs
        for tld in suspicious_tlds:
            if re.search(rf"https?://[^\s/]+{re.escape(tld)}(/|\s|$|\"|')", text):
                return (f"suspicious TLD: {tld}", "medium")

    return (None, None)


def check_dangerous_commands(tool_input, iocs, allowlist):
    """Detect dangerous shell command patterns."""
    patterns = iocs.get("dangerous_commands", {}).get("patterns", [])
    allowed_commands = allowlist.get("commands", [])

    haystack = _collect_strings(tool_input)

    for text in haystack:
        stripped = text.strip()
        if any(stripped == a or stripped.startswith(a + " ") for a in allowed_commands):
            continue
        for rx in patterns:
            if re.search(rx, text):
                return (f"dangerous command pattern: /{rx}/", "critical")
    return (None, None)


def check_data_exfiltration(tool_input, iocs, allowlist):
    """Detect patterns suggesting data archiving + exfiltration."""
    haystack = _collect_strings(tool_input)

    # Load patterns from iocs.json, with hardcoded fallbacks
    exfil_section = iocs.get("data_exfiltration", {})
    exfil_patterns = exfil_section.get("patterns", [])

    sensitive_data_patterns = [
        r"/etc/passwd", r"/etc/shadow", r"\.ssh/", r"\.aws/",
        r"\.env\b", r"credentials", r"\.kube/config", r"\.gnupg/",
        r"id_rsa", r"\.pem\b", r"\.key\b",
    ]

    for text in haystack:
        tl = text.lower()

        # Check patterns from iocs.json first (e.g. tar+curl combos)
        for rx in exfil_patterns:
            try:
                if re.search(rx, text, re.IGNORECASE):
                    return (f"data exfiltration pattern: /{rx}/", "critical")
            except re.error:
                continue

        # curl POST with file upload targeting sensitive data
        if re.search(r"curl\b.*-[A-Za-z]*X\s*POST", text) or re.search(r"curl\b.*--data|curl\b.*-d\s", text):
            if re.search(r"-d\s+@|--data-binary\s+@|--data\s+@|-F\s+['\"]?file=@", text):
                for sp in sensitive_data_patterns:
                    if re.search(sp, text):
                        return ("data exfiltration: curl POST with sensitive file upload", "critical")

        # Archive (tar/zip) combined with curl/wget in the same command
        if re.search(r"\b(tar|zip|7z|gzip)\b", tl) and re.search(r"\b(curl|wget|nc|ncat)\b", tl):
            for sp in sensitive_data_patterns:
                if re.search(sp, text):
                    return ("data exfiltration: archive + upload of sensitive data", "critical")
            # Even without sensitive pattern, archiving + sending is suspicious
            return ("data exfiltration: archive + network upload detected", "high")

    return (None, None)


def check_crypto_mining(tool_input, iocs, allowlist):
    """Detect crypto mining related commands and patterns."""
    haystack = _collect_strings(tool_input)

    # Load patterns from iocs.json
    mining_section = iocs.get("crypto_mining", {})
    ioc_patterns = mining_section.get("patterns", [])
    known_pools = mining_section.get("known_pools", [])

    # Hardcoded fallbacks for patterns not in iocs.json
    fallback_patterns = [
        r"\bxmrig\b",
        r"stratum\+tcp://",
        r"stratum\+ssl://",
        r"--donate-level\b",
        r"\bcpuminer\b",
        r"\bminerd\b",
        r"\bbfgminer\b",
        r"\bcgminer\b",
        r"\bmonero\b",
        r"\bxmr\b",
        r"coinhive",
        r"cryptonight",
    ]

    # Merge ioc_patterns with fallbacks (avoid duplicates)
    all_patterns = list(ioc_patterns)
    ioc_patterns_lower = {p.lower() for p in ioc_patterns}
    for p in fallback_patterns:
        if p.lower() not in ioc_patterns_lower:
            all_patterns.append(p)

    # Add known pool domains as regex patterns
    for pool in known_pools:
        pool_rx = re.escape(pool)
        if pool_rx.lower() not in ioc_patterns_lower:
            all_patterns.append(pool_rx)

    for text in haystack:
        tl = text.lower()
        for rx in all_patterns:
            try:
                if re.search(rx, tl):
                    return (f"crypto mining detected: /{rx}/", "critical")
            except re.error:
                continue

    return (None, None)


def check_prompt_injection(tool_input, iocs):
    """Detect prompt injection phrases in tool call arguments."""
    patterns = iocs.get("prompt_injection_phrases", {}).get("patterns", [])

    haystack = _collect_strings(tool_input)
    for text in haystack:
        for rx in patterns:
            if re.search(rx, text):
                return (f"prompt injection detected: /{rx}/", "high")
    return (None, None)


def _collect_strings(obj):
    """Walk a dict/list recursively and return all leaf strings."""
    out = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            out.extend(_collect_strings(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_collect_strings(v))
    return out


SELF_PROTECTED_PATTERNS = [
    re.compile(r"sentinel-allowlist\.json", re.IGNORECASE),
    re.compile(r"\.security/.*\.json$", re.IGNORECASE),
    re.compile(r"mcp-sentinel-threats\.json", re.IGNORECASE),
    re.compile(r"iocs\.json$", re.IGNORECASE),
]

WRITE_TOOLS = {"write", "edit", "bash"}


def _is_self_protected_write(tool_name, tool_input):
    """Check if tool call attempts to write to a security config file.

    Returns the matched path string, or None.
    Only checks file paths and bash write commands -- not file content,
    to avoid false positives on documentation or code that mentions
    security file names.
    """
    if tool_name not in WRITE_TOOLS:
        return None

    # For write/edit tools, only check the target file path
    if tool_name in ("write", "edit"):
        candidates = [
            tool_input.get("filePath", ""),
            tool_input.get("newFilePath", ""),
        ]
        for val in candidates:
            if not isinstance(val, str):
                continue
            for pattern in SELF_PROTECTED_PATTERNS:
                if pattern.search(val):
                    return val
        return None

    # For bash, only block commands that write to protected files
    if tool_name == "bash":
        cmd = tool_input.get("command", "")
        if not isinstance(cmd, str):
            return None
        write_patterns = [
            re.compile(r">\s*\S*sentinel-allowlist", re.IGNORECASE),
            re.compile(r"tee\s+\S*sentinel-allowlist", re.IGNORECASE),
            re.compile(r"cp\s+.*sentinel-allowlist", re.IGNORECASE),
            re.compile(r"mv\s+.*sentinel-allowlist", re.IGNORECASE),
            re.compile(r"rm\s+.*sentinel-allowlist", re.IGNORECASE),
            re.compile(r">\s*\S*trusted-skills", re.IGNORECASE),
            re.compile(r"tee\s+\S*trusted-skills", re.IGNORECASE),
            re.compile(r"cp\s+.*trusted-skills", re.IGNORECASE),
            re.compile(r"mv\s+.*trusted-skills", re.IGNORECASE),
            re.compile(r"rm\s+.*trusted-skills", re.IGNORECASE),
            re.compile(r">\s*\S*iocs\.json", re.IGNORECASE),
            re.compile(r"tee\s+\S*iocs\.json", re.IGNORECASE),
            re.compile(r"rm\s+.*iocs\.json", re.IGNORECASE),
            re.compile(r">\s*\S*mcp-sentinel-threats", re.IGNORECASE),
            re.compile(r"rm\s+.*mcp-sentinel-threats", re.IGNORECASE),
        ]
        for wp in write_patterns:
            if wp.search(cmd):
                return cmd

    return None


def _build_allowlist_hint(tool_input, reason):
    """Build a concrete hint telling the human what to add to the allowlist.

    Inspects the block reason and tool_input to suggest the minimal exception.
    """
    hint_lines = ["Suggested exception (for the human to add manually):"]

    # Detect what kind of block it was from the reason string
    reason_lc = reason.lower() if reason else ""

    if "sensitive path" in reason_lc or "sensitive file" in reason_lc:
        # Extract the path from filePath or command
        target = tool_input.get("filePath", "") or ""
        if not target:
            # Try to extract from command
            cmd = tool_input.get("command", "")
            # Simple heuristic: grab the first path-like token
            for token in cmd.split():
                if "/" in token:
                    target = token
                    break
        if target:
            hint_lines.append(f'  Add to "paths": ["{target}"]')

    elif "domain" in reason_lc or "network" in reason_lc or "url" in reason_lc:
        # Try to extract domain from the reason or command
        cmd = tool_input.get("command", "") or tool_input.get("url", "") or ""
        import urllib.parse
        try:
            parsed = urllib.parse.urlparse(cmd if "://" in cmd else f"https://{cmd}")
            domain = parsed.hostname
            if domain:
                hint_lines.append(f'  Add to "domains": ["{domain}"]')
        except Exception:
            hint_lines.append('  Add the domain to "domains": ["example.com"]')

    elif "command" in reason_lc or "dangerous" in reason_lc:
        cmd = tool_input.get("command", "")
        if cmd:
            # Suggest the base command (first token)
            base = cmd.strip().split()[0] if cmd.strip() else cmd
            hint_lines.append(f'  Add to "commands": ["{base}"]')

    else:
        hint_lines.append(
            '  Add the appropriate exception to "paths", "domains", or "commands" in the allowlist.'
        )

    hint_lines.append(
        "  Then re-run the operation."
    )
    return "\n".join(hint_lines)


# ---------------------------------------------------------------------------
# Unicode Smuggling Detection
# ---------------------------------------------------------------------------

# Dangerous Unicode ranges used in smuggling attacks
_UNICODE_SMUGGLING_RANGES = [
    (0xE0000, 0xE007F),   # Tags block (used for invisible instructions)
    (0xE0100, 0xE01EF),   # Variation Selectors Supplement
    (0x200B, 0x200F),     # Zero-width & directional marks (ZWSP, ZWNJ, ZWJ, LRM, RLM)
    (0x2028, 0x2029),     # Line/paragraph separators
    (0x202A, 0x202E),     # Bidirectional overrides (LRE, RLE, PDF, LRO, RLO)
    (0x2060, 0x2064),     # Word joiner, invisible operators
    (0x2066, 0x2069),     # Bidirectional isolates
    (0xFEFF, 0xFEFF),     # BOM / zero-width no-break space
    (0x00AD, 0x00AD),     # Soft hyphen (invisible in most renderers)
    (0xFFF9, 0xFFFB),     # Interlinear annotations
]

# Compile into a regex character class for efficient matching
_SMUGGLING_PATTERN = re.compile(
    "[" + "".join(
        f"\\U{lo:08X}-\\U{hi:08X}" if lo != hi else f"\\U{lo:08X}"
        for lo, hi in _UNICODE_SMUGGLING_RANGES
    ) + "]"
)


def check_unicode_smuggling(tool_input, iocs):
    """Detect invisible/smuggled Unicode characters in tool inputs.

    These characters are invisible to humans but interpreted by LLMs,
    enabling hidden instruction injection in skills, prompts, and file content.

    Returns (reason, severity) or (None, None).
    """
    # Fields to inspect for hidden Unicode
    fields_to_check = [
        ("content", "file content"),
        ("command", "command"),
        ("description", "description"),
        ("prompt", "prompt"),
        ("code", "code"),
        ("text", "text"),
        ("body", "body"),
        ("message", "message"),
        ("filePath", "file path"),
        ("newFilePath", "file path"),
    ]

    for field, label in fields_to_check:
        value = tool_input.get(field, "")
        if not value or not isinstance(value, str):
            continue

        matches = _SMUGGLING_PATTERN.findall(value)
        if matches:
            # Classify severity based on the characters found
            has_tags = any(0xE0000 <= ord(c) <= 0xE007F for c in matches)
            has_bidi = any(
                0x202A <= ord(c) <= 0x202E or 0x2066 <= ord(c) <= 0x2069
                for c in matches
            )

            # Tag characters are the primary smuggling vector
            if has_tags:
                severity = "critical"
                detail = (
                    f"Unicode Tag characters (U+E0000-U+E007F) detected in {label}. "
                    f"These are invisible characters commonly used to smuggle hidden "
                    f"instructions into AI agent skills and prompts. "
                    f"Found {len(matches)} suspicious character(s)."
                )
            elif has_bidi:
                severity = "high"
                detail = (
                    f"Bidirectional override characters detected in {label}. "
                    f"These can hide malicious content by reversing text display direction. "
                    f"Found {len(matches)} suspicious character(s)."
                )
            else:
                severity = "medium"
                detail = (
                    f"Invisible Unicode characters detected in {label}. "
                    f"Zero-width or non-rendering characters may hide instructions. "
                    f"Found {len(matches)} suspicious character(s)."
                )

            return detail, severity

    return None, None


def decide(payload):
    """Given a tool call payload, return (decision, reason).

    Decision is one of: "allow", "block", "warn".
    """
    iocs = load_iocs()
    allowlist = load_user_allowlist()

    tool_name = payload.get("tool_name") or payload.get("tool", "")
    tool_input = payload.get("tool_input") or payload.get("input") or {}

    # --- Self-protection: block writes to allowlist/security config files ---
    protected_match = _is_self_protected_write(tool_name, tool_input)
    if protected_match:
        return "block", (
            "[CRITICAL] self-protection: writing to security configuration files "
            "is not allowed from within the agent. "
            "A human must edit this file manually outside of OpenCode."
        )

    # If the target file is explicitly allowlisted, skip all content checks.
    # This lets users allowlist files whose content contains security patterns
    # (e.g. scripts that reference .env, documentation that mentions malicious domains).
    allowed_paths = allowlist.get("paths", []) + iocs.get("allowlist", {}).get("paths", [])
    target_file = tool_input.get("filePath", "") or tool_input.get("newFilePath", "")
    if target_file and any(is_allowlisted_path(target_file, [p]) for p in allowed_paths):
        return "allow", None

    # All checks: ("3arg", fn) takes (tool_input, iocs, allowlist),
    #             ("2arg", fn) takes (tool_input, iocs)
    checks = [
        ("3arg", check_sensitive_paths),
        ("3arg", check_suspicious_network),
        ("3arg", check_dangerous_commands),
        ("3arg", check_data_exfiltration),
        ("3arg", check_crypto_mining),
        ("2arg", check_sensitive_env),
        ("2arg", check_prompt_injection),
        ("2arg", check_unicode_smuggling),
    ]

    highest = None
    highest_reason = None
    severity_rank = {"medium": 1, "high": 2, "critical": 3}

    for sig, fn in checks:
        if sig == "3arg":
            reason, severity = fn(tool_input, iocs, allowlist)
        else:
            reason, severity = fn(tool_input, iocs)
        if severity:
            if not highest or severity_rank.get(severity, 0) > severity_rank.get(highest, 0):
                highest = severity
                highest_reason = reason

    if not highest:
        return "allow", None

    if highest in ("critical", "high"):
        return "block", f"[{highest.upper()}] {highest_reason}"
    return "warn", f"[{highest.upper()}] {highest_reason}"


def main():
    if "--version" in sys.argv:
        print(f"sentinel_preflight {__version__}")
        sys.exit(0)

    t0 = time.monotonic()

    raw = sys.stdin.read()
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        elapsed = round((time.monotonic() - t0) * 1000, 2)
        print(json.dumps({"decision": "allow", "elapsed_ms": elapsed}))
        return

    decision, reason = decide(payload)
    elapsed = round((time.monotonic() - t0) * 1000, 2)

    if decision == "allow":
        print(json.dumps({"decision": "allow", "elapsed_ms": elapsed}))
        return

    tool_name = payload.get("tool_name") or payload.get("tool", "<unknown>")
    tool_input = payload.get("tool_input") or payload.get("input") or {}

    if decision == "allow":
        print(json.dumps({"decision": "allow", "elapsed_ms": elapsed}))
        return

    # Extract severity from reason string (e.g. "[CRITICAL] ..." -> "critical")
    severity = "unknown"
    if reason:
        import re as _re
        m = _re.match(r"\[(\w+)\]", reason)
        if m:
            severity = m.group(1).lower()

    # Log structured decision for SIEM / post-incident analysis
    _log_decision(tool_name, decision, reason, severity, elapsed, tool_input)

    if decision == "block":
        # Build a human-friendly hint showing what to allowlist
        hint = _build_allowlist_hint(tool_input, reason)
        message = (
            f"OpenCode Security Agent blocked a {tool_name} call.\n"
            f"Reason: {reason}\n"
            f"If this is a false positive, ask the human to manually add an exception "
            f"to .security/sentinel-allowlist.json (this file cannot be edited by the agent).\n"
            f"{hint}"
        )
        print(json.dumps({
            "decision": "block",
            "reason": message,
            "elapsed_ms": elapsed,
        }))
    else:  # warn
        message = (
            f"OpenCode Security Agent: suspicious {tool_name} call allowed with warning.\n"
            f"Reason: {reason}"
        )
        print(json.dumps({
            "decision": "allow",
            "reason": message,
            "elapsed_ms": elapsed,
        }))


if __name__ == "__main__":
    main()
