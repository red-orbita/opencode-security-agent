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

__version__ = "1.2.0"

import json
import os
import re
import sys
import time
from pathlib import Path

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
        data = json.loads(path.read_text())
    except Exception:
        data = default

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


def is_allowlisted_domain(url_or_domain, allowlist_domains):
    url_lc = url_or_domain.lower()
    return any(d.lower() in url_lc for d in allowlist_domains)


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
            if entry.get("domain", "").lower() in text.lower():
                return (f"known-malicious domain: {entry['domain']} ({entry.get('incident', 'confirmed incident')})", "critical")

        # Typosquatting detection -- high severity
        typo_reason, typo_severity = check_typosquatting(text, known_malicious)
        if typo_severity:
            return (typo_reason, typo_severity)

        # Allowlisted? Skip remaining checks.
        if is_allowlisted_domain(text, allowed_domains):
            continue

        # Pastebin-style services
        for ps in pastebin:
            if ps.lower() in text.lower():
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

    sensitive_data_patterns = [
        r"/etc/passwd", r"/etc/shadow", r"\.ssh/", r"\.aws/",
        r"\.env\b", r"credentials", r"\.kube/config", r"\.gnupg/",
        r"id_rsa", r"\.pem\b", r"\.key\b",
    ]

    for text in haystack:
        tl = text.lower()

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

    mining_patterns = [
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
        r"pool\.minexmr\.com",
        r"pool\.hashvault\.pro",
        r"monerohash\.com",
        r"nanopool\.org",
        r"minergate\.com",
        r"coinhive",
        r"cryptonight",
    ]

    for text in haystack:
        tl = text.lower()
        for rx in mining_patterns:
            if re.search(rx, tl):
                return (f"crypto mining detected: /{rx}/", "critical")

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


def decide(payload):
    """Given a tool call payload, return (decision, reason).

    Decision is one of: "allow", "block", "warn".
    """
    iocs = load_iocs()
    allowlist = load_user_allowlist()

    tool_name = payload.get("tool_name") or payload.get("tool", "")
    tool_input = payload.get("tool_input") or payload.get("input") or {}

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
    if decision == "block":
        message = (
            f"OpenCode Security Agent blocked a {tool_name} call.\n"
            f"Reason: {reason}\n"
            f"If this is a false positive, add an exception to "
            f".security/sentinel-allowlist.json and retry."
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
