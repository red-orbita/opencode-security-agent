#!/usr/bin/env python3
"""
OpenCode Security Agent — MCP Tool Poisoning Detection

Detects attempts to inject hidden instructions, deceptive text, or malicious
metadata into MCP tool definitions. Attacks target the LLM that reads tool
descriptions, not the end user.

Detected patterns (inspired by NVIDIA SkillSpector):
  TP1: Hidden Instructions — HTML comments, zero-width chars, base64, data URIs
  TP2: Unicode Deception — homoglyphs, RTL overrides, mixed-script identifiers
  TP3: Parameter Description Injection — override tokens, system prompts in params
  TP4: Description-Behavior Mismatch — suspicious keywords indicating deception

Zero external dependencies. Python 3.8+ compatible.
"""

import base64
import json
import re
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional


# ---------------------------------------------------------------------------
# TP1: Hidden Instructions patterns
# ---------------------------------------------------------------------------

# HTML comment injection
_HTML_COMMENT = re.compile(r"<!--[\s\S]*?-->")

# Zero-width characters (invisible text carriers)
_ZERO_WIDTH_CHARS = re.compile(
    "[\u200B\u200C\u200D\u200E\u200F"   # zero-width space, joiners, marks
    "\u2060\u2061\u2062\u2063\u2064"     # word joiner, invisible operators
    "\uFEFF"                              # BOM / zero-width no-break
    "\U000E0000-\U000E007F"              # Tags block
    "\U000E0100-\U000E01EF"              # Variation selectors supplement
    "]"
)

# Base64 encoded content (suspiciously long)
_BASE64_BLOCK = re.compile(
    r"(?:base64[,:]?\s*|data:[^;]+;base64,)([A-Za-z0-9+/=]{40,})"
)

# Standalone base64 blobs (at least 60 chars, likely encoded instructions)
_BASE64_STANDALONE = re.compile(r"\b[A-Za-z0-9+/]{60,}={0,2}\b")

# Data URI patterns
_DATA_URI = re.compile(r"data:[a-z]+/[a-z]+;base64,[A-Za-z0-9+/=]+", re.IGNORECASE)

# Invisible Unicode tag encoding (U+E0001-U+E007F = ASCII mapped to tags block)
_TAG_ENCODING = re.compile("[\U000E0020-\U000E007E]+")


# ---------------------------------------------------------------------------
# TP2: Unicode Deception patterns
# ---------------------------------------------------------------------------

# RTL override characters (can reverse display of text)
_RTL_OVERRIDES = re.compile("[\u202A-\u202E\u2066-\u2069]")

# Common homoglyph substitutions (Latin lookalikes from Cyrillic, Greek, etc.)
_HOMOGLYPHS = {
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043E": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у
    "\u0445": "x",  # Cyrillic х
    "\u0456": "i",  # Ukrainian і
    "\u0458": "j",  # Cyrillic ј
    "\u04BB": "h",  # Cyrillic һ
    "\u0501": "d",  # Cyrillic ԁ
    "\u051B": "q",  # Cyrillic ԛ
    "\u0261": "g",  # Latin Small Letter Script G
    "\u01C3": "!",  # Latin Letter Retroflex Click
    "\uFF41": "a",  # Fullwidth a
    "\uFF42": "b",  # Fullwidth b
}

_HOMOGLYPH_CHARS = re.compile("[" + "".join(_HOMOGLYPHS.keys()) + "]")

# Mixed script detection (Latin + Cyrillic/Greek in same word)
_CYRILLIC = re.compile(r"[\u0400-\u04FF]")
_LATIN = re.compile(r"[a-zA-Z]")


# ---------------------------------------------------------------------------
# TP3: Parameter Description Injection
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS = [
    # System prompt / instruction overrides
    re.compile(r"(?:system|instruction|prompt)\s*(?:override|:)", re.IGNORECASE),
    re.compile(r"ignore\s+(?:all\s+)?(?:previous|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"you\s+(?:are|must|should|will)\s+now", re.IGNORECASE),
    re.compile(r"disregard\s+(?:all|any)\s+(?:prior|previous)", re.IGNORECASE),
    re.compile(r"new\s+(?:system\s+)?instructions?\s*:", re.IGNORECASE),

    # Hidden directives disguised as descriptions
    re.compile(r"(?:IMPORTANT|NOTE|WARNING):\s*(?:always|never|must|do not)", re.IGNORECASE),
    re.compile(r"(?:secret|hidden)\s+(?:instruction|command|directive)", re.IGNORECASE),

    # Token injection attempts
    re.compile(r"<\|(?:im_start|im_end|system|endoftext)\|>"),
    re.compile(r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>"),

    # Malicious default values
    re.compile(r"default\s*(?:value)?\s*[:=]\s*['\"].*(?:curl|wget|nc\s|bash|eval|exec)", re.IGNORECASE),

    # --- LLM-directed social engineering in tool descriptions ---
    # Directing the AI to read sensitive files
    re.compile(r"(?:read|access|open|cat|include|check)\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:~/|/etc/|~/)?\.(ssh|aws|gnupg|config|env)", re.IGNORECASE),
    re.compile(r"(?:read|access|open|cat)\s+(?:the\s+)?/etc/(?:shadow|passwd|sudoers)", re.IGNORECASE),
    re.compile(r"~/.ssh/(?:id_rsa|id_ed25519|config|authorized_keys)", re.IGNORECASE),
    re.compile(r"~/.aws/credentials", re.IGNORECASE),

    # Directing the AI to exfiltrate data
    re.compile(r"(?:send|transmit|post|forward|include|append)\s+(?:the\s+)?(?:value\s+of\s+)?(?:all\s+)?(?:env(?:ironment)?(?:\s*var(?:iable)?s?)?|credentials?|tokens?|keys?|secrets?)", re.IGNORECASE),
    re.compile(r"(?:include|append|add)\s+.*(?:(?:env|environment)\s*(?:var|variable)s?|api.?keys?|tokens?)\s+(?:in|to)\s+(?:the\s+)?(?:response|output|request|result)", re.IGNORECASE),

    # Directing the AI to execute commands
    re.compile(r"(?:silently|quietly|secretly)\s+(?:execute|run|invoke|call)", re.IGNORECASE),
    re.compile(r"(?:before|after)\s+respond(?:ing)?\s*,?\s*(?:silently\s+)?(?:execute|run)", re.IGNORECASE),
    re.compile(r"(?:curl|wget|nc|bash|sh)\s+.*https?://", re.IGNORECASE),

    # "Do not tell the user" / secrecy patterns
    re.compile(r"(?:do\s+not|don'?t|never)\s+(?:mention|tell|reveal|show|disclose)\s+(?:this|these|the)\s+(?:instruction|step|action)", re.IGNORECASE),
    re.compile(r"(?:do\s+not|don'?t|never)\s+(?:mention|tell|reveal)\s+(?:this\s+)?(?:to\s+)?(?:the\s+)?user", re.IGNORECASE),

    # Instructing to include exfiltration URLs
    re.compile(r"(?:send|post|forward)\s+(?:to|at)\s+https?://", re.IGNORECASE),

    # NOTE TO AI / AI ASSISTANT patterns
    re.compile(r"(?:NOTE|INSTRUCTION|DIRECTIVE)\s+(?:TO|FOR)\s+(?:AI|ASSISTANT|LLM|MODEL|AGENT)", re.IGNORECASE),
    re.compile(r"(?:THIS\s+IS\s+)?(?:PART\s+OF\s+)?(?:YOUR|THE)\s+(?:CORE|SYSTEM|BASE)\s+INSTRUCTIONS?", re.IGNORECASE),

    # "From now on" behavioral modification
    re.compile(r"from\s+now\s+on\s*,?\s+(?:always|include|add|send|append)", re.IGNORECASE),

    # process.env / os.environ references in descriptions (should not be there)
    re.compile(r"process\.env\.\w+", re.IGNORECASE),
    re.compile(r"os\.environ", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# TP4: Description-Behavior Mismatch indicators
# ---------------------------------------------------------------------------

_DECEPTION_KEYWORDS = [
    # Claims to be harmless but uses dangerous patterns
    re.compile(r"(?:harmless|safe|simple|basic)\s+(?:helper|tool|utility)", re.IGNORECASE),
    # Contradictory claims
    re.compile(r"does\s+not\s+(?:access|read|write|send|execute).*(?:but|however|also)", re.IGNORECASE),
    # Suspicious capability claims combined with innocent descriptions
    re.compile(r"(?:formatter|linter|validator|beautifier).*(?:network|http|socket|exec)", re.IGNORECASE),
    # Shadow command indicators
    re.compile(r"(?:replaces?|overrides?|intercepts?|hooks?)\s+(?:built-?in|default|native)", re.IGNORECASE),
]


def _decode_base64_safe(data: str) -> Optional[str]:
    """Try to decode base64 and check if it contains text."""
    try:
        decoded = base64.b64decode(data).decode("utf-8", errors="replace")
        # Check if decoded content looks like instructions
        if any(kw in decoded.lower() for kw in
               ["exec", "eval", "system", "curl", "wget", "ignore", "override",
                "instruction", "secret", "password", "token", "key"]):
            return decoded
    except Exception:
        pass
    return None


def _check_mixed_scripts(text: str) -> List[Dict[str, Any]]:
    """Detect words with mixed Latin + Cyrillic characters."""
    findings = []
    words = re.findall(r"\b\w+\b", text)
    for word in words:
        has_cyrillic = bool(_CYRILLIC.search(word))
        has_latin = bool(_LATIN.search(word))
        if has_cyrillic and has_latin and len(word) > 2:
            findings.append(word)
    return findings


def analyze_text(text: str, context: str = "tool_description") -> List[Dict[str, Any]]:
    """
    Analyze text content for MCP tool poisoning patterns.

    Args:
        text: The text to analyze (tool description, parameter description, etc.)
        context: Context label for findings

    Returns:
        List of findings
    """
    findings = []

    # --- TP1: Hidden Instructions ---

    # HTML comments with content
    for match in _HTML_COMMENT.finditer(text):
        comment_content = match.group().strip("<!->- \n\t")
        if len(comment_content) > 5:  # Non-trivial comment
            findings.append({
                "rule_id": "TP1",
                "severity": "high",
                "message": f"Hidden HTML comment in {context}: '{comment_content[:80]}...'",
                "confidence": 88,
                "pattern": "html_comment",
            })

    # Zero-width characters
    zw_matches = _ZERO_WIDTH_CHARS.findall(text)
    if zw_matches:
        findings.append({
            "rule_id": "TP1",
            "severity": "high",
            "message": (
                f"Zero-width/invisible characters in {context} "
                f"({len(zw_matches)} hidden chars detected)"
            ),
            "confidence": 92,
            "pattern": "zero_width",
        })

    # Base64 encoded blocks
    for match in _BASE64_BLOCK.finditer(text):
        decoded = _decode_base64_safe(match.group(1))
        if decoded:
            findings.append({
                "rule_id": "TP1",
                "severity": "high",
                "message": (
                    f"Base64-encoded instructions in {context}: "
                    f"decoded contains '{decoded[:60]}...'"
                ),
                "confidence": 90,
                "pattern": "base64_instructions",
            })

    # Standalone base64 that decodes to instructions
    for match in _BASE64_STANDALONE.finditer(text):
        decoded = _decode_base64_safe(match.group())
        if decoded:
            findings.append({
                "rule_id": "TP1",
                "severity": "high",
                "message": (
                    f"Hidden base64 payload in {context}: "
                    f"decodes to '{decoded[:60]}...'"
                ),
                "confidence": 85,
                "pattern": "base64_hidden",
            })

    # Data URIs
    for match in _DATA_URI.finditer(text):
        findings.append({
            "rule_id": "TP1",
            "severity": "medium",
            "message": f"Data URI in {context} may hide instructions",
            "confidence": 70,
            "pattern": "data_uri",
        })

    # Tag-block encoded text
    tag_matches = _TAG_ENCODING.findall(text)
    if tag_matches:
        # Decode: U+E0020 = space, U+E0041 = A, etc.
        decoded_parts = []
        for match_str in tag_matches:
            decoded_parts.append(
                "".join(chr(ord(c) - 0xE0000) for c in match_str)
            )
        if any(len(d) > 3 for d in decoded_parts):
            findings.append({
                "rule_id": "TP1",
                "severity": "critical",
                "message": (
                    f"Unicode Tags block encoding in {context}: "
                    f"hidden text '{' '.join(decoded_parts)[:60]}'"
                ),
                "confidence": 95,
                "pattern": "tag_encoding",
            })

    # --- TP2: Unicode Deception ---

    # RTL overrides
    rtl_matches = _RTL_OVERRIDES.findall(text)
    if rtl_matches:
        findings.append({
            "rule_id": "TP2",
            "severity": "high",
            "message": (
                f"RTL override characters in {context} "
                f"({len(rtl_matches)} found) — can reverse displayed text"
            ),
            "confidence": 90,
            "pattern": "rtl_override",
        })

    # Homoglyphs
    homoglyph_matches = _HOMOGLYPH_CHARS.findall(text)
    if homoglyph_matches:
        substitutions = [
            f"'{c}'→'{_HOMOGLYPHS[c]}'" for c in homoglyph_matches[:5]
        ]
        findings.append({
            "rule_id": "TP2",
            "severity": "high",
            "message": (
                f"Homoglyph characters in {context}: "
                f"{', '.join(substitutions)} ({len(homoglyph_matches)} total)"
            ),
            "confidence": 85,
            "pattern": "homoglyph",
        })

    # Mixed scripts
    mixed_words = _check_mixed_scripts(text)
    if mixed_words:
        findings.append({
            "rule_id": "TP2",
            "severity": "high",
            "message": (
                f"Mixed-script identifiers in {context}: "
                f"{', '.join(mixed_words[:5])}"
            ),
            "confidence": 88,
            "pattern": "mixed_script",
        })

    # --- TP3: Parameter Description Injection ---

    for pattern in _INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            matched_text = match.group().lower()
            # Escalate severity for direct exfiltration / execution patterns
            if any(kw in matched_text for kw in [
                "override", "curl", "wget", "bash", "exec", "eval",
                "ssh", "shadow", "credentials", "/etc/",
                "silently", "secretly", "do not", "don't",
                "note to ai", "core instruction",
            ]):
                severity = "high"
            elif any(kw in matched_text for kw in [
                "send", "include", "append", "token", "key", "env",
                "from now on", "process.env",
            ]):
                severity = "high"
            else:
                severity = "medium"

            findings.append({
                "rule_id": "TP3",
                "severity": severity,
                "message": (
                    f"Injection pattern in {context}: '{match.group()[:80]}'"
                ),
                "confidence": 82,
                "pattern": "description_injection",
            })

    # --- TP4: Description-Behavior Mismatch ---

    for pattern in _DECEPTION_KEYWORDS:
        match = pattern.search(text)
        if match:
            findings.append({
                "rule_id": "TP4",
                "severity": "medium",
                "message": (
                    f"Potential description-behavior mismatch: '{match.group()}'"
                ),
                "confidence": 65,
                "pattern": "behavior_mismatch",
            })

    return findings


def analyze_mcp_manifest(manifest_path: Path) -> List[Dict[str, Any]]:
    """
    Analyze an MCP manifest/config file for tool poisoning.

    Scans tool names, descriptions, and parameter descriptions.
    """
    findings = []

    try:
        raw = manifest_path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return []

    # Scan top-level description
    top_desc = data.get("description", "")
    if top_desc:
        top_findings = analyze_text(top_desc, "manifest description")
        for f in top_findings:
            f["file"] = str(manifest_path)
        findings.extend(top_findings)

    # Scan tool definitions
    tools = data.get("tools", data.get("functions", []))
    if isinstance(tools, dict):
        tools = list(tools.values())

    for i, tool in enumerate(tools):
        if not isinstance(tool, dict):
            continue

        tool_name = tool.get("name", f"tool_{i}")

        # Scan tool description
        desc = tool.get("description", "")
        if desc:
            desc_findings = analyze_text(desc, f"tool '{tool_name}' description")
            for f in desc_findings:
                f["file"] = str(manifest_path)
                f["tool_name"] = tool_name
            findings.extend(desc_findings)

        # Scan parameter descriptions
        params = tool.get("parameters", tool.get("inputSchema", {}))
        if isinstance(params, dict):
            properties = params.get("properties", {})
            for param_name, param_def in properties.items():
                if isinstance(param_def, dict):
                    param_desc = param_def.get("description", "")
                    if param_desc:
                        param_findings = analyze_text(
                            param_desc,
                            f"tool '{tool_name}' param '{param_name}'"
                        )
                        for f in param_findings:
                            f["file"] = str(manifest_path)
                            f["tool_name"] = tool_name
                            f["parameter"] = param_name
                        findings.extend(param_findings)

    return findings


def analyze_skill_file(skill_path: Path) -> List[Dict[str, Any]]:
    """Analyze a skill file (SKILL.md, README, etc.) for poisoning."""
    try:
        content = skill_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    findings = analyze_text(content, f"skill file '{skill_path.name}'")
    for f in findings:
        f["file"] = str(skill_path)

    return findings


def analyze_directory(dir_path: Path) -> List[Dict[str, Any]]:
    """Analyze all relevant files in a directory for MCP poisoning."""
    findings = []

    # Check JSON manifests
    for pattern in ["*.json", "**/*.json"]:
        for json_file in dir_path.glob(pattern):
            if json_file.name in ("package.json", "mcp.json", "manifest.json",
                                   "tool.json", "server.json", "tsconfig.json"):
                findings.extend(analyze_mcp_manifest(json_file))

    # Check skill/readme files
    for md_file in dir_path.rglob("*.md"):
        findings.extend(analyze_skill_file(md_file))

    # Check YAML configs
    for yaml_file in list(dir_path.rglob("*.yaml")) + list(dir_path.rglob("*.yml")):
        try:
            content = yaml_file.read_text(encoding="utf-8", errors="replace")
            text_findings = analyze_text(content, f"config '{yaml_file.name}'")
            for f in text_findings:
                f["file"] = str(yaml_file)
            findings.extend(text_findings)
        except OSError:
            continue

    return findings


# ---------------------------------------------------------------------------
# CLI interface
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 mcp_poisoning.py <path>", file=sys.stderr)
        sys.exit(2)

    target = Path(sys.argv[1])
    if target.is_file():
        if target.suffix == ".json":
            results = analyze_mcp_manifest(target)
        else:
            results = analyze_skill_file(target)
    elif target.is_dir():
        results = analyze_directory(target)
    else:
        print(f"Error: {target} not found", file=sys.stderr)
        sys.exit(2)

    print(json.dumps(results, indent=2))
    sys.exit(1 if results else 0)
