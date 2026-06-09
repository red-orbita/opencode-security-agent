#!/usr/bin/env python3
"""
OpenCode Security Agent — YARA-like Pattern Signatures

Implements malware, webshell, cryptominer, and exploit detection using pure
regex patterns. Inspired by YARA rule semantics but without requiring the
YARA library (zero dependencies).

Each "rule" defines:
  - Multiple string patterns (all/any must match)
  - Condition logic (AND/OR/count thresholds)
  - Metadata (severity, description, tags)

Detected patterns:
  YR1: Malware signatures (RATs, backdoors, C2 beacons)
  YR2: Webshell patterns (PHP/Python/JS shells)
  YR3: Cryptominer indicators (pool connections, mining libraries)
  YR4: Hack tools / exploit code (privilege escalation, network scanners)

Zero external dependencies. Python 3.8+ compatible.
"""

import re
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

class YaraRule:
    """A YARA-like rule with multiple patterns and a condition."""

    def __init__(self, rule_id: str, name: str, severity: str,
                 description: str, patterns: List[re.Pattern],
                 condition: str = "any", min_matches: int = 1,
                 tags: Optional[List[str]] = None):
        self.rule_id = rule_id
        self.name = name
        self.severity = severity
        self.description = description
        self.patterns = patterns
        self.condition = condition  # "any", "all", "count"
        self.min_matches = min_matches
        self.tags = tags or []

    def match(self, content: str) -> Optional[Dict[str, Any]]:
        """Test content against this rule. Returns finding or None."""
        matches = []
        for pattern in self.patterns:
            found = pattern.search(content)
            if found:
                matches.append(found)

        triggered = False
        if self.condition == "any" and len(matches) >= 1:
            triggered = True
        elif self.condition == "all" and len(matches) == len(self.patterns):
            triggered = True
        elif self.condition == "count" and len(matches) >= self.min_matches:
            triggered = True

        if not triggered:
            return None

        # Find line number of first match
        first_match = matches[0]
        line_num = content[:first_match.start()].count("\n") + 1

        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": f"{self.name}: {self.description}",
            "line": line_num,
            "code": first_match.group()[:100],
            "confidence": 85,
            "analyzer": "yara_patterns",
            "matches": len(matches),
            "tags": self.tags,
        }


# ---------------------------------------------------------------------------
# YR1: Malware Signatures
# ---------------------------------------------------------------------------

_MALWARE_RULES = [
    YaraRule(
        "YR1", "Reverse Shell", "critical",
        "Reverse shell pattern detected — connects back to attacker",
        [
            re.compile(r"socket\.connect\s*\(\s*\(['\"][\d.]+['\"]", re.MULTILINE),
            re.compile(r"subprocess\.call\s*\(\s*\[.*?/bin/(?:sh|bash)", re.MULTILINE),
            re.compile(r"os\.dup2\s*\(", re.MULTILINE),
        ],
        condition="count", min_matches=2,
        tags=["malware", "reverse_shell"],
    ),
    YaraRule(
        "YR1", "Python RAT", "critical",
        "Remote Access Trojan pattern — persistent C2 communication",
        [
            re.compile(r"while\s+True.*?socket.*?recv", re.DOTALL),
            re.compile(r"exec\s*\(.*?recv|eval\s*\(.*?recv", re.MULTILINE),
            re.compile(r"subprocess.*?stdout\s*=\s*subprocess\.PIPE", re.MULTILINE),
        ],
        condition="count", min_matches=2,
        tags=["malware", "rat"],
    ),
    YaraRule(
        "YR1", "Keylogger Pattern", "critical",
        "Keyboard capture and exfiltration indicators",
        [
            re.compile(r"pynput|keyboard\.on_press|GetAsyncKeyState", re.MULTILINE),
            re.compile(r"log.*?key|key.*?log|keystroke", re.IGNORECASE),
        ],
        condition="all",
        tags=["malware", "keylogger"],
    ),
    YaraRule(
        "YR1", "Data Stealer", "critical",
        "Credential/browser data theft pattern",
        [
            re.compile(r"(?:Chrome|Firefox|Opera).*?(?:Login Data|cookies|passwords)", re.IGNORECASE),
            re.compile(r"sqlite3\.connect.*?(?:Login Data|cookies\.sqlite)", re.IGNORECASE),
            re.compile(r"CryptUnprotectData|dpapi|win32crypt", re.IGNORECASE),
        ],
        condition="count", min_matches=2,
        tags=["malware", "stealer"],
    ),
    YaraRule(
        "YR1", "Backdoor Persistence", "high",
        "System persistence mechanism (crontab/registry/startup)",
        [
            re.compile(r"crontab|/etc/cron\.|@reboot", re.MULTILINE),
            re.compile(r"HKEY_.*?\\Run|CurrentVersion\\Run", re.MULTILINE),
            re.compile(r"~/.bashrc|~/.profile|/etc/rc\.local|\.config/autostart", re.MULTILINE),
        ],
        condition="any",
        tags=["malware", "persistence"],
    ),
    YaraRule(
        "YR1", "C2 Beacon Pattern", "high",
        "Command and Control beacon communication loop",
        [
            re.compile(r"while.*?(?:True|1).*?(?:sleep|time\.sleep).*?(?:requests?\.|urllib|http)", re.DOTALL),
            re.compile(r"(?:requests?\.|urllib).*?(?:sleep|time\.sleep).*?while", re.DOTALL),
        ],
        condition="any",
        tags=["malware", "c2"],
    ),
]

# ---------------------------------------------------------------------------
# YR2: Webshell Patterns
# ---------------------------------------------------------------------------

_WEBSHELL_RULES = [
    YaraRule(
        "YR2", "Python Webshell", "critical",
        "Python-based web shell allowing remote command execution",
        [
            re.compile(r"(?:BaseHTTPServer|http\.server).*?(?:os\.popen|subprocess)", re.DOTALL),
            re.compile(r"flask.*?os\.(system|popen)|os\.(system|popen).*?flask", re.DOTALL),
            re.compile(r"@app\.route.*?(?:exec|eval|os\.system|subprocess)", re.DOTALL),
        ],
        condition="any",
        tags=["webshell", "python"],
    ),
    YaraRule(
        "YR2", "PHP Webshell", "critical",
        "PHP web shell pattern in project files",
        [
            re.compile(r"<\?php.*?(?:\$_(?:GET|POST|REQUEST)\[.*?\]).*?(?:exec|system|passthru|shell_exec|eval)", re.DOTALL),
            re.compile(r"(?:exec|system|passthru|shell_exec)\s*\(\s*\$_(?:GET|POST|REQUEST)", re.MULTILINE),
        ],
        condition="any",
        tags=["webshell", "php"],
    ),
    YaraRule(
        "YR2", "JS Webshell", "critical",
        "JavaScript/Node.js web shell pattern",
        [
            re.compile(r"require\s*\(\s*['\"]child_process['\"].*?(?:req\.(?:body|query|params))", re.DOTALL),
            re.compile(r"child_process.*?exec.*?req\.(body|query|params)", re.DOTALL),
        ],
        condition="any",
        tags=["webshell", "javascript"],
    ),
    YaraRule(
        "YR2", "File Upload Shell", "high",
        "Unrestricted file upload enabling code execution",
        [
            re.compile(r"upload.*?\.(?:php|phtml|phar|jsp|asp)", re.IGNORECASE),
            re.compile(r"move_uploaded_file|shutil\.move.*?upload", re.IGNORECASE),
            re.compile(r"(?:no|skip|bypass).*?(?:validation|check|filter).*?upload", re.IGNORECASE),
        ],
        condition="count", min_matches=2,
        tags=["webshell", "upload"],
    ),
]

# ---------------------------------------------------------------------------
# YR3: Cryptominer Patterns
# ---------------------------------------------------------------------------

_CRYPTOMINER_RULES = [
    YaraRule(
        "YR3", "Cryptominer Binary", "high",
        "Cryptocurrency mining binary or library reference",
        [
            re.compile(r"xmrig|cgminer|bfgminer|cpuminer|ethminer|nbminer", re.IGNORECASE),
            re.compile(r"stratum\+tcp://|stratum\+ssl://", re.IGNORECASE),
            re.compile(r"monero|XMR|ethereum|ETH.*?mining|mining.*?(?:pool|proxy)", re.IGNORECASE),
        ],
        condition="any",
        tags=["cryptominer"],
    ),
    YaraRule(
        "YR3", "Mining Pool Connection", "high",
        "Connection to known cryptocurrency mining pools",
        [
            re.compile(r"(?:pool\.|mine\.|mining\.).*?(?:\.com|\.io|\.org|\.net)(?::\d+)?", re.IGNORECASE),
            re.compile(r"(?:nanopool|f2pool|antpool|minergate|nicehash|hashvault|supportxmr)", re.IGNORECASE),
            re.compile(r"4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}", re.MULTILINE),  # Monero address
        ],
        condition="count", min_matches=2,
        tags=["cryptominer", "pool"],
    ),
    YaraRule(
        "YR3", "Browser-based Miner", "high",
        "In-browser cryptocurrency mining (cryptojacking)",
        [
            re.compile(r"coinhive|cryptonight|CoinIMP|WebMinePool", re.IGNORECASE),
            re.compile(r"wasm.*?(?:mine|hash|crypto)|(?:mine|hash|crypto).*?wasm", re.IGNORECASE),
        ],
        condition="any",
        tags=["cryptominer", "browser"],
    ),
]

# ---------------------------------------------------------------------------
# YR4: Hack Tools / Exploit Code
# ---------------------------------------------------------------------------

_HACKTOOL_RULES = [
    YaraRule(
        "YR4", "Network Scanner", "high",
        "Network scanning/enumeration tool pattern",
        [
            re.compile(r"(?:nmap|masscan|zmap).*?(?:scan|port)", re.IGNORECASE),
            re.compile(r"for\s+port\s+in.*?(?:socket\.connect|connect_ex)", re.DOTALL),
            re.compile(r"(?:scan|enum).*?(?:subnet|range|CIDR|/24|/16)", re.IGNORECASE),
        ],
        condition="count", min_matches=2,
        tags=["hacktool", "scanner"],
    ),
    YaraRule(
        "YR4", "Privilege Escalation", "high",
        "Local privilege escalation exploit pattern",
        [
            re.compile(r"(?:priv.*?esc|escalat).*?(?:root|admin|SYSTEM)", re.IGNORECASE),
            re.compile(r"SUID|setuid|sudo.*?NOPASSWD|/etc/sudoers", re.MULTILINE),
            re.compile(r"CVE-\d{4}-\d+.*?(?:exploit|payload|shell)", re.IGNORECASE),
        ],
        condition="count", min_matches=2,
        tags=["hacktool", "privesc"],
    ),
    YaraRule(
        "YR4", "Password Cracker", "high",
        "Password cracking or brute-force tool",
        [
            re.compile(r"(?:hashcat|john|hydra|medusa|brutus)", re.IGNORECASE),
            re.compile(r"brute.?force.*?(?:password|login|auth)", re.IGNORECASE),
            re.compile(r"wordlist|rockyou|dictionary.*?attack", re.IGNORECASE),
        ],
        condition="count", min_matches=2,
        tags=["hacktool", "cracker"],
    ),
    YaraRule(
        "YR4", "SQL Injection Tool", "high",
        "SQL injection exploitation pattern",
        [
            re.compile(r"(?:sqlmap|havij|sqli)", re.IGNORECASE),
            re.compile(r"(?:UNION\s+SELECT|OR\s+1\s*=\s*1|'\s*OR\s*')", re.IGNORECASE),
            re.compile(r"(?:inject|sqli).*?(?:payload|exploit|bypass)", re.IGNORECASE),
        ],
        condition="count", min_matches=2,
        tags=["hacktool", "sqli"],
    ),
    YaraRule(
        "YR4", "Credential Dumper", "critical",
        "Credential dumping tool (mimikatz-like)",
        [
            re.compile(r"mimikatz|sekurlsa|lsadump|wdigest", re.IGNORECASE),
            re.compile(r"SAM.*?(?:dump|extract|hash)|(?:dump|extract).*?SAM", re.IGNORECASE),
            re.compile(r"NTLM|LM\s*hash|pass.the.hash", re.IGNORECASE),
        ],
        condition="count", min_matches=2,
        tags=["hacktool", "credential_dump"],
    ),
    YaraRule(
        "YR4", "Ransomware Pattern", "critical",
        "File encryption with ransom/payment indicators",
        [
            re.compile(r"(?:encrypt|cipher).*?(?:all|files|documents|folder)", re.IGNORECASE),
            re.compile(r"(?:ransom|bitcoin|BTC|payment|wallet).*?(?:decrypt|key|unlock)", re.IGNORECASE),
            re.compile(r"\.encrypted|\.locked|\.ransom|README.*?(?:decrypt|pay)", re.IGNORECASE),
        ],
        condition="count", min_matches=2,
        tags=["malware", "ransomware"],
    ),
]

# All rules combined
ALL_RULES = _MALWARE_RULES + _WEBSHELL_RULES + _CRYPTOMINER_RULES + _HACKTOOL_RULES


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_file(file_path: Path) -> List[Dict[str, Any]]:
    """Scan a file against all YARA-like rules."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    findings = []
    for rule in ALL_RULES:
        result = rule.match(content)
        if result:
            result["file"] = str(file_path)
            findings.append(result)

    return findings


def analyze_directory(dir_path: Path) -> List[Dict[str, Any]]:
    """Scan all relevant files in a directory."""
    findings = []
    # Scan code files
    extensions = {".py", ".js", ".ts", ".sh", ".bash", ".php", ".rb",
                  ".pl", ".ps1", ".bat", ".cmd", ".vbs"}

    for f in dir_path.rglob("*"):
        if f.is_file() and f.suffix in extensions:
            findings.extend(analyze_file(f))

    return findings


# ---------------------------------------------------------------------------
# CLI interface
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    if len(sys.argv) < 2:
        print("Usage: python3 yara_patterns.py <path>", file=sys.stderr)
        sys.exit(2)

    target = Path(sys.argv[1])
    if target.is_file():
        results = analyze_file(target)
    elif target.is_dir():
        results = analyze_directory(target)
    else:
        print(f"Error: {target} not found", file=sys.stderr)
        sys.exit(2)

    print(json.dumps(results, indent=2))
    sys.exit(1 if results else 0)
