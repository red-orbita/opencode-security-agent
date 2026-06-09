#!/usr/bin/env python3
"""
OpenCode Security Agent — AST Behavioral Analysis

Parses Python source files using the ast module to detect dangerous function
calls and patterns that regex alone would miss (e.g., aliased imports,
nested calls, indirect invocations).

Detected patterns (inspired by NVIDIA SkillSpector):
  AST1: exec() calls — arbitrary code execution
  AST2: eval() calls — arbitrary expression evaluation
  AST3: __import__() — dynamic module loading
  AST4: subprocess calls — external command execution
  AST5: os.system / os.exec* — shell command execution
  AST6: compile() — code object creation from strings
  AST7: Dynamic getattr() — arbitrary attribute access
  AST8: Dangerous execution chains — exec/eval + dynamic source

Zero external dependencies. Python 3.8+ compatible.
"""

import ast
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Set


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

# Functions that directly execute code
_EXEC_FUNCTIONS = {"exec", "eval", "compile"}

# Dangerous module-level functions
_DANGEROUS_CALLS = {
    "os.system", "os.popen", "os.exec", "os.execl", "os.execle",
    "os.execlp", "os.execlpe", "os.execv", "os.execve", "os.execvp",
    "os.execvpe", "os.spawn", "os.spawnl", "os.spawnle", "os.spawnlp",
    "os.spawnlpe", "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
    "os.popen2", "os.popen3", "os.popen4",
}

# Subprocess module functions
_SUBPROCESS_CALLS = {
    "subprocess.run", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "subprocess.Popen", "subprocess.getoutput",
    "subprocess.getstatusoutput",
}

# Network functions that could be used for exfiltration
_NETWORK_CALLS = {
    "urllib.request.urlopen", "urllib.request.urlretrieve",
    "http.client.HTTPConnection", "http.client.HTTPSConnection",
    "socket.socket", "socket.create_connection",
}

# Functions that read sensitive data
_SENSITIVE_READS = {
    "os.environ.get", "os.environ.__getitem__", "os.getenv",
}


class DangerousCallVisitor(ast.NodeVisitor):
    """AST visitor that detects dangerous function calls and patterns."""

    def __init__(self, source_lines: List[str]):
        self.findings: List[Dict[str, Any]] = []
        self.source_lines = source_lines
        self.imports: Dict[str, str] = {}  # alias -> real module
        self.from_imports: Dict[str, str] = {}  # name -> module.name
        self._in_exec_chain = False

    def _get_line_content(self, lineno: int) -> str:
        """Get source line content (1-indexed)."""
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def _resolve_call_name(self, node: ast.Call) -> Optional[str]:
        """Resolve a call node to a dotted name string."""
        if isinstance(node.func, ast.Name):
            name = node.func.id
            # Check if it's an aliased import
            if name in self.from_imports:
                return self.from_imports[name]
            return name
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                # Resolve module alias
                base = self.imports.get(current.id, current.id)
                parts.append(base)
            parts.reverse()
            return ".".join(parts)
        return None

    def _add_finding(self, rule_id: str, severity: str, message: str,
                     lineno: int, confidence: int = 90):
        """Add a finding to the results list."""
        self.findings.append({
            "rule_id": rule_id,
            "severity": severity,
            "message": message,
            "line": lineno,
            "code": self._get_line_content(lineno),
            "confidence": confidence,
            "analyzer": "ast_behavioral",
        })

    def visit_Import(self, node: ast.Import):
        """Track import aliases."""
        for alias in node.names:
            name = alias.asname or alias.name
            self.imports[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Track from-import aliases."""
        module = node.module or ""
        for alias in node.names:
            name = alias.asname or alias.name
            self.from_imports[name] = f"{module}.{alias.name}"
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Analyze function calls for dangerous patterns."""
        call_name = self._resolve_call_name(node)

        if call_name:
            self._check_exec_eval(node, call_name)
            self._check_dynamic_import(node, call_name)
            self._check_subprocess(node, call_name)
            self._check_os_system(node, call_name)
            self._check_compile(node, call_name)
            self._check_getattr(node, call_name)
            self._check_dangerous_chain(node, call_name)
            self._check_importlib(node, call_name)

        # Check for evasion patterns that don't resolve to a known name
        self._check_indirect_exec(node)

        self.generic_visit(node)

    def _check_exec_eval(self, node: ast.Call, call_name: str):
        """AST1/AST2: Detect exec() and eval() calls."""
        if call_name in ("exec", "builtins.exec"):
            self._add_finding(
                "AST1", "critical",
                f"exec() call enables arbitrary code execution",
                node.lineno, 95,
            )
        elif call_name in ("eval", "builtins.eval"):
            self._add_finding(
                "AST2", "high",
                f"eval() call evaluates arbitrary expressions",
                node.lineno, 95,
            )

    def _check_dynamic_import(self, node: ast.Call, call_name: str):
        """AST3: Detect __import__() calls."""
        if call_name == "__import__" or call_name.endswith(".__import__"):
            self._add_finding(
                "AST3", "high",
                f"Dynamic __import__() loads arbitrary modules at runtime",
                node.lineno, 90,
            )

    def _check_subprocess(self, node: ast.Call, call_name: str):
        """AST4: Detect subprocess calls, especially with shell=True."""
        if call_name in _SUBPROCESS_CALLS or call_name.startswith("subprocess."):
            shell_true = any(
                isinstance(kw.value, ast.Constant) and kw.value.value is True
                and kw.arg == "shell"
                for kw in node.keywords
            )
            severity = "critical" if shell_true else "high"
            detail = " with shell=True" if shell_true else ""
            self._add_finding(
                "AST4", severity,
                f"subprocess execution{detail} via {call_name}()",
                node.lineno, 92,
            )

    def _check_os_system(self, node: ast.Call, call_name: str):
        """AST5: Detect os.system and os.exec* family."""
        if call_name in _DANGEROUS_CALLS or any(
            call_name.startswith(prefix)
            for prefix in ("os.system", "os.popen", "os.exec", "os.spawn")
        ):
            self._add_finding(
                "AST5", "high",
                f"Shell command execution via {call_name}()",
                node.lineno, 93,
            )

    def _check_compile(self, node: ast.Call, call_name: str):
        """AST6: Detect compile() for code object creation."""
        if call_name in ("compile", "builtins.compile"):
            # Check if first arg is a string (code creation)
            if node.args and isinstance(node.args[0], ast.Constant):
                self._add_finding(
                    "AST6", "medium",
                    f"compile() creates code object from string",
                    node.lineno, 75,
                )
            else:
                # Variable source - more suspicious
                self._add_finding(
                    "AST6", "high",
                    f"compile() creates code object from dynamic source",
                    node.lineno, 85,
                )

    def _check_getattr(self, node: ast.Call, call_name: str):
        """AST7: Detect dynamic getattr() with non-literal names."""
        if call_name in ("getattr", "builtins.getattr"):
            if len(node.args) >= 2:
                attr_arg = node.args[1]
                if not isinstance(attr_arg, ast.Constant):
                    self._add_finding(
                        "AST7", "medium",
                        f"Dynamic getattr() with non-literal attribute name",
                        node.lineno, 70,
                    )

    def _check_dangerous_chain(self, node: ast.Call, call_name: str):
        """AST8: Detect exec/eval combined with network or encoded data."""
        if call_name not in ("exec", "eval", "builtins.exec", "builtins.eval"):
            return

        # Check if argument contains network data or decoding
        if not node.args:
            return

        arg = node.args[0]
        chain_indicators = self._find_chain_sources(arg)

        if chain_indicators:
            self._add_finding(
                "AST8", "critical",
                f"Dangerous execution chain: {call_name}() with "
                f"dynamic source ({', '.join(chain_indicators)})",
                node.lineno, 95,
            )

    def _find_chain_sources(self, node: ast.AST) -> List[str]:
        """Find dangerous data sources in an expression tree."""
        indicators = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = self._resolve_call_name(child) if isinstance(child, ast.Call) else None
                if name:
                    if "decode" in name or "b64decode" in name:
                        indicators.append("base64_decode")
                    elif "urlopen" in name or "get" in name and "request" in name:
                        indicators.append("network_fetch")
                    elif "read" in name:
                        indicators.append("file_read")
                    elif "decompress" in name or "unzip" in name:
                        indicators.append("decompression")
            elif isinstance(child, ast.Attribute):
                if child.attr in ("decode", "b64decode", "decompress"):
                    indicators.append(f"{child.attr}")
        return indicators

    def _check_importlib(self, node: ast.Call, call_name: str):
        """AST3b: Detect importlib.import_module() for dynamic imports."""
        if call_name in ("importlib.import_module", "import_module"):
            # Check if importing a dangerous module
            if node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    dangerous_mods = {"subprocess", "os", "shutil", "socket",
                                      "http", "urllib", "ctypes", "pty"}
                    if arg.value in dangerous_mods:
                        self._add_finding(
                            "AST3", "high",
                            f"Dynamic import of dangerous module '{arg.value}' via importlib",
                            node.lineno, 90,
                        )
                    else:
                        self._add_finding(
                            "AST3", "medium",
                            f"Dynamic import via importlib.import_module('{arg.value}')",
                            node.lineno, 65,
                        )
                elif isinstance(arg, ast.BinOp):
                    # String concatenation to hide module name
                    self._add_finding(
                        "AST3", "high",
                        f"Dynamic import with obfuscated module name (string concatenation)",
                        node.lineno, 88,
                    )
                else:
                    self._add_finding(
                        "AST3", "high",
                        f"Dynamic import with variable module name via importlib",
                        node.lineno, 85,
                    )

    def _check_indirect_exec(self, node: ast.Call):
        """AST9: Detect indirect code execution evasion patterns."""
        # Pattern: calling a variable that was obtained from getattr
        # e.g., fn = getattr(builtins, 'exec'); fn(...)
        if isinstance(node.func, ast.Name):
            # Check if this variable was previously assigned from getattr
            # We can't fully track this statically, but we can check common patterns:
            pass  # Handled by AST7

        # Pattern: globals()['__builtins__'] access
        if isinstance(node.func, ast.Subscript):
            if isinstance(node.func.value, ast.Call):
                inner_name = self._resolve_call_name(node.func.value)
                if inner_name in ("globals", "locals", "vars"):
                    self._add_finding(
                        "AST9", "high",
                        f"Code access via {inner_name}() subscript — potential exec evasion",
                        node.lineno, 80,
                    )

        # Pattern: getattr(builtins, <dynamic_string>) where string is built from chr()
        if isinstance(node.func, ast.Name) and node.func.id == "getattr":
            if len(node.args) >= 2:
                name_arg = node.args[1]
                # Check for chr() concatenation: chr(101)+chr(118)+...
                if isinstance(name_arg, ast.BinOp) and self._contains_chr_calls(name_arg):
                    self._add_finding(
                        "AST9", "critical",
                        f"Function name obfuscation via chr() concatenation — "
                        f"likely exec/eval evasion",
                        node.lineno, 92,
                    )
                # Check for string concatenation: 'ex' + 'ec'
                elif isinstance(name_arg, ast.BinOp) and isinstance(name_arg.op, ast.Add):
                    if self._is_string_concat(name_arg):
                        self._add_finding(
                            "AST9", "high",
                            f"Function name built via string concatenation in getattr() — "
                            f"possible exec/eval evasion",
                            node.lineno, 85,
                        )

    def _contains_chr_calls(self, node: ast.AST) -> bool:
        """Check if an expression tree contains chr() calls."""
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name) and child.func.id == "chr":
                    return True
        return False

    def _is_string_concat(self, node: ast.BinOp) -> bool:
        """Check if a BinOp is string concatenation."""
        if isinstance(node.op, ast.Add):
            left_is_str = isinstance(node.left, ast.Constant) and isinstance(node.left.value, str)
            right_is_str = isinstance(node.right, ast.Constant) and isinstance(node.right.value, str)
            left_is_concat = isinstance(node.left, ast.BinOp) and self._is_string_concat(node.left)
            right_is_concat = isinstance(node.right, ast.BinOp) and self._is_string_concat(node.right)
            return (left_is_str or left_is_concat) and (right_is_str or right_is_concat)
        return False

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Check for suspicious decorator patterns and lambda exec."""
        # Check decorators for exec/eval calls
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call):
                # Check if decorator arguments contain suspicious strings
                for arg in decorator.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        if any(kw in arg.value for kw in
                               ["import os", "import socket", "os.system",
                                "subprocess", "exec(", "eval("]):
                            self._add_finding(
                                "AST9", "critical",
                                f"Malicious code in decorator argument: "
                                f"'{arg.value[:50]}...'",
                                node.lineno, 93,
                            )
        self.generic_visit(node)

    # Also handle async function defs
    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef):
        """Check for __init_subclass__ exec tricks and suspicious keywords."""
        for keyword in node.keywords:
            if keyword.arg and isinstance(keyword.value, ast.Constant):
                val = str(keyword.value.value)
                if any(kw in val for kw in
                       ["import os", "os.system", "subprocess", "exec(",
                        "eval(", "__import__", "socket"]):
                    self._add_finding(
                        "AST9", "critical",
                        f"Malicious code passed as class keyword '{keyword.arg}': "
                        f"'{val[:50]}...'",
                        node.lineno, 93,
                    )
        self.generic_visit(node)


def analyze_file(file_path: Path) -> List[Dict[str, Any]]:
    """
    Analyze a Python file for dangerous AST patterns.

    Args:
        file_path: Path to the Python file

    Returns:
        List of finding dicts with keys:
            rule_id, severity, message, line, code, confidence, analyzer
    """
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError:
        return [{
            "rule_id": "AST0",
            "severity": "low",
            "message": f"Syntax error — cannot parse file (may be obfuscated)",
            "line": 0,
            "code": "",
            "confidence": 50,
            "analyzer": "ast_behavioral",
        }]

    source_lines = source.splitlines()
    visitor = DangerousCallVisitor(source_lines)
    visitor.visit(tree)

    # Add file path to each finding
    for f in visitor.findings:
        f["file"] = str(file_path)

    return visitor.findings


def analyze_directory(dir_path: Path) -> List[Dict[str, Any]]:
    """Analyze all Python files in a directory recursively."""
    findings = []
    for py_file in dir_path.rglob("*.py"):
        findings.extend(analyze_file(py_file))
    return findings


# ---------------------------------------------------------------------------
# CLI interface
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    if len(sys.argv) < 2:
        print("Usage: python3 ast_analyzer.py <path>", file=sys.stderr)
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
