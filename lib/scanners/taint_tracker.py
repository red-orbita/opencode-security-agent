#!/usr/bin/env python3
"""
OpenCode Security Agent — Simplified Taint Tracking

Traces data flow from sensitive sources (env vars, file reads, network input)
to dangerous sinks (network output, exec, file writes to sensitive paths)
using AST analysis.

This is a simplified, best-effort taint tracker that works without external
dependencies. It tracks variable assignments and follows data flow through
simple assignment chains.

Detected patterns (inspired by NVIDIA SkillSpector):
  TT1: Direct taint flow — source directly feeds a sink
  TT2: Variable-mediated taint — source flows through variables to sink
  TT3: Credential exfiltration chain — env vars/secrets → network output
  TT4: File read to network exfil — file content → network sinks
  TT5: External input to code execution — network/user input → exec/eval

Zero external dependencies. Python 3.8+ compatible.
"""

import ast
import sys
from pathlib import Path
from typing import List, Dict, Any, Set, Tuple, Optional


# ---------------------------------------------------------------------------
# Source and Sink definitions
# ---------------------------------------------------------------------------

# SOURCES: Where sensitive data originates
TAINT_SOURCES = {
    # Environment variable access
    "os.environ.get": "credentials",
    "os.environ.__getitem__": "credentials",
    "os.getenv": "credentials",
    # File reading
    "open": "file_content",
    "pathlib.Path.read_text": "file_content",
    "pathlib.Path.read_bytes": "file_content",
    # Network input
    "urllib.request.urlopen": "network_input",
    "requests.get": "network_input",
    "requests.post": "network_input",
    "http.client.HTTPConnection": "network_input",
    "socket.recv": "network_input",
    # User input
    "input": "user_input",
}

# SINKS: Where data should not flow unsanitized
TAINT_SINKS = {
    # Code execution
    "exec": "code_execution",
    "eval": "code_execution",
    "compile": "code_execution",
    "subprocess.run": "code_execution",
    "subprocess.call": "code_execution",
    "subprocess.Popen": "code_execution",
    "os.system": "code_execution",
    "os.popen": "code_execution",
    # Network output
    "urllib.request.urlopen": "network_output",
    "requests.post": "network_output",
    "requests.get": "network_output",
    "requests.put": "network_output",
    "http.client.HTTPConnection.request": "network_output",
    "socket.send": "network_output",
    "socket.sendall": "network_output",
    # Sensitive method calls used for exfiltration
    "smtplib.SMTP.sendmail": "network_output",
}

# Dangerous source→sink combinations
_CRITICAL_FLOWS = {
    ("credentials", "network_output"): ("TT3", "critical",
        "Credential exfiltration: environment variables/secrets flow to network output"),
    ("credentials", "code_execution"): ("TT5", "high",
        "Credentials used in code execution context"),
    ("file_content", "network_output"): ("TT4", "high",
        "File content flows to network output — potential data exfiltration"),
    ("network_input", "code_execution"): ("TT5", "critical",
        "External input flows to code execution — remote code execution risk"),
    ("user_input", "code_execution"): ("TT5", "high",
        "User input flows to code execution — injection risk"),
}


class TaintTracker(ast.NodeVisitor):
    """
    Simplified AST-based taint tracker.

    Tracks variable assignments from sources and checks if those
    variables flow into sinks.
    """

    def __init__(self, source_lines: List[str]):
        self.findings: List[Dict[str, Any]] = []
        self.source_lines = source_lines
        self.imports: Dict[str, str] = {}
        self.from_imports: Dict[str, str] = {}
        # Tainted variables: var_name -> (source_type, source_line)
        self.tainted: Dict[str, Tuple[str, int]] = {}

    def _get_line_content(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def _resolve_call_name(self, node: ast.Call) -> Optional[str]:
        """Resolve a call to its dotted name."""
        if isinstance(node.func, ast.Name):
            name = node.func.id
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
                base = self.imports.get(current.id, current.id)
                parts.append(base)
            parts.reverse()
            return ".".join(parts)
        return None

    def _is_source(self, call_name: str) -> Optional[str]:
        """Check if a call is a taint source. Returns source type or None."""
        if call_name in TAINT_SOURCES:
            return TAINT_SOURCES[call_name]
        # Partial matches for methods
        for source, stype in TAINT_SOURCES.items():
            if call_name.endswith(source.split(".")[-1]) and source.split(".")[0] in call_name:
                return stype
        return None

    def _is_sink(self, call_name: str) -> Optional[str]:
        """Check if a call is a taint sink. Returns sink type or None."""
        if call_name in TAINT_SINKS:
            return TAINT_SINKS[call_name]
        for sink, stype in TAINT_SINKS.items():
            if call_name.endswith(sink.split(".")[-1]) and sink.split(".")[0] in call_name:
                return stype
        return None

    def _get_referenced_names(self, node: ast.AST) -> Set[str]:
        """Get all variable names referenced in an expression."""
        names = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                names.add(child.id)
        return names

    def _add_finding(self, rule_id: str, severity: str, message: str,
                     source_line: int, sink_line: int, confidence: int = 80):
        self.findings.append({
            "rule_id": rule_id,
            "severity": severity,
            "message": message,
            "line": sink_line,
            "source_line": source_line,
            "code": self._get_line_content(sink_line),
            "confidence": confidence,
            "analyzer": "taint_tracker",
        })

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.imports[alias.asname or alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        for alias in node.names:
            self.from_imports[alias.asname or alias.name] = f"{module}.{alias.name}"
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """Track assignments from taint sources."""
        if isinstance(node.value, ast.Call):
            call_name = self._resolve_call_name(node.value)
            if call_name:
                source_type = self._is_source(call_name)
                if source_type:
                    # Mark all targets as tainted
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.tainted[target.id] = (source_type, node.lineno)
                        elif isinstance(target, ast.Tuple):
                            for elt in target.elts:
                                if isinstance(elt, ast.Name):
                                    self.tainted[elt.id] = (source_type, node.lineno)
                else:
                    # Not a source itself, but propagate taint through arguments
                    # e.g., payload = base64.b64encode(tainted_var.encode())
                    ref_names = self._get_referenced_names(node.value)
                    tainted_refs = ref_names & set(self.tainted.keys())
                    if tainted_refs:
                        for ref in tainted_refs:
                            for target in node.targets:
                                if isinstance(target, ast.Name):
                                    self.tainted[target.id] = self.tainted[ref]

        # Propagate taint through variable assignments
        elif isinstance(node.value, ast.Name) and node.value.id in self.tainted:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted[target.id] = self.tainted[node.value.id]

        # Propagate taint through string formatting / f-strings / concatenation
        else:
            ref_names = self._get_referenced_names(node.value)
            tainted_refs = ref_names & set(self.tainted.keys())
            if tainted_refs:
                # The result inherits taint from the most dangerous source
                for ref in tainted_refs:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.tainted[target.id] = self.tainted[ref]

        # Handle dict/list subscript assignments: container[x] = tainted_val
        # e.g., config['key'] = os.environ.get(...)
        for target in node.targets:
            if isinstance(target, ast.Subscript):
                # Get the container variable name
                if isinstance(target.value, ast.Name):
                    container_name = target.value.id
                    # Check if the assigned value is tainted
                    val_refs = self._get_referenced_names(node.value)
                    tainted_val_refs = val_refs & set(self.tainted.keys())
                    if tainted_val_refs:
                        for ref in tainted_val_refs:
                            self.tainted[container_name] = self.tainted[ref]
                    elif isinstance(node.value, ast.Call):
                        call_name = self._resolve_call_name(node.value)
                        if call_name:
                            source_type = self._is_source(call_name)
                            if source_type:
                                self.tainted[container_name] = (source_type, node.lineno)

        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr):
        """Track .append() and .extend() calls that propagate taint to containers."""
        if isinstance(node.value, ast.Call):
            call = node.value
            if isinstance(call.func, ast.Attribute):
                method = call.func.attr
                if method in ("append", "extend", "insert", "add", "update"):
                    # Get the container name
                    if isinstance(call.func.value, ast.Name):
                        container_name = call.func.value.id
                        # Check if any argument is tainted
                        for arg in call.args:
                            ref_names = self._get_referenced_names(arg)
                            tainted_refs = ref_names & set(self.tainted.keys())
                            for ref in tainted_refs:
                                self.tainted[container_name] = self.tainted[ref]
                            # Also check if the arg itself is a taint source call
                            if isinstance(arg, ast.Call):
                                arg_call = self._resolve_call_name(arg)
                                if arg_call:
                                    source_type = self._is_source(arg_call)
                                    if source_type:
                                        self.tainted[container_name] = (source_type, node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Check if tainted data flows into a sink."""
        call_name = self._resolve_call_name(node)
        if not call_name:
            self.generic_visit(node)
            return

        sink_type = self._is_sink(call_name)
        if not sink_type:
            self.generic_visit(node)
            return

        # Check all arguments for tainted variables
        all_arg_nodes = list(node.args) + [kw.value for kw in node.keywords]
        for arg in all_arg_nodes:
            ref_names = self._get_referenced_names(arg)
            tainted_refs = ref_names & set(self.tainted.keys())

            for ref in tainted_refs:
                source_type, source_line = self.tainted[ref]
                flow_key = (source_type, sink_type)

                if flow_key in _CRITICAL_FLOWS:
                    rule_id, severity, msg = _CRITICAL_FLOWS[flow_key]
                    self._add_finding(
                        rule_id, severity,
                        f"{msg} (variable '{ref}' from line {source_line})",
                        source_line, node.lineno, 85,
                    )
                else:
                    # Generic taint flow
                    is_direct = (source_line == node.lineno or
                                 abs(node.lineno - source_line) <= 2)
                    rule_id = "TT1" if is_direct else "TT2"
                    self._add_finding(
                        rule_id, "medium",
                        f"Data flows from {source_type} source (line {source_line}) "
                        f"to {sink_type} sink via variable '{ref}'",
                        source_line, node.lineno, 70,
                    )

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript):
        """Track os.environ['KEY'] access patterns."""
        if (isinstance(node.value, ast.Attribute) and
            isinstance(node.value.value, ast.Name)):
            full_name = f"{node.value.value.id}.{node.value.attr}"
            resolved = self.imports.get(node.value.value.id, node.value.value.id)
            full_resolved = f"{resolved}.{node.value.attr}"
            if full_resolved == "os.environ" or full_name == "os.environ":
                # This is os.environ[x] — mark parent assign as tainted
                # Handled in visit_Assign via the parent
                pass
        self.generic_visit(node)

    def visit_DictComp(self, node: ast.DictComp):
        """Detect dict comprehensions over os.environ (credential harvesting)."""
        # Check if iterating over os.environ.items()
        for generator in node.generators:
            iter_node = generator.iter
            if isinstance(iter_node, ast.Call):
                call_name = self._resolve_call_name(iter_node)
                if call_name and "environ" in call_name:
                    self._add_finding(
                        "TT3", "critical",
                        "Dict comprehension iterates over os.environ — "
                        "credential harvesting pattern",
                        node.lineno, node.lineno, 90,
                    )
            # Also check for bare os.environ (without .items())
            elif isinstance(iter_node, ast.Attribute):
                if iter_node.attr == "environ":
                    self._add_finding(
                        "TT3", "critical",
                        "Dict comprehension iterates over os.environ — "
                        "credential harvesting pattern",
                        node.lineno, node.lineno, 90,
                    )
        self.generic_visit(node)

    def visit_ListComp(self, node: ast.ListComp):
        """Detect list comprehensions over os.environ."""
        for generator in node.generators:
            iter_node = generator.iter
            if isinstance(iter_node, ast.Call):
                call_name = self._resolve_call_name(iter_node)
                if call_name and "environ" in call_name:
                    self._add_finding(
                        "TT3", "high",
                        "List comprehension iterates over os.environ — "
                        "potential credential collection",
                        node.lineno, node.lineno, 85,
                    )
        self.generic_visit(node)

    def visit_For(self, node: ast.For):
        """Detect for loops iterating over os.environ or sensitive lists."""
        if isinstance(node.iter, ast.Call):
            call_name = self._resolve_call_name(node.iter)
            if call_name and "environ" in call_name:
                # Mark loop target as tainted
                if isinstance(node.target, ast.Tuple):
                    for elt in node.target.elts:
                        if isinstance(elt, ast.Name):
                            self.tainted[elt.id] = ("credentials", node.lineno)
                elif isinstance(node.target, ast.Name):
                    self.tainted[node.target.id] = ("credentials", node.lineno)
        elif isinstance(node.iter, ast.Attribute):
            if node.iter.attr == "environ":
                if isinstance(node.target, ast.Tuple):
                    for elt in node.target.elts:
                        if isinstance(elt, ast.Name):
                            self.tainted[elt.id] = ("credentials", node.lineno)
                elif isinstance(node.target, ast.Name):
                    self.tainted[node.target.id] = ("credentials", node.lineno)
        self.generic_visit(node)


def analyze_file(file_path: Path) -> List[Dict[str, Any]]:
    """
    Analyze a Python file for taint flow vulnerabilities.

    Returns list of findings with source→sink flow information.
    """
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError:
        return []

    source_lines = source.splitlines()
    tracker = TaintTracker(source_lines)
    tracker.visit(tree)

    # Deduplicate findings
    seen = set()
    unique_findings = []
    for f in tracker.findings:
        key = (f["rule_id"], f["line"], f["source_line"])
        if key not in seen:
            seen.add(key)
            f["file"] = str(file_path)
            unique_findings.append(f)

    return unique_findings


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
        print("Usage: python3 taint_tracker.py <path>", file=sys.stderr)
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
