"""
OpenCode Security Agent — Advanced Scanners Package

Inspired by NVIDIA SkillSpector, these modules provide deep static analysis
for AI agent skills and MCP servers. All modules use Python stdlib only
(zero external dependencies) and are designed for pre-installation scanning.

Modules:
  - ast_analyzer:      AST-based behavioral analysis (exec, eval, subprocess, etc.)
  - taint_tracker:     Simplified source→sink data flow tracking
  - mcp_privilege:     MCP least privilege validation
  - mcp_poisoning:     MCP tool poisoning detection
  - agent_signatures:  AI agent ecosystem attack signatures (AG1-AG8)
  - osv_checker:       OSV.dev live CVE lookup for dependencies
  - yara_patterns:     YARA-like malware signature detection (pure regex)
  - risk_scorer:       Formal risk scoring (0-100)
"""

__version__ = "1.1.0"
