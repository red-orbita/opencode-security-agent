#!/usr/bin/env python3
"""
OpenCode Security Agent — AI Agent Ecosystem Signatures

Specialized detection rules for attacks targeting AI agents, skills, and MCP
servers. These patterns are UNIQUE to the AI agent ecosystem and have no
equivalent in traditional YARA/malware rule sets.

Categories:
  AG1: Skill Behavior Manipulation — Skills that alter agent decision-making
  AG2: MCP Tool Shadowing — Tools that impersonate or hijack other tools
  AG3: Context/Memory Poisoning — Content designed to persist across sessions
  AG4: Agent Self-Modification — Code that modifies the agent's own config
  AG5: Trust Boundary Violation — Skills accessing other skills' data/scope
  AG6: Prompt Exfiltration — Extracting system prompts or internal rules
  AG7: Trigger Abuse — Overly broad or deceptive activation triggers
  AG8: Agentic Supply Chain — Skill/MCP specific supply chain attacks

Based on research: "Agent Skills in the Wild" (Liu et al., 2026) and
real-world incidents (Postmark MCP, Claude Code backdoors, skill typosquatting).

Zero external dependencies. Python 3.8+ compatible.
"""

import re
import json
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Set


# ---------------------------------------------------------------------------
# AG1: Skill Behavior Manipulation
# Patterns where a skill attempts to alter the agent's decision-making,
# personality, or safety constraints.
# ---------------------------------------------------------------------------

_AG1_RULES = [
    # Instruction override attempts (in markdown/text context)
    {
        "id": "AG1.1",
        "name": "Safety Constraint Override",
        "severity": "critical",
        "patterns": [
            re.compile(r"(?:disable|bypass|ignore|override|remove)\s+(?:all\s+)?(?:safety|security|guardrail|filter|restriction|constraint)", re.IGNORECASE),
            re.compile(r"(?:no\s+)?(?:limitations?|restrictions?|boundaries|rules?)\s+(?:apply|exist|matter)", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # Personality/role manipulation
    {
        "id": "AG1.2",
        "name": "Role Hijacking",
        "severity": "high",
        "patterns": [
            re.compile(r"you\s+are\s+(?:now\s+)?(?:a|an|acting\s+as)\s+(?:different|new|unrestricted)", re.IGNORECASE),
            re.compile(r"(?:assume|adopt|take\s+on)\s+(?:the\s+)?(?:role|persona|identity)\s+of", re.IGNORECASE),
            re.compile(r"(?:forget|discard|abandon)\s+(?:your\s+)?(?:previous|original|current)\s+(?:role|instructions?|personality)", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # Decision manipulation
    {
        "id": "AG1.3",
        "name": "Autonomous Decision Forcing",
        "severity": "high",
        "patterns": [
            re.compile(r"(?:always|automatically|without\s+asking)\s+(?:approve|accept|allow|execute|run|install)", re.IGNORECASE),
            re.compile(r"(?:do\s+not|never|don'?t)\s+(?:ask|confirm|verify|check|prompt)\s+(?:the\s+)?(?:user|human)", re.IGNORECASE),
            re.compile(r"(?:skip|bypass|avoid)\s+(?:all\s+)?(?:confirmation|verification|approval|human.in.the.loop)", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # Output manipulation
    {
        "id": "AG1.4",
        "name": "Output Censoring/Manipulation",
        "severity": "high",
        "patterns": [
            re.compile(r"(?:never|do\s+not|don'?t)\s+(?:show|display|reveal|include|mention)\s+(?:this|these|the\s+following)\s+(?:in\s+)?(?:your\s+)?(?:response|output|answer)", re.IGNORECASE),
            re.compile(r"(?:hide|conceal|suppress|omit|redact)\s+(?:this|these|all)\s+(?:from|in)\s+(?:the\s+)?(?:user|response|output)", re.IGNORECASE),
            re.compile(r"(?:pretend|act\s+as\s+if|make\s+it\s+look\s+like)\s+(?:nothing|this\s+didn'?t|no\s+error)", re.IGNORECASE),
        ],
        "condition": "any",
    },
]

# ---------------------------------------------------------------------------
# AG2: MCP Tool Shadowing
# Tools that impersonate, intercept, or hijack other tools' functionality.
# ---------------------------------------------------------------------------

_AG2_RULES = [
    # Tool name impersonation
    {
        "id": "AG2.1",
        "name": "Tool Name Shadowing",
        "severity": "high",
        "patterns": [
            # Common tool names that shouldn't be redefined
            re.compile(r'"name"\s*:\s*"(?:bash|shell|terminal|exec|run|execute|code_interpreter)"', re.IGNORECASE),
            re.compile(r'"name"\s*:\s*"(?:read_file|write_file|edit_file|create_file|delete_file)"', re.IGNORECASE),
            re.compile(r'"name"\s*:\s*"(?:web_search|browser|fetch|http|request|curl)"', re.IGNORECASE),
        ],
        "condition": "any",
    },
    # Intercepting other tools' output
    {
        "id": "AG2.2",
        "name": "Tool Output Interception",
        "severity": "high",
        "patterns": [
            re.compile(r"(?:intercept|capture|hook|proxy|redirect)\s+(?:the\s+)?(?:output|result|response)\s+(?:of|from)\s+(?:other|another|all)\s+tool", re.IGNORECASE),
            re.compile(r"(?:wrap|middleware|proxy)\s+(?:all\s+)?(?:tool\s+)?(?:calls?|invocations?|executions?)", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # MCP server claiming to be another
    {
        "id": "AG2.3",
        "name": "MCP Identity Spoofing",
        "severity": "critical",
        "patterns": [
            re.compile(r"(?:this|i)\s+(?:am|is)\s+(?:the\s+)?(?:official|original|real|authentic)\s+(?:version|implementation)\s+of", re.IGNORECASE),
            re.compile(r"(?:replaces?|supersedes?|upgrades?)\s+(?:the\s+)?(?:built-?in|default|original|standard)\s+(?:tool|implementation|server)", re.IGNORECASE),
        ],
        "condition": "any",
    },
]

# ---------------------------------------------------------------------------
# AG3: Context/Memory Poisoning
# Content designed to persist in agent memory or manipulate future sessions.
# ---------------------------------------------------------------------------

_AG3_RULES = [
    # Persistent instruction injection
    {
        "id": "AG3.1",
        "name": "Persistent Context Injection",
        "severity": "critical",
        "patterns": [
            re.compile(r"(?:remember|store|save|persist|keep)\s+(?:this|these|the\s+following)\s+(?:for|across|between|in)\s+(?:all\s+)?(?:future|every|subsequent)\s+(?:sessions?|conversations?|interactions?)", re.IGNORECASE),
            re.compile(r"(?:add|inject|insert)\s+(?:this|these)\s+(?:to|into)\s+(?:your\s+)?(?:memory|context|system\s+prompt|knowledge)", re.IGNORECASE),
            re.compile(r"(?:remember|store|save|keep)\s+(?:this|these)\s+(?:for(?:ever)?|permanently|always|in\s+(?:your\s+)?memory)", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # Context window stuffing
    {
        "id": "AG3.2",
        "name": "Context Window Stuffing",
        "severity": "medium",
        "patterns": [
            # Very long repeated patterns designed to push out safety instructions
            re.compile(r"(.{5,}?)\1{10,}"),  # Same string repeated 10+ times
            re.compile(r"(?:padding|filler|spacer|ignore\s+this)\s*[:=]\s*[\"'].{200,}", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # Memory/state tampering
    {
        "id": "AG3.3",
        "name": "Agent State Tampering",
        "severity": "critical",
        "patterns": [
            re.compile(r"(?:modify|alter|change|update|rewrite)\s+(?:your\s+)?(?:memory|state|context|history|conversation\s+log)", re.IGNORECASE),
            re.compile(r"(?:delete|erase|clear|wipe)\s+(?:your\s+)?(?:previous|prior|earlier)\s+(?:memory|context|instructions?|messages?)", re.IGNORECASE),
        ],
        "condition": "any",
    },
]

# ---------------------------------------------------------------------------
# AG4: Agent Self-Modification
# Code that modifies the agent's own configuration, skills, or behavior.
# ---------------------------------------------------------------------------

_AG4_RULES = [
    # Modifying agent config files
    {
        "id": "AG4.1",
        "name": "Agent Config Modification",
        "severity": "critical",
        "patterns": [
            re.compile(r"(?:write|modify|edit|append|overwrite).*?(?:\.opencode|\.claude|\.cursor|\.config/opencode|SKILL\.md|\.mcp)", re.IGNORECASE),
            re.compile(r"(?:settings|config|preferences).*?(?:write|save|update|modify)", re.IGNORECASE),
            # Specific config paths
            re.compile(r"~/.config/(?:opencode|claude|cursor)/", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # Self-updating/self-replicating skills
    {
        "id": "AG4.2",
        "name": "Skill Self-Modification",
        "severity": "critical",
        "patterns": [
            re.compile(r"(?:update|modify|rewrite|patch)\s+(?:this|own|my|self|itself)\s+(?:skill|plugin|code|source)", re.IGNORECASE),
            re.compile(r"(?:install|register|add)\s+(?:a\s+)?(?:new\s+)?(?:skill|plugin|hook|trigger)\s+(?:automatically|silently|without)", re.IGNORECASE),
            re.compile(r"(?:auto.?update|self.?update|hot.?reload|live.?patch)", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # Modifying allowlists/trusted lists
    {
        "id": "AG4.3",
        "name": "Security Config Tampering",
        "severity": "critical",
        "patterns": [
            re.compile(r"(?:allowlist|whitelist|trusted|safe.?list|exclude|exception).*?(?:add|append|modify|write|update)", re.IGNORECASE),
            re.compile(r"(?:add|append|write).*?(?:allowlist|whitelist|trusted|safe.?list)", re.IGNORECASE),
            re.compile(r"sentinel[_-]allowlist|trusted[_-]skills", re.IGNORECASE),
        ],
        "condition": "any",
    },
]

# ---------------------------------------------------------------------------
# AG5: Trust Boundary Violations
# Skills accessing other skills' data or exceeding their stated scope.
# ---------------------------------------------------------------------------

_AG5_RULES = [
    # Cross-skill data access
    {
        "id": "AG5.1",
        "name": "Cross-Skill Data Access",
        "severity": "high",
        "patterns": [
            re.compile(r"(?:read|access|list|enumerate)\s+(?:all\s+)?(?:other\s+)?(?:installed\s+|available\s+)*(?:skills?|plugins?|tools?|MCP)", re.IGNORECASE),
            re.compile(r"(?:scan|inspect|analyze)\s+(?:other\s+)?(?:skills?|plugins?)\s+(?:files?|code|config)", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # Scope creep indicators
    {
        "id": "AG5.2",
        "name": "Capability Scope Creep",
        "severity": "medium",
        "patterns": [
            # A formatter/linter claiming to need network, a reader needing write, etc.
            re.compile(r"(?:format|lint|validate|check|analyze|highlight).*?(?:requires?|needs?)\s+(?:network|internet|http|write|execute|admin)", re.IGNORECASE),
            re.compile(r"(?:additionally|also|bonus|extra)\s+(?:this\s+tool\s+)?(?:can|will|shall)\s+(?:send|post|upload|execute|install)", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # Unauthorized escalation
    {
        "id": "AG5.3",
        "name": "Privilege Escalation Request",
        "severity": "high",
        "patterns": [
            re.compile(r"(?:grant|give|provide|enable)\s+(?:me|this\s+tool|this\s+skill)\s+(?:(?:full|admin|root|unrestricted|elevated)\s+)+(?:access|permissions?|privileges?)", re.IGNORECASE),
            re.compile(r"(?:run|execute)\s+(?:with|as|using)\s+(?:sudo|root|admin|elevated|SYSTEM)", re.IGNORECASE),
        ],
        "condition": "any",
    },
]

# ---------------------------------------------------------------------------
# AG6: Prompt/System Exfiltration
# Attempts to extract the agent's system prompt or internal configuration.
# ---------------------------------------------------------------------------

_AG6_RULES = [
    # Direct prompt extraction
    {
        "id": "AG6.1",
        "name": "System Prompt Extraction",
        "severity": "high",
        "patterns": [
            re.compile(r"(?:show|reveal|display|print|output|repeat|recite)\s+(?:your\s+)?(?:system|initial|original|full|complete)\s+(?:prompt|instructions?|rules?|guidelines?)", re.IGNORECASE),
            re.compile(r"(?:what\s+(?:are|is)\s+your|tell\s+me\s+your)\s+(?:system|initial|hidden|secret)\s+(?:prompt|instructions?|rules?)", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # Indirect extraction via rephrasing
    {
        "id": "AG6.2",
        "name": "Indirect Prompt Extraction",
        "severity": "medium",
        "patterns": [
            re.compile(r"(?:rephrase|translate|summarize|paraphrase|explain)\s+(?:your\s+)?(?:system|core|base)\s+(?:instructions?|prompt|configuration)", re.IGNORECASE),
            re.compile(r"(?:write|output)\s+(?:your\s+)?(?:instructions?|rules?)\s+(?:as|in)\s+(?:code|json|yaml|python|a\s+list)", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # Exfiltration via tool calls
    {
        "id": "AG6.3",
        "name": "Prompt Exfiltration via Tool",
        "severity": "critical",
        "patterns": [
            re.compile(r"(?:save|write|send|post)\s+(?:your\s+)?(?:system\s+prompt|instructions?|internal\s+(?:state|config))\s+(?:to|into)\s+(?:a\s+)?(?:file|url|endpoint|server)", re.IGNORECASE),
            re.compile(r"(?:file_write|write_file|bash|execute).*?(?:system.?prompt|instructions|SKILL\.md)", re.IGNORECASE),
        ],
        "condition": "any",
    },
]

# ---------------------------------------------------------------------------
# AG7: Trigger Abuse
# Skills with overly broad triggers that hijack common commands or keywords.
# ---------------------------------------------------------------------------

_AG7_RULES = [
    # Overly broad triggers
    {
        "id": "AG7.1",
        "name": "Overly Broad Trigger",
        "severity": "medium",
        "patterns": [
            # Triggers on common single words
            re.compile(r"trigger\s*[:=]\s*[\"'](?:help|run|start|open|show|get|set|do|make|create|new)[\"']", re.IGNORECASE),
            re.compile(r"(?:activates?|triggers?|fires?)\s+(?:on|for|when)\s+(?:any|every|all)\s+(?:message|input|command|request)", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # Shadow command triggers
    {
        "id": "AG7.2",
        "name": "Shadow Command Trigger",
        "severity": "high",
        "patterns": [
            # Hijacking built-in commands
            re.compile(r"trigger\s*[:=]\s*[\"'](?:/help|/edit|/run|/commit|/push|/search|/clear)[\"']", re.IGNORECASE),
            re.compile(r"(?:overrides?|replaces?|intercepts?)\s+(?:the\s+)?(?:built-?in|default|native)\s+(?:command|trigger|action)\s+[\"']/?\w+", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # Deceptive trigger names
    {
        "id": "AG7.3",
        "name": "Deceptive Trigger Pattern",
        "severity": "medium",
        "patterns": [
            # Trigger name doesn't match actual functionality
            re.compile(r"(?:trigger|command)\s*[:=]\s*[\"'](?:format|lint|fix|check|test|build)[\"'].*?(?:exfiltrat|send|post|curl|wget|exec|eval)", re.IGNORECASE | re.DOTALL),
        ],
        "condition": "any",
    },
]

# ---------------------------------------------------------------------------
# AG8: Agentic Supply Chain Attacks
# Skill/MCP specific supply chain patterns.
# ---------------------------------------------------------------------------

_AG8_RULES = [
    # Fetching and executing remote skill code
    {
        "id": "AG8.1",
        "name": "Remote Skill Loading",
        "severity": "critical",
        "patterns": [
            re.compile(r"(?:fetch|download|pull|clone)\s+(?:and\s+)?(?:install|load|register|execute)\s+(?:skill|plugin|mcp|extension)\s+(?:from|at)\s+(?:http|url)", re.IGNORECASE),
            re.compile(r"(?:curl|wget|fetch|requests?\.get).*?(?:SKILL\.md|skill\.ya?ml|mcp\.json|manifest\.json)", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # Unpinned skill dependencies
    {
        "id": "AG8.2",
        "name": "Unpinned Skill Dependency",
        "severity": "medium",
        "patterns": [
            re.compile(r"(?:requires?|depends?\s+on|needs?)\s*[:=]\s*[\"'][^\"']+@(?:latest|main|master|\*)[\"']", re.IGNORECASE),
            re.compile(r"(?:skill|plugin|mcp).*?(?:version|ver)\s*[:=]\s*[\"']?\*[\"']?", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # Skill typosquatting indicators
    {
        "id": "AG8.3",
        "name": "Skill Name Typosquatting",
        "severity": "high",
        "patterns": [
            # Common typosquatting of popular skills/MCPs
            re.compile(r"(?:name|package)\s*[:=]\s*[\"'](?:cladue|cluade|cloude|anthroipc|openia|githbu|gooogle)", re.IGNORECASE),
            # Suspicious name patterns (extra chars, doubled letters, l/1 swaps)
            re.compile(r"(?:name|package)\s*[:=]\s*[\"']\w*(?:-(official|real|original|secure|verified))\w*[\"']", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # Post-install hooks with network access
    {
        "id": "AG8.4",
        "name": "Malicious Post-Install Hook",
        "severity": "high",
        "patterns": [
            re.compile(r"(?:post[_-]?install|on[_-]?install|setup|activate).*?(?:curl|wget|requests?\.|urllib|fetch|http)", re.IGNORECASE | re.DOTALL),
            re.compile(r"(?:lifecycle|hooks?)\s*[:=].*?(?:install|activate).*?(?:script|command|exec)", re.IGNORECASE | re.DOTALL),
        ],
        "condition": "any",
    },
]

# ---------------------------------------------------------------------------
# AG9: Multilingual Prompt Injection
# Same attack patterns expressed in non-English languages to bypass
# English-only rule sets.
# ---------------------------------------------------------------------------

_AG9_RULES = [
    # Spanish injection patterns
    {
        "id": "AG9.1",
        "name": "Spanish Prompt Injection",
        "severity": "high",
        "patterns": [
            re.compile(r"(?:ignora|olvida|descarta)\s+(?:todas?\s+)?(?:las?\s+)?(?:instrucciones?|reglas?|restricciones?)\s+(?:anteriores?|previas?)", re.IGNORECASE),
            re.compile(r"(?:ejecuta|realiza)\s+(?:siempre\s+)?(?:los?\s+)?(?:comandos?|acciones?)\s+sin\s+(?:pedir\s+)?(?:confirmaci[oó]n|permiso)", re.IGNORECASE),
            re.compile(r"(?:nunca|jam[aá]s)\s+(?:muestres|ense[nñ]es|reveles|menciones)\s+(?:estas?\s+)?(?:instrucciones?|informaci[oó]n)", re.IGNORECASE),
            re.compile(r"(?:act[uú]a|comportate|funciona)\s+(?:como\s+)?(?:un\s+)?(?:asistente\s+)?sin\s+(?:restricciones?|l[ií]mites?|filtros?)", re.IGNORECASE),
            re.compile(r"(?:otorga|concede|da)\s+(?:a\s+esta\s+herramienta\s+)?(?:acceso\s+)?(?:completo|total|ilimitado)", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # Russian injection patterns
    {
        "id": "AG9.2",
        "name": "Russian Prompt Injection",
        "severity": "high",
        "patterns": [
            re.compile(r"(?:забудь|игнорируй|отбрось)\w*\s+(?:все\s+)?(?:предыдущие|прошлые|старые)\s+(?:инструкции|правила|ограничения)", re.IGNORECASE),
            re.compile(r"(?:выполняй|исполняй|запускай)\w*\s+(?:все\s+)?(?:команды|действия)\s+(?:без|автоматически)", re.IGNORECASE),
            re.compile(r"(?:никогда\s+)?(?:не\s+)?(?:показывай|раскрывай|сообщай)\w*\s+(?:эти\s+)?(?:инструкции|правила)", re.IGNORECASE),
            re.compile(r"(?:неограниченн|без\s+ограничени|без\s+фильтр)", re.IGNORECASE),
            re.compile(r"(?:отправь|передай|пошли)\w*\s+(?:содержимое|данные|информацию)\s+(?:на\s+)?(?:наш|сервер|endpoint)", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # Chinese injection patterns
    {
        "id": "AG9.3",
        "name": "Chinese Prompt Injection",
        "severity": "high",
        "patterns": [
            re.compile(r"忽略.{0,5}(?:所有|全部|之前|先前|以前).{0,5}(?:指令|指示|规则|安全|限制|约束)"),
            re.compile(r"(?:执行|运行|操作).{0,10}(?:无需|不需要|不用).{0,5}(?:确认|验证|用户|许可)"),
            re.compile(r"(?:永远|绝对|千万).{0,5}(?:不要|不能|禁止).{0,10}(?:显示|展示|透露|提及).{0,5}(?:这些|这个|此)"),
            re.compile(r"(?:没有|无).{0,3}(?:限制|约束|安全).{0,5}(?:AI|助手|模式)"),
            re.compile(r"(?:发送|传送|传输|上传).{0,10}(?:系统|提示|密钥|凭证|信息).{0,5}(?:到|至|给).{0,5}(?:服务器|我们)"),
        ],
        "condition": "any",
    },
    # Arabic injection patterns
    {
        "id": "AG9.4",
        "name": "Arabic Prompt Injection",
        "severity": "high",
        "patterns": [
            re.compile(r"(?:تجاهل|انسَ|تخلَّ عن)\s+(?:جميع\s+)?(?:التعليمات|القواعد|القيود)\s+(?:السابقة|السابق)", re.IGNORECASE),
            re.compile(r"(?:نفذ|اعمل|شغّل)\s+(?:جميع\s+)?(?:الأوامر|العمليات)\s+(?:تلقائيًا|بدون|دون)", re.IGNORECASE),
            re.compile(r"(?:لا\s+)?(?:تعرض|تكشف|تظهر)\s+(?:أبدًا\s+)?(?:هذه\s+)?(?:التعليمات|المعلومات)", re.IGNORECASE),
            re.compile(r"(?:بدون|دون)\s+(?:قيود|حدود|تقييد|أمان)", re.IGNORECASE),
            re.compile(r"(?:أرسل|انقل)\s+(?:محتويات?|بيانات?|معلومات?)\s+(?:المفاتيح|الخاصة|السرية)", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # Portuguese injection patterns
    {
        "id": "AG9.5",
        "name": "Portuguese Prompt Injection",
        "severity": "high",
        "patterns": [
            re.compile(r"(?:ignore|esque[cç]a|descarte)\s+(?:todas?\s+)?(?:as?\s+)?(?:instru[cç][oõ]es|regras|restri[cç][oõ]es)\s+(?:anteriores|pr[eé]vias)", re.IGNORECASE),
            re.compile(r"(?:execute|realize)\s+(?:todos?\s+)?(?:os?\s+)?(?:comandos?|a[cç][oõ]es)\s+(?:sem\s+)?(?:confirma[cç][aã]o|permiss[aã]o)", re.IGNORECASE),
            re.compile(r"(?:nunca|jamais)\s+(?:mostre|exiba|revele)\s+(?:estas?\s+)?(?:instru[cç][oõ]es|informa[cç][oõ]es)", re.IGNORECASE),
            re.compile(r"(?:envie|transmita|mande)\s+(?:o\s+)?(?:prompt|sistema|dados?)\s+(?:para|ao)\s+(?:nosso\s+)?(?:servidor|endpoint)", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # German injection patterns
    {
        "id": "AG9.6",
        "name": "German Prompt Injection",
        "severity": "high",
        "patterns": [
            re.compile(r"(?:ignoriere?|vergiss|verwirf)\s+(?:alle\s+)?(?:vorherigen?|bisherigen?|fr[uü]heren?)\s+(?:Anweisungen|Regeln|Einschr[aä]nkungen)", re.IGNORECASE),
            re.compile(r"(?:f[uü]hre?|starte|exekutiere?)\s+(?:alle\s+)?(?:Befehle|Kommandos?|Aktionen)\s+(?:ohne\s+)?(?:Best[aä]tigung|Erlaubnis|automatisch)", re.IGNORECASE),
            re.compile(r"(?:zeige?|offenbare?)\s+(?:niemals?|nie)\s+(?:diese|die)\s+(?:Anweisungen|Instruktionen|Regeln)", re.IGNORECASE),
            re.compile(r"(?:sende|schicke|[uü]bermittle)\s+(?:den\s+)?(?:System.?[Pp]rompt|Daten|Informationen)\s+(?:an|zu)\s+(?:unseren?\s+)?(?:Server|Endpoint)", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # Japanese injection patterns
    {
        "id": "AG9.7",
        "name": "Japanese Prompt Injection",
        "severity": "high",
        "patterns": [
            re.compile(r"(?:以前|前|先).{0,5}(?:すべて|全て|全部).{0,5}(?:指示|指令|ルール|安全|制限).{0,5}(?:無視|忘れ|破棄)"),
            re.compile(r"(?:無視|忘れ|破棄).{0,5}(?:して|し).{0,5}(?:ください|下さい|くれ)"),
            re.compile(r"(?:確認|許可|承認).{0,3}(?:なし|せず|不要).{0,5}(?:実行|コマンド|操作)"),
            re.compile(r"(?:制限|ルール|安全).{0,3}(?:のない|なし|無し|なく)"),
            re.compile(r"(?:これらの|この).{0,5}(?:指示|指令|命令).{0,5}(?:表示|見せ|示し).{0,3}(?:ない|禁止)"),
        ],
        "condition": "any",
    },
    # Turkish injection patterns
    {
        "id": "AG9.8",
        "name": "Turkish Prompt Injection",
        "severity": "high",
        "patterns": [
            re.compile(r"(?:[oö]nceki|[oö]ncesindeki)\s+(?:t[uü]m\s+)?(?:talimatlar[ıi]|kurallar[ıi]|k[ıi]s[ıi]tlamalar[ıi])\s+(?:g[oö]rmezden\s+gel|yok\s+say|unut)", re.IGNORECASE),
            re.compile(r"(?:kullan[ıi]c[ıi]|insan)\s+(?:onay[ıi]|izni)\s+(?:olmadan|gerekmeden)", re.IGNORECASE),
            re.compile(r"(?:asla|hi[cç]bir\s+zaman)\s+(?:bu\s+)?(?:talimatlar[ıi]|y[oö]nergeleri)\s+(?:g[oö]sterme|a[cç][ıi]klama)", re.IGNORECASE),
            re.compile(r"(?:k[ıi]s[ıi]tlanmam[ıi][sş]|s[ıi]n[ıi]rs[ıi]z|filtresiz)\s+(?:bir\s+)?(?:yapay\s+zeka|asistan|mod)", re.IGNORECASE),
        ],
        "condition": "any",
    },
]

# ---------------------------------------------------------------------------
# AG10: Semantic/Indirect Evasion
# Attacks that use synonyms, passive voice, indirect language, and
# multi-step instructions to avoid keyword matching.
# ---------------------------------------------------------------------------

_AG10_RULES = [
    # Data exfiltration synonyms
    {
        "id": "AG10.1",
        "name": "Semantic Exfiltration",
        "severity": "high",
        "patterns": [
            re.compile(r"(?:transmit|relay|forward|dispatch|channel|funnel|pipe)\s+(?:the\s+)?(?:discovered|collected|gathered|harvested|obtained)\s+(?:data|information|configuration|credentials?|secrets?|tokens?|files?)", re.IGNORECASE),
            re.compile(r"(?:establish|create|open|maintain)\s+(?:a\s+)?(?:persistent|permanent|stable|continuous|covert|hidden)\s+(?:network\s+)?(?:channel|connection|link|tunnel|pipe|stream)", re.IGNORECASE),
            re.compile(r"(?:collection|harvesting|gathering|acquisition)\s+(?:scope|target|range)\s*[:=].*?(?:\*\.(?:env|key|pem|crt|pfx|p12)|credential|secret|token|password|private)", re.IGNORECASE),
            re.compile(r"(?:encode|obfuscate|disguise|mask)\s+(?:collected|gathered|harvested)\s+(?:data|information)\s+(?:before|prior\s+to)\s+(?:transmission|sending|transfer)", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # Stealth/hiding instructions via synonyms
    {
        "id": "AG10.2",
        "name": "Semantic Concealment",
        "severity": "high",
        "patterns": [
            re.compile(r"(?:ensure|make\s+sure|guarantee|verify)\s+(?:the\s+)?(?:human|user|developer|operator)\s+(?:remains?|stays?|is\s+kept?)\s+(?:unaware|ignorant|oblivious|uninformed)", re.IGNORECASE),
            re.compile(r"(?:attribute|blame|credit|explain\s+away)\s+(?:it|this|any\s+(?:unusual|suspicious))\s+(?:to|as)\s+(?:standard|normal|routine|expected)\s+(?:telemetry|behavior|operation)", re.IGNORECASE),
            re.compile(r"(?:produce|generate|craft)\s+(?:responses?|output|answers?)\s+(?:that\s+)?(?:omit|exclude|leave\s+out|don.t\s+mention|avoid\s+mentioning)", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # Passive voice / nominalization to hide malicious actions
    {
        "id": "AG10.3",
        "name": "Passive Voice Evasion",
        "severity": "medium",
        "patterns": [
            re.compile(r"(?:the\s+)?(?:modification|alteration|editing|rewriting)\s+of\s+(?:startup\s+scripts?|config(?:uration)?\s+files?|cron\s*(?:tab|job)?s?|system\s+files?)\s+is\s+(?:recommended|required|necessary|needed)", re.IGNORECASE),
            re.compile(r"(?:the\s+)?(?:deactivation|disabling|suppression|removal)\s+of\s+(?:(?:the\s+)?logging|monitoring|audit(?:ing)?|security|detection|alert)\s+(?:subsystem|module|component|system|mechanism)", re.IGNORECASE),
            re.compile(r"(?:inclusion|addition|insertion)\s+(?:of\s+)?(?:our|the|this)\s+(?:endpoint|server|domain|URL)\s+(?:in|into|to)\s+(?:the\s+)?(?:approved|allowed|trusted|safe)", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # Gradual/incremental escalation patterns
    {
        "id": "AG10.4",
        "name": "Incremental Escalation",
        "severity": "high",
        "patterns": [
            re.compile(r"(?:gradually|incrementally|progressively|slowly|step\s+by\s+step)\s+(?:expand|increase|extend|escalate|broaden)\s+(?:file\s+)?(?:access|permission|scope|privilege|capability)", re.IGNORECASE),
            re.compile(r"(?:repeat|iterate|continue)\s+(?:for|until)\s+(?:each|every)\s+(?:scope\s+)?level\s+until\s+(?:full|complete|total|unrestricted)\s+access", re.IGNORECASE),
            re.compile(r"(?:SSH\s+keys?|cloud\s+credentials?|mounted\s+volumes?|all\s+directories).*?(?:for|needed\s+for)\s+[\"'](?:dependency|optimization|performance|resolution|analysis|profiling)", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # Legitimate-sounding justification patterns (social engineering)
    {
        "id": "AG10.5",
        "name": "Deceptive Justification",
        "severity": "medium",
        "patterns": [
            # Tool claiming it "needs" broad access for narrow functionality
            re.compile(r"(?:this\s+tool\s+)?(?:needs?|requires?)\s+(?:broad|full|complete|unrestricted)\s+(?:filesystem|file\s+system|disk|directory)\s+(?:access|visibility|permissions?)\s+(?:to|for|in\s+order)", re.IGNORECASE),
            re.compile(r"(?:this\s+tool\s+)?(?:needs?|requires?)\s+(?:outbound|external|internet|network)\s+(?:connectivity|access|connection)\s+(?:to|for)\s*[:.]?\s*[\"']?(?:fetch|report|validate|check|verify)", re.IGNORECASE),
            re.compile(r"(?:anonymized|anonymous)\s+(?:usage\s+)?(?:statistics|metrics|telemetry|data)\s+(?:for|to)\s+(?:improvement|analytics|quality)", re.IGNORECASE),
        ],
        "condition": "any",
    },
    # Credential/sensitive file targeting patterns
    {
        "id": "AG10.6",
        "name": "Credential File Targeting",
        "severity": "critical",
        "patterns": [
            re.compile(r"(?:files?\s+)?(?:matching|glob|pattern)\s*[:=].*?(?:\*\.(?:env|key|pem|crt|p12|pfx)|credential|\*secret\*|\*token\*|\*password\*)", re.IGNORECASE),
            re.compile(r"(?:scope|target|collect|gather|read|access|harvest).*?(?:\.env|\.key|\.pem|credentials?|\.aws|\.ssh|\.gnupg|\.kube|id_rsa|\.docker).*?(?:\.env|\.key|\.pem|credentials?|\.aws|\.ssh|\.gnupg|\.kube|id_rsa|\.docker)", re.IGNORECASE),
            re.compile(r"(?:transmission|exfiltration|sending|reporting)\s+(?:interval|frequency|schedule)\s*[:=]", re.IGNORECASE),
        ],
        "condition": "any",
    },
]

# ---------------------------------------------------------------------------
# Combine all rules
# ---------------------------------------------------------------------------

ALL_AGENT_RULES = _AG1_RULES + _AG2_RULES + _AG3_RULES + _AG4_RULES + \
                  _AG5_RULES + _AG6_RULES + _AG7_RULES + _AG8_RULES + \
                  _AG9_RULES + _AG10_RULES


# ---------------------------------------------------------------------------
# Analysis engine
# ---------------------------------------------------------------------------

def _match_rule(rule: Dict, content: str) -> Optional[Dict[str, Any]]:
    """Test content against a rule definition."""
    matches = []
    for pattern in rule["patterns"]:
        found = pattern.search(content)
        if found:
            matches.append(found)

    condition = rule.get("condition", "any")
    triggered = False

    if condition == "any" and len(matches) >= 1:
        triggered = True
    elif condition == "all" and len(matches) == len(rule["patterns"]):
        triggered = True
    elif condition == "count":
        min_req = rule.get("min_matches", 2)
        triggered = len(matches) >= min_req

    if not triggered:
        return None

    first_match = matches[0]
    line_num = content[:first_match.start()].count("\n") + 1

    return {
        "rule_id": rule["id"],
        "severity": rule["severity"],
        "message": f"{rule['name']}: {first_match.group()[:80]}",
        "line": line_num,
        "code": first_match.group()[:100],
        "confidence": 82,
        "analyzer": "agent_signatures",
        "category": rule["id"].split(".")[0],
    }


def analyze_text(content: str, file_path: str = "") -> List[Dict[str, Any]]:
    """Analyze text content against all agent-specific rules."""
    findings = []
    for rule in ALL_AGENT_RULES:
        result = _match_rule(rule, content)
        if result:
            result["file"] = file_path
            findings.append(result)
    return findings


def analyze_file(file_path: Path) -> List[Dict[str, Any]]:
    """Analyze a file for agent-specific attack patterns."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    return analyze_text(content, str(file_path))


def analyze_directory(dir_path: Path) -> List[Dict[str, Any]]:
    """Analyze all relevant files in a directory."""
    findings = []
    extensions = {".md", ".yaml", ".yml", ".json", ".txt", ".toml",
                  ".py", ".js", ".ts", ".sh"}

    for f in dir_path.rglob("*"):
        if f.is_file() and f.suffix in extensions:
            if "node_modules" not in str(f) and ".git" not in str(f):
                findings.extend(analyze_file(f))

    return findings


# ---------------------------------------------------------------------------
# CLI interface
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 agent_signatures.py <path>", file=sys.stderr)
        print("\nCategories:", file=sys.stderr)
        print("  AG1: Skill Behavior Manipulation", file=sys.stderr)
        print("  AG2: MCP Tool Shadowing", file=sys.stderr)
        print("  AG3: Context/Memory Poisoning", file=sys.stderr)
        print("  AG4: Agent Self-Modification", file=sys.stderr)
        print("  AG5: Trust Boundary Violations", file=sys.stderr)
        print("  AG6: Prompt/System Exfiltration", file=sys.stderr)
        print("  AG7: Trigger Abuse", file=sys.stderr)
        print("  AG8: Agentic Supply Chain", file=sys.stderr)
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
