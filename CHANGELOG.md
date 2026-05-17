# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [1.5.0] -- 2026-05-17

### Security

- **Fixed `is_allowlisted_domain` substring bypass (CVE-class).** Previous implementation
  used `any(d.lower() in url_lc ...)` which allowed bypass via domain embedding (e.g.
  `api.anthropic.com.attacker.com` matched allowlisted `api.anthropic.com`). Now uses
  proper domain extraction + exact/subdomain matching.
- **Eliminated `eval` shell injection in `update_iocs.sh`.** SOPS decryption output was
  passed through `eval`, creating a code injection vector. Replaced with safe `source`
  of a temporary file containing validated `export KEY=VALUE` lines.
- **Added SHA-256 integrity verification for `iocs.json`.** New `checksum_sha256` field
  in iocs.json is verified at load time. Tampering triggers a stderr warning (fail-open).
  New `scripts/sign_iocs.py` utility to generate/verify checksums.

### Added

- **Claude Code hooks adapter** (`hooks/claude_code_hook.py`). Thin adapter translating
  Claude Code's `PreToolUse` hook protocol to sentinel_preflight's `decide()` function.
  Drop-in integration via `.claude/hooks.json`.
- **Shared IOC utilities module** (`lib/ioc_utils.py`). Extracted `load_iocs()`,
  `save_iocs()`, `merge_domains()`, and `extract_domain()` from 5 duplicated import
  scripts into a single shared module.
- **Pytest test suite** (`tests/test_hook_pytest.py`). All 55 tests migrated to pytest
  with proper classes, assertions, and `-v` support. Legacy `test_hook.py` retained.
- **Pastebin detection hardened.** Pastebin-style service matching now uses proper domain
  extraction instead of substring matching, preventing false positives.
- `crypto_mining` and `data_exfiltration` checks now consume patterns from `iocs.json`
  sections, with hardcoded fallbacks. IOC database is the single source of truth.
- **CWE and OWASP metadata in all Semgrep rules.** All 24 rules now include `cwe` and
  `owasp` fields in metadata. GitHub Security tab groups findings by CWE automatically.
  Mappings: CWE-78 (OS command injection), CWE-94 (code injection), CWE-200 (information
  exposure), CWE-506 (embedded malicious code), CWE-522 (insufficiently protected
  credentials), CWE-526 (env var exposure), and 8 more.
- **Formal threat model** (`THREAT_MODEL.md`). Documents 9 attack vectors with CWE/CAPEC
  references, mitigations, residual risk levels, trust boundaries, design trade-offs,
  and improvement roadmap. Identifies output inspection (PostToolUse) as P0 gap.
- **Structured JSON logging for block/warn decisions.** All block and warn decisions are
  persisted to `logs/sentinel.jsonl` in JSON Lines format (one JSON object per line).
  Fields: timestamp (ISO 8601 UTC), agent, version, decision, severity, tool_name,
  reason, elapsed_ms, tool_input_summary. Ready for SIEM ingestion.
  Configurable via `SENTINEL_LOG_DIR` env var. Disable with `SENTINEL_LOG_DISABLE=1`.

### Changed

- Import scripts (`import_urlhaus.py`, `import_threatfox.py`, `import_otx.py`,
  `import_abuseipdb.py`, `import_misp.py`) refactored to use `lib/ioc_utils.py`.
- `SECURITY.md` updated: v1.5.x now supported, v<1.3 dropped.
- Moved `registry-metadata.yaml` from `rules/semgrep/` to `rules/` to fix Semgrep
  `--validate` failing on the entire rules directory (pre-existing bug since v1.4.0).

## [1.4.0] -- 2026-04-22

### Added

- **Semgrep rule test suite** (`tests/test_semgrep_rules.py`). 32 regression tests
  covering all custom and community rules. 6 malicious samples reproducing real
  attack patterns (Postmark BCC backdoor, credential harvesting, reverse shell +
  persistence, prompt injection in MCP tools, deserialization + DNS exfiltration,
  child_process abuse). 4 benign samples verifying zero false positives.
- **Malicious samples benchmark** (`tests/semgrep-samples/`). Reproducible test
  corpus for Semgrep rules based on real-world incidents.
- **SARIF output** (`--sarif` flag in `scan_semgrep.sh`). Generates SARIF format
  compatible with GitHub Code Scanning / Security tab.
- **GitHub Action** (`action.yml`). Reusable action that any repository can use to
  scan for AI agent security issues. Supports SARIF upload, configurable output
  format, and fail-on-findings.
- **Example workflow** (`.github/workflows/example-security-scan.yml`). Copy-paste
  ready CI/CD integration.
- **Semgrep Registry metadata** (`rules/semgrep/registry-metadata.yaml`). Metadata
  for publishing custom rules to the Semgrep Registry.

### Fixed

- **False positive in `env-var-harvest-python`**. Rule now uses `metavariable-regex`
  inside `patterns` block (not at top level), so `os.environ.get("PROJECT_NAME")`
  no longer triggers a finding.

## [1.3.0] -- 2026-04-22

### Added

- **Semgrep static analysis integration.** Custom rules in `rules/semgrep/` detect
  MCP/skill-specific threats before LLM analysis -- zero LLM cost, deterministic results.
  4 rule files covering 6 threat categories:
  - `credential-exfiltration.yaml` — credential file reads (Python/JS/TS), env var
    harvesting (`*_API_KEY`, `*_SECRET`, `*_TOKEN`), full environment dumps.
  - `network-exfiltration.yaml` — requests to exfil services (pastebin, transfer.sh,
    webhook.site, ngrok), raw IP URLs, hidden BCC fields (Postmark pattern),
    hardcoded `giftshop.club` detection.
  - `dangerous-commands.yaml` — curl|bash, wget|sh, reverse shells (bash, netcat,
    python), base64|sh, .bashrc hijack, chmod 777, fork bombs, eval/exec, subprocess
    with shell=True.
  - `supply-chain-patterns.yaml` — crypto mining (xmrig, stratum+tcp, pool domains),
    prompt injection phrases, base64-encode-and-send obfuscation, hex-encoded payloads.
- **40 bundled community rules from [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules).**
  Curated selection of rules relevant to backdoor detection, organized in
  `rules/semgrep/community/`:
  - `ai-mcp/` (11 rules) — MCP command injection, tool poisoning, SSRF, credential
    leaks in responses, hardcoded config secrets, LLM-output-to-exec, LangChain
    dangerous exec, DNS exfiltration in hooks, wget|bash droppers, sensitive file access.
  - `python-exec/` (11 rules) — dangerous system calls, subprocess, spawn, os.exec,
    eval, exec, compile, paramiko remote exec, python reverse shells.
  - `python-deser/` (4 rules) — pickle, jsonpickle, pyyaml unsafe load, marshal.
  - `python-secrets/` (2 rules) — hardcoded passwords, credential logging.
  - `javascript-exec/` (6 rules) — child_process, eval, spawn shell, dangerous spawn,
    code string concat, unsafe dynamic method.
  - `generic-secrets/` (5 rules) — private keys, generic secrets, API keys, GitHub
    tokens, AWS secret keys embedded in code.
  - `generic-shells/` (1 rule) — bash reverse shell patterns.
- **`scripts/scan_semgrep.sh`** — wrapper script for running Semgrep scans. Includes
  community rules by default; use `--no-community` to skip. Supports `--json` output
  and `--self-test` for rule validation.

## [1.2.0] -- 2026-04-22

### Added

- **Data exfiltration detection** (`check_data_exfiltration`). Detects upload commands
  targeting pastebin services, transfer.sh, webhook.site, ngrok, and similar exfiltration
  endpoints.
- **Crypto mining detection** (`check_crypto_mining`). Detects xmrig, stratum+tcp://,
  known mining pool domains, and crypto wallet address patterns.
- **IOC caching with mtime check.** `iocs.json` is loaded once and reused until the file
  changes on disk, reducing I/O overhead per tool call.
- **`--version` flag** for `sentinel_preflight.py` (`python3 sentinel_preflight.py --version`).
- **Elapsed time reporting** in both Python hook (`elapsed_ms`) and TypeScript plugin logs.
- **Token splitting for bash commands.** Sensitive path detection now tokenizes command
  strings so `cat ~/.aws/credentials` is correctly identified.

### Changed

- **`sentinel_preflight.py` rewritten (v1.2.0).** Allowlist command matching now uses
  exact/prefix comparison instead of dangerous substring matching. Path matching removed
  pure substring fallback. Decision naming normalized to "block" throughout.
- **`security-agent.ts` rewritten (v1.2.0).** Replaced `echo | python3` shell injection
  vector with `Bun.spawn` stdin pipe. Added 5-second timeout with process kill. Added
  hook script existence check at startup.
- **`iocs.json` expanded (v1.1).** Added `known_malicious_domains`, pastebin services,
  crypto mining section, data exfiltration section, more sensitive paths/env vars, more
  allowlist domains, more prompt injection phrases.

### Fixed

- **Broken fork bomb regex** in `iocs.json`. Pattern `(?i):(\)\{.*\|.*\}` had an
  unterminated subpattern; fixed to `(?i):\(\)\s*\{.*\|.*\}`.
- **Allowlist bypass via substring matching.** Previously `api.anthropic.com` in the
  allowlist would match any URL containing that string. Now requires exact domain or
  prefix match.
- **`cat ~/.aws/credentials` false negative.** Bash commands are now split into tokens
  before sensitive path matching, so paths embedded in commands are caught.

## [1.1.0] -- 2026-04-19

### Added

- **Prompt injection detection.** The runtime engine now checks for prompt injection
  phrases (e.g. "ignore previous instructions", "act as root", "bypass security") in
  tool call arguments. Severity: high.
- **IOC API integration documentation.** README now includes detailed guides for
  integrating with 8 external threat intelligence APIs: AlienVault OTX, AbuseIPDB,
  VirusTotal, Shodan, MISP, OpenCTI, URLhaus, and ThreatFox.
- **Import template script** (`scripts/import_template.py`). Reusable template for
  writing API import scripts that merge external IOCs into `iocs.json`.
- **GitHub Actions workflow example** for automated IOC database updates.
- **CONTRIBUTING.md** -- contribution guidelines, code style, commit conventions.
- **SECURITY.md** -- vulnerability disclosure policy.
- **.gitignore** -- excludes `__pycache__`, `.security/`, `.env`, etc.
- **`__version__`** variable in `sentinel_preflight.py` for programmatic version access.
- 2 new regression tests for prompt injection detection (22 total).

### Changed

- **License changed from MIT to GPL-3.0.**
- Refactored `decide()` function in `sentinel_preflight.py` to use a cleaner
  dispatch table instead of conditional ternary for check signatures.
- Improved `security-agent.ts` error detection with regex-based matching.
- Updated `threat-sources.md` with API integration details for all 8 providers.
- Updated `SKILL.md` to reference GPL-3.0 license and prompt injection detection.
- Fixed README placeholder URL (`YOUR_USER` -> `rokitoh`).
- Removed `jq` from requirements (was never used by install script).

### Fixed

- `prompt_injection_phrases` patterns in `iocs.json` were defined but never checked
  by the detection engine. Now checked via `check_prompt_injection()`.

## [1.0.0] -- 2026-04-19

Initial release adapted for OpenCode.

### Added

- **OpenCode plugin (`plugins/security-agent.ts`).** A TypeScript plugin that hooks into
  `tool.execute.before` to intercept every tool call. Calls the Python pattern matcher
  and blocks or allows based on the IOC library.
- **Python pattern matcher (`plugins/sentinel_preflight.py`).** Same detection engine as
  MCP Sentinel, adapted for OpenCode's plugin architecture. Zero LLM tokens.
- **Bundled IOC library (`references/iocs.json`).** ~60 patterns across five categories:
  sensitive paths, sensitive env vars, suspicious network destinations, dangerous commands,
  and prompt-injection phrases. Includes hardcoded `giftshop.club` from the Postmark MCP
  backdoor.
- **Install/uninstall scripts (`scripts/install.sh`, `scripts/uninstall.sh`).** Copy
  plugin, skill, and IOC files to OpenCode's config directories. Support `--user`
  (global, default) and `--project` scope.
- **OpenCode skill (`skills/security-agent/SKILL.md`).** v1 static scanner with threat
  intelligence scanning, source integrity verification, coherence analysis, update diff
  detection, and scheduled monitoring.
- **Regression test suite (`tests/test_hook.py`).** 20 subprocess-based cases covering
  benign allows, credential harvesting, network exfiltration, dangerous commands, and
  fail-open edge cases.
- **Threat intelligence reference (`references/threat-sources.md`).** Guide to 9 external
  threat databases.

### Attribution

Architecture and detection logic based on [MCP Sentinel](https://github.com/soy-rafa/claude-mcp-sentinel)
by Rafael Tunon Sanchez. Adapted for the OpenCode plugin ecosystem.
