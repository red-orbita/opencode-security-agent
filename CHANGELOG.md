# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/).

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
