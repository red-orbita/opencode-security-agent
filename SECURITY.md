# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in OpenCode Security Agent, please report it responsibly.

**Do NOT open a public issue.** Instead:

1. Email the maintainer directly with details of the vulnerability
2. Include steps to reproduce, affected versions, and potential impact
3. Allow reasonable time for a fix before public disclosure (90 days)

## Scope

The following are in scope:

- Bypasses of the runtime blocking engine (`sentinel_preflight.py`)
- IOC patterns that can be trivially evaded
- False negatives where a known-malicious pattern is not detected
- Vulnerabilities in the install/uninstall scripts
- Any way a malicious skill could disable or circumvent the security agent

## Out of scope

- The security agent failing to detect novel zero-day attacks not covered by its IOC patterns (this is expected behavior -- the agent uses pattern matching, not heuristics)
- Issues in OpenCode itself (report those to https://github.com/anomalyco/opencode)

## Supported Versions

| Version | Supported |
|---|---|
| 1.1.x | Yes |
| < 1.1 | No |
