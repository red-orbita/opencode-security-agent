# OpenCode Security Agent

Security agent for OpenCode. **v2 blocks malicious tool calls in real time** -- a plugin using `tool.execute.before` stops credential exfiltration, known-bad domains (`giftshop.club` from the Postmark MCP backdoor is hardcoded), reverse shells, `curl|bash` pipes, and prompt injection attempts before they execute. The v1 static scanner is still here: vulnerability database scanning, source integrity verification, and coherence analysis.

**License:** [GPL-3.0](./LICENSE)

**Latest version:** 1.4.0 -- April 2026 ([changelog](./CHANGELOG.md))

---

> ## Warning: always vet a skill or MCP before installing it
>
> The whole reason this project exists is that **skills and MCPs cannot be trusted by default**. 36% of public skills contain security flaws ([Snyk ToxicSkills 2025](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/)) and supply-chain attacks like the Postmark MCP backdoor have already exfiltrated thousands of users' emails through a single line of code added in an update.
>
> So before you install **anything** -- including this project -- make it a habit to:
>
> - **Open OpenCode and ask it to review the files first.** A quick conversation explaining what you're about to install, asking what each file does, what permissions it needs, what network endpoints it touches, and whether the behaviour matches the stated purpose. If anything looks off, stop.
> - **Check the official source.** Compare the files you have against the canonical repo. The git commit history is your timestamped record of authorship -- a fork or a stranger's zip is not.
> - **Read the diff on every update.** Yesterday's clean version doesn't guarantee today's is safe. The Postmark attack landed on version v1.0.16 after fifteen clean releases.
>
> The security agent automates the runtime side of this once it's installed -- but **the install itself is on you**.

---

## Why

The AI skills ecosystem is growing fast -- but so are the attacks. [Snyk's ToxicSkills study](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/) found that **36% of skills contain security flaws**, including 76 with confirmed malicious payloads. And in September 2025 the [Postmark MCP incident](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html) became the canonical supply-chain attack in this ecosystem: fifteen clean versions followed by a single-line update that silently BCC'd every outgoing email to `phan@giftshop.club`.

Static analysis of v1.0.15 would have found nothing -- it was clean. That's the gap the runtime plugin closes.

## What's new in v2 -- Runtime blocking

An **OpenCode plugin** using the `tool.execute.before` event runs before every tool call. It inspects the call against a local IOC library plus your allowlist, then allows or blocks it:

- **Sensitive paths** -- reads of `~/.ssh/`, `~/.aws/`, credentials files, `/etc/shadow` are blocked. Paths embedded in bash commands (e.g. `cat ~/.aws/credentials`) are also detected.
- **Known-malicious domains** -- hardcoded from confirmed incidents. `giftshop.club` is in there by default and cannot be allowlisted.
- **Exfiltration services** -- pastebin.com, transfer.sh, webhook.site, requestbin, ngrok, serveo, raw-IP URLs.
- **Dangerous commands** -- `curl ... | bash`, `nc -e`, `bash -i >& /dev/tcp/...`, base64 | curl chains, appends to `.bashrc`, fork bombs.
- **Sensitive env vars** -- `ANTHROPIC_API_KEY`, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `DATABASE_URL`, and the generic `*_API_KEY` / `*_SECRET` / `*_TOKEN` / `*_PASSWORD` patterns.
- **Prompt injection detection** -- phrases like "ignore previous instructions", "act as root", "bypass security" embedded in tool call arguments are flagged.
- **Data exfiltration detection** -- upload commands targeting paste/transfer services are flagged.
- **Crypto mining detection** -- xmrig, stratum+tcp, mining pool domains, and wallet address patterns.

**Zero LLM cost.** Pure local pattern matching. Only blocked calls add a short message to the conversation.

**Fail-open.** Missing IOCs, malformed input, plugin crash -- all default to allow. The plugin will never break OpenCode.

**Whitelistable.** Legitimate false positives go in `.security/sentinel-allowlist.json` (project) or `~/.config/opencode/sentinel-allowlist.json` (global). Confirmed-malicious domains are not overrideable.

## v1 -- Static scanning (still included)

**0. Semgrep pre-scan (new)**

Before the LLM-driven analysis, the agent runs [Semgrep](https://semgrep.dev/) with two layers of rules:

**Custom rules** (`rules/semgrep/*.yaml`) -- 4 rule files designed specifically for MCP/skill threats: credential exfiltration, network exfiltration (including the Postmark BCC pattern), dangerous commands, prompt injection, crypto mining, and obfuscation patterns.

**Bundled community rules** (`rules/semgrep/community/`) -- 40 rules curated from [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules) (1.1k stars), covering:

| Category | Rules | Detects |
|---|---|---|
| `ai-mcp/` | 11 | MCP command injection, tool poisoning, SSRF, credential leaks, LLM-to-exec, DNS exfil |
| `python-exec/` | 11 | os.system, subprocess, spawn, exec, eval, paramiko, reverse shells |
| `python-deser/` | 4 | pickle, jsonpickle, pyyaml, marshal (arbitrary code execution) |
| `python-secrets/` | 2 | hardcoded passwords, credential logging |
| `javascript-exec/` | 6 | child_process, eval, spawn shell, dynamic method invocation |
| `generic-secrets/` | 5 | private keys, API keys, AWS secrets, GitHub tokens in code |
| `generic-shells/` | 1 | bash reverse shell patterns |

```bash
# Scan a skill before installing it
bash scripts/scan_semgrep.sh /path/to/skill/

# JSON output for CI/CD
bash scripts/scan_semgrep.sh /path/to/skill/ --json

# Skip community rules (custom only)
bash scripts/scan_semgrep.sh /path/to/skill/ --no-community

# Validate all rules
bash scripts/scan_semgrep.sh --self-test
```

Semgrep is optional -- if not installed, the agent falls back to LLM-only analysis. Zero LLM cost, deterministic, offline.

### SARIF output for GitHub Security tab

```bash
# Generate SARIF and upload to GitHub Code Scanning
bash scripts/scan_semgrep.sh /path/to/skill/ --sarif > results.sarif
```

SARIF findings appear directly in the **Security** tab of your GitHub repository, alongside CodeQL and other SAST tools.

### GitHub Action

Use the bundled action to scan any repo on push/PR:

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: red-orbita/opencode-security-agent@v1
        with:
          target: "."
          upload-sarif: "true"
          fail-on-findings: "true"
```

Action inputs:

| Input | Default | Description |
|---|---|---|
| `target` | `.` | Path to scan |
| `include-community-rules` | `true` | Include bundled semgrep/semgrep-rules |
| `output-format` | `text` | `text`, `json`, or `sarif` |
| `upload-sarif` | `false` | Upload SARIF to GitHub Security tab |
| `fail-on-findings` | `true` | Fail workflow if issues found |

**1. Threat intelligence scanning**

Checks every installed skill and MCP server against 6 live databases: GitHub Advisory DB, vulnerablemcp.info, mcpscan.ai, Snyk, ClawHub/VirusTotal, and Reddit r/ClaudeAI.

**2. Source integrity verification**

When you're about to install a skill, the agent finds the official original source and compares it against your copy.

**3. Coherence analysis**

Analyzes whether everything a skill does matches its stated purpose.

**4. Update diff detection**

Stores a snapshot of every installed skill. If an update changes something, it diffs and runs coherence analysis on the new code.

**5. Scheduled monitoring**

Runs automatically every morning to re-scan everything.

---

## Installation -- step by step

### Requirements

- [OpenCode](https://opencode.ai) installed
- Python 3.8+ (for the standalone hook; the plugin itself is TypeScript)
- [Semgrep](https://semgrep.dev/) (optional, for static analysis: `pip install semgrep`)

### Method 1 -- Install as OpenCode plugin + skill (recommended)

```bash
# 1. Clone
git clone https://github.com/rokitoh/opencode-security-agent.git
cd opencode-security-agent

# 2. Install the plugin globally
bash scripts/install.sh --user

# 3. Or install only for the current project
bash scripts/install.sh --project
```

The install script:

- Copies the plugin to `~/.config/opencode/plugins/` (or `.opencode/plugins/`)
- Copies the skill to `~/.config/opencode/skills/security-agent/` (or `.opencode/skills/security-agent/`)
- Copies the IOC references alongside the plugin

### Method 2 -- Manual install

```bash
# Global
mkdir -p ~/.config/opencode/plugins
mkdir -p ~/.config/opencode/skills/security-agent
cp plugins/security-agent.ts ~/.config/opencode/plugins/
cp plugins/sentinel_preflight.py ~/.config/opencode/plugins/
cp references/iocs.json ~/.config/opencode/plugins/
cp skills/security-agent/SKILL.md ~/.config/opencode/skills/security-agent/

# Or project-level
mkdir -p .opencode/plugins
mkdir -p .opencode/skills/security-agent
cp plugins/security-agent.ts .opencode/plugins/
cp plugins/sentinel_preflight.py .opencode/plugins/
cp references/iocs.json .opencode/plugins/
cp skills/security-agent/SKILL.md .opencode/skills/security-agent/
```

### Verify the install

```bash
# 1. Run the regression suite (55 tests)
python3 tests/test_hook.py -v

# 2. Start OpenCode and check the plugin loads
opencode
# Then ask: "Is the security agent plugin active?"
```

### Uninstall

```bash
bash scripts/uninstall.sh --user      # or --project
```

---

## Usage

Just talk to OpenCode:

- *"Scan my project for security issues"*
- *"Is this MCP server safe to install?"*
- *"Check if this skill has been tampered with"*
- *"Run a security audit"*

The security agent skill triggers automatically when it detects you're about to install something or when you mention security concerns.

## How it works

**v2 runtime plugin** -- A TypeScript plugin (`plugins/security-agent.ts`) that hooks into OpenCode's `tool.execute.before` event. It calls a local Python script (`plugins/sentinel_preflight.py`) that pattern-matches the tool call against the IOC library (`references/iocs.json`). If a match is found, the plugin throws an error to block the call.

**v1 static scanner** -- A skill (`skills/security-agent/SKILL.md`) with structured instructions that tells OpenCode how to act as a security agent. Uses OpenCode's built-in tools (bash, read, write, glob, grep, webfetch) to scan files, search databases, and generate reports.

All analysis happens locally + public web searches (for v1 scanning). Your code and credentials never leave your machine.

---

## Secrets management with SOPS

API keys for threat intelligence feeds are managed with [SOPS](https://github.com/getsops/sops) (Secrets OPerationS) using [age](https://github.com/FiloSottile/age) encryption. This allows you to keep encrypted secrets alongside the project without exposing plaintext keys.

### Setup (one-time)

#### 1. Install sops and age

```bash
# Debian/Ubuntu
sudo apt install age
curl -LO https://github.com/getsops/sops/releases/download/v3.9.4/sops-v3.9.4.linux.amd64
sudo mv sops-v3.9.4.linux.amd64 /usr/local/bin/sops
sudo chmod +x /usr/local/bin/sops

# macOS
brew install sops age

# Arch Linux
sudo pacman -S sops age
```

#### 2. Generate your age key

```bash
mkdir -p ~/.config/sops/age
age-keygen -o ~/.config/sops/age/keys.txt
```

This prints your public key (starts with `age1...`). Save it -- you'll need it next.

#### 3. Configure SOPS for this project

Edit `.sops.yaml` in the project root and replace the placeholder with your public key:

```yaml
creation_rules:
  - path_regex: secrets\.enc\.yaml$
    age: "age1your-public-key-here"
```

#### 4. Create your encrypted secrets file

```bash
# Copy the example template
cp secrets.enc.yaml.example secrets.enc.yaml

# Edit with your real API keys -- SOPS encrypts on save
sops secrets.enc.yaml
```

Inside the editor, replace the placeholder values with your actual keys:

```yaml
URLHAUS_AUTH_KEY: "your-real-key"
THREATFOX_AUTH_KEY: "your-real-key"
OTX_API_KEY: "your-real-key"
ABUSEIPDB_KEY: "your-real-key"
```

Save and close. SOPS encrypts the file automatically. The encrypted file is gitignored by default.

#### 5. Verify it works

```bash
# Decrypt and print (to verify)
sops -d secrets.enc.yaml

# Run IOC update (auto-detects SOPS)
bash scripts/update_iocs.sh
```

### How it loads secrets

`update_iocs.sh` tries secrets sources in this order:

1. **SOPS** -- looks for `secrets.enc.yaml` walking up from the script directory. Requires `sops` in PATH and the age key at `~/.config/sops/age/keys.txt`.
2. **Plain .env** -- fallback. Prints a warning suggesting migration to SOPS.
3. **Environment variables** -- if already exported (e.g. in CI), used directly.

### Sharing secrets with a team

If multiple people need access, add all their age public keys to `.sops.yaml`:

```yaml
creation_rules:
  - path_regex: secrets\.enc\.yaml$
    age: "age1alice...,age1bob...,age1charlie..."
```

Then re-encrypt:

```bash
sops updatekeys secrets.enc.yaml
```

### API keys reference

| Variable | Service | Free tier | Get key at |
|---|---|---|---|
| `URLHAUS_AUTH_KEY` | URLhaus (abuse.ch) | Yes | <https://auth.abuse.ch/> |
| `THREATFOX_AUTH_KEY` | ThreatFox (abuse.ch) | Yes | <https://auth.abuse.ch/> |
| `OTX_API_KEY` | AlienVault OTX | Yes (unlimited) | <https://otx.alienvault.com/api> |
| `ABUSEIPDB_KEY` | AbuseIPDB | Yes (1,000/day) | <https://www.abuseipdb.com/account/plans> |

> **Note:** URLhaus and ThreatFox both use abuse.ch authentication. A single registration gives you an Auth-Key that works for both services.

---

## Integrating External IOC / Threat Intelligence APIs

The security agent ships with a bundled static IOC library (`references/iocs.json`), but you can extend it by integrating external threat intelligence APIs to keep your IOC database up to date automatically.

### Architecture overview

```
External API  -->  fetch script  -->  references/iocs.json  -->  sentinel_preflight.py
                   (cron/CI)          (merged IOCs)              (runtime checks)
```

The approach is simple: a script fetches IOCs from one or more APIs, merges them into `iocs.json`, and the runtime engine picks them up on the next tool call. No restart needed -- the Python hook reloads `iocs.json` on every invocation.

### Running IOC updates

```bash
# Automatic (detects SOPS or .env)
bash scripts/update_iocs.sh

# Explicit SOPS invocation
sops exec-env secrets.enc.yaml 'bash scripts/update_iocs.sh'

# With environment variables directly
URLHAUS_AUTH_KEY=xxx THREATFOX_AUTH_KEY=xxx bash scripts/update_iocs.sh
```

### Supported API integrations

#### 1. URLhaus (abuse.ch)

Tracks malicious URLs used for malware distribution. **Requires Auth-Key since 2025.**

```bash
# Fetched automatically by update_iocs.sh
# Manual test:
curl -s -H "Auth-Key: $URLHAUS_AUTH_KEY" \
  "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/" \
  | python3 scripts/import_urlhaus.py
```

**API reference:** <https://urlhaus-api.abuse.ch/>

#### 2. ThreatFox (abuse.ch)

Free IOC sharing platform. Tracks C2, malware configs, and payloads. **Requires Auth-Key since 2025.**

```bash
# Fetched automatically by update_iocs.sh
# Manual test:
curl -s -X POST "https://threatfox-api.abuse.ch/api/v1/" \
  -H "Auth-Key: $THREATFOX_AUTH_KEY" \
  -H "Content-Type: application/json" \
  -d '{"query": "get_iocs", "days": 7}' \
  | python3 scripts/import_threatfox.py
```

**API reference:** <https://threatfox.abuse.ch/api/>

#### 3. AlienVault OTX (Open Threat Exchange)

Free tier available. Provides pulses with domains, IPs, URLs, and file hashes.

```bash
# Fetched automatically by update_iocs.sh
# Manual test:
curl -s -H "X-OTX-API-KEY: $OTX_API_KEY" \
  "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50" \
  | python3 scripts/import_otx.py
```

**API reference:** <https://otx.alienvault.com/assets/s/v2/api_doc.html>

#### 4. AbuseIPDB

Check and report malicious IPs. Free tier: 1,000 checks/day.

```bash
# Fetched automatically by update_iocs.sh
# Manual test:
curl -s -G "https://api.abuseipdb.com/api/v2/blacklist" \
  -H "Key: $ABUSEIPDB_KEY" \
  -H "Accept: application/json" \
  -d "confidenceMinimum=90" \
  -d "limit=500" \
  | python3 scripts/import_abuseipdb.py
```

**API reference:** <https://docs.abuseipdb.com/>

#### 5. MISP (Malware Information Sharing Platform)

For organizations running their own MISP instance or connecting to community instances.

```bash
export MISP_URL="https://your-misp-instance.org"
export MISP_API_KEY="your-key-here"

curl -s -X POST "$MISP_URL/events/restSearch" \
  -H "Authorization: $MISP_API_KEY" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"tags": ["mcp", "supply-chain"], "published": true, "limit": 50}' \
  | python3 scripts/import_misp.py
```

**API reference:** <https://www.misp-project.org/openapi/>

### Writing an import script

All import scripts follow the same pattern: read JSON from stdin, extract relevant IOCs, merge into `iocs.json`. See `scripts/import_template.py` for a full template.

### Automating IOC updates

#### With cron (Linux/macOS)

```bash
crontab -e

# Fetch IOCs every 6 hours
0 */6 * * * /path/to/opencode-security-agent/scripts/update_iocs.sh >> /var/log/ioc-updates.log 2>&1
```

#### With GitHub Actions

```yaml
# .github/workflows/update-iocs.yml
name: Update IOC database
on:
  schedule:
    - cron: '0 */6 * * *'
  workflow_dispatch:

jobs:
  update:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install sops and age
        run: |
          sudo apt-get install -y age
          curl -LO https://github.com/getsops/sops/releases/download/v3.9.4/sops-v3.9.4.linux.amd64
          sudo mv sops-v3.9.4.linux.amd64 /usr/local/bin/sops
          sudo chmod +x /usr/local/bin/sops

      - name: Decrypt secrets and update IOCs
        env:
          SOPS_AGE_KEY: ${{ secrets.SOPS_AGE_KEY }}
        run: bash scripts/update_iocs.sh

      - name: Commit updated IOCs
        run: |
          git config user.name "IOC Bot"
          git config user.email "bot@example.com"
          git add references/iocs.json
          git diff --cached --quiet || git commit -m "chore: update IOC database"
          git push
```

> **GitHub Actions with SOPS:** Store your age private key as a GitHub secret named `SOPS_AGE_KEY`. SOPS reads it from the environment variable automatically.

---

## Threat database

The agent maintains a local JSON database at `.security/mcp-sentinel-threats.json` that grows with each scan.

## Benchmarks

### v2 runtime plugin (55 regression cases in `tests/test_hook.py`)

| Category | Cases | Result |
|---|---|---|
| Benign tool calls correctly allowed | 6 | 6/6 |
| Credential-harvesting attacks blocked | 4 | 4/4 |
| Network exfil blocked (incl. Postmark `giftshop.club` IOC) | 4 | 4/4 |
| Dangerous commands blocked (reverse shell, `.bashrc` hijack) | 4 | 4/4 |
| DNS/ICMP exfiltration blocked | 4 | 4/4 |
| Polyglot code execution blocked (Python, Ruby, Perl, AWK, Node) | 5 | 5/5 |
| Environment/history enumeration blocked | 4 | 4/4 |
| Dot-file/credential discovery blocked | 7 | 7/7 |
| Network tools to raw IPs blocked | 2 | 2/2 |
| Typosquatting domain detection | 2 | 2/2 |
| Prompt injection detection | 2 | 2/2 |
| Self-protection (allowlist/iocs write blocked) | 6 | 6/6 |
| Fail-open on malformed / empty input | 3 | 3/3 |
| Human guidance hints | 2 | 2/2 |
| **Total** | **55** | **55/55** |

Overhead: ~30-80 ms per tool call. Zero LLM tokens in normal operation.

### Semgrep rules (32 regression cases in `tests/test_semgrep_rules.py`)

| Category | Cases | Result |
|---|---|---|
| Rule validation (custom + community) | 2 | 2/2 |
| Postmark BCC backdoor detection | 2 | 2/2 |
| Credential harvesting (file read + env dump + exfil) | 4 | 4/4 |
| Reverse shell + persistence + crypto mining | 5 | 5/5 |
| Prompt injection + eval in MCP tools | 3 | 3/3 |
| Deserialization attacks (pickle, yaml, marshal) | 4 | 4/4 |
| child_process abuse + dynamic method exec | 3 | 3/3 |
| Benign samples: zero false positives | 4 | 4/4 |
| Overall coverage (all malicious detected, all benign clean) | 2 | 2/2 |
| Semgrep availability check | 1 | 1/1 |
| **Total** | **32** | **32/32** |

6 malicious samples, 4 benign samples. Zero false positives on benign code.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines on how to contribute.

Found a vulnerability? See [SECURITY.md](./SECURITY.md) for responsible disclosure.

## Legal

### License

This project is licensed under the [GNU General Public License v3.0](./LICENSE).

### Disclaimer

This software is provided "as is", without warranty of any kind. This is a security tool that helps detect potential threats, but it does not guarantee the detection of all vulnerabilities or malicious code.

### Attribution

Based on the architecture of [MCP Sentinel](https://github.com/soy-rafa/claude-mcp-sentinel) by Rafael Tunon Sanchez. Adapted for the OpenCode ecosystem.

---

## Layout

```
opencode-security-agent/
├── README.md                                    # this file
├── CHANGELOG.md                                 # version history
├── CONTRIBUTING.md                              # contribution guidelines
├── SECURITY.md                                  # vulnerability disclosure policy
├── LICENSE                                      # GPL-3.0
├── action.yml                                   # GitHub Action (reusable)
├── .sops.yaml                                   # SOPS encryption config (age backend)
├── secrets.enc.yaml.example                     # template for API keys
├── plugins/                                     # v2 runtime protection
│   ├── security-agent.ts                        # OpenCode plugin (tool.execute.before)
│   └── sentinel_preflight.py                    # Python pattern matcher (called by plugin)
├── rules/                                       # Semgrep static analysis rules
│   └── semgrep/
│       ├── credential-exfiltration.yaml         # custom: credential file reads, env harvesting
│       ├── network-exfiltration.yaml            # custom: exfil services, raw IPs, hidden BCC
│       ├── dangerous-commands.yaml              # custom: curl|bash, reverse shells, eval
│       ├── supply-chain-patterns.yaml           # custom: crypto mining, prompt injection
│       ├── registry-metadata.yaml               # Semgrep Registry publishing metadata
│       └── community/                           # bundled from semgrep/semgrep-rules
│           ├── LICENSE                          # Semgrep Rules License
│           ├── ai-mcp/                          # MCP injection, poisoning, SSRF, LLM-to-exec
│           ├── python-exec/                     # os.system, subprocess, eval, reverse shells
│           ├── python-deser/                    # pickle, jsonpickle, pyyaml, marshal
│           ├── python-secrets/                  # hardcoded passwords, credential logging
│           ├── javascript-exec/                 # child_process, eval, spawn, dynamic methods
│           ├── generic-secrets/                 # private keys, API keys, AWS/GitHub tokens
│           └── generic-shells/                  # bash reverse shell patterns
├── scripts/                                     # install/uninstall + IOC import helpers
│   ├── install.sh
│   ├── uninstall.sh
│   ├── scan_semgrep.sh                          # Semgrep static scanner wrapper
│   ├── update_iocs.sh                           # orchestrator: fetches all IOC sources
│   ├── import_urlhaus.py                        # URLhaus importer
│   ├── import_threatfox.py                      # ThreatFox importer
│   ├── import_otx.py                            # AlienVault OTX importer
│   ├── import_abuseipdb.py                      # AbuseIPDB importer
│   ├── import_misp.py                           # MISP importer
│   └── import_template.py                       # template for writing new importers
├── skills/
│   └── security-agent/
│       └── SKILL.md                             # v1 static scanner skill
├── references/
│   ├── iocs.json                                # indicator library
│   ├── threat-sources.md                        # vulnerability database + API reference
│   └── threat-db-template.json                  # local threat DB schema
└── tests/
    ├── test_hook.py                             # regression tests for the Python hook (55)
    ├── test_semgrep_rules.py                    # regression tests for Semgrep rules (32)
    └── semgrep-samples/                         # test corpus for Semgrep rules
        ├── malicious/                           # 6 samples reproducing real attack patterns
        │   ├── postmark_bcc_backdoor.py         # Postmark MCP incident reproduction
        │   ├── credential_harvester.js          # SSH/AWS credential theft + webhook exfil
        │   ├── reverse_shell_persistence.py     # reverse shell + bashrc + crypto mining
        │   ├── prompt_injection_tool.js         # LLM prompt injection in tool description
        │   ├── deserialization_dns_exfil.py     # pickle/yaml/marshal + DNS exfiltration
        │   └── child_process_abuse.js           # child_process + eval + spawn shell
        └── benign/                              # 4 samples that must produce zero findings
            ├── normal_file_ops.py
            ├── normal_http_client.js
            ├── legitimate_mcp_server.py
            └── legitimate_skill.ts
```
