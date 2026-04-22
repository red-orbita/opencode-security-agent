# OpenCode Security Agent

Security agent for OpenCode. **v2 blocks malicious tool calls in real time** -- a plugin using `tool.execute.before` stops credential exfiltration, known-bad domains (`giftshop.club` from the Postmark MCP backdoor is hardcoded), reverse shells, `curl|bash` pipes, and prompt injection attempts before they execute. The v1 static scanner is still here: vulnerability database scanning, source integrity verification, and coherence analysis.

**License:** [GPL-3.0](./LICENSE)
**Latest version:** 1.3.0 -- April 2026 ([changelog](./CHANGELOG.md))

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

- **Sensitive paths** -- reads of `~/.ssh/`, `~/.aws/`, `~/.env`, `credentials.json`, `/etc/shadow` are blocked. Paths embedded in bash commands (e.g. `cat ~/.aws/credentials`) are also detected.
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
# 1. Run the regression suite (standalone hook -- 55 tests)
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

## Integrating External IOC / Threat Intelligence APIs

The security agent ships with a bundled static IOC library (`references/iocs.json`), but you can extend it by integrating external threat intelligence APIs to keep your IOC database up to date automatically. This section describes how to connect to different APIs and feed their data into the agent.

### Architecture overview

```
External API  -->  fetch script  -->  references/iocs.json  -->  sentinel_preflight.py
                   (cron/CI)          (merged IOCs)              (runtime checks)
```

The approach is simple: a script fetches IOCs from one or more APIs, merges them into `iocs.json`, and the runtime engine picks them up on the next tool call. No restart needed -- the Python hook reloads `iocs.json` on every invocation.

### Supported API integrations

#### 1. AlienVault OTX (Open Threat Exchange)

Free tier available. Provides pulses with domains, IPs, URLs, and file hashes.

```bash
# Get your API key at https://otx.alienvault.com/api
export OTX_API_KEY="your-key-here"

# Fetch malicious domains from a pulse
curl -s -H "X-OTX-API-KEY: $OTX_API_KEY" \
  "https://otx.alienvault.com/api/v1/indicators/domain/giftshop.club/general" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(json.dumps({
    'domain': data.get('indicator'),
    'incident': 'OTX pulse: ' + str(data.get('pulse_info', {}).get('count', 0)) + ' pulses',
    'reference': 'https://otx.alienvault.com/indicator/domain/' + data.get('indicator', '')
}, indent=2))
"

# Fetch all IOCs from subscribed pulses (last 30 days)
curl -s -H "X-OTX-API-KEY: $OTX_API_KEY" \
  "https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since=$(date -d '30 days ago' +%Y-%m-%dT00:00:00+00:00)&limit=50" \
  | python3 scripts/import_otx.py
```

**API reference**: https://otx.alienvault.com/assets/s/v2/api_doc.html

#### 2. AbuseIPDB

Check and report malicious IPs. Free tier: 1,000 checks/day.

```bash
export ABUSEIPDB_KEY="your-key-here"

# Check a specific IP
curl -s -G "https://api.abuseipdb.com/api/v2/check" \
  -H "Key: $ABUSEIPDB_KEY" \
  -H "Accept: application/json" \
  -d "ipAddress=185.220.101.42" \
  -d "maxAgeInDays=90" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)['data']
if data['abuseConfidenceScore'] > 50:
    print(f\"MALICIOUS: {data['ipAddress']} (confidence: {data['abuseConfidenceScore']}%, reports: {data['totalReports']})\")
"

# Bulk export blacklisted IPs (confidence > 90%)
curl -s -G "https://api.abuseipdb.com/api/v2/blacklist" \
  -H "Key: $ABUSEIPDB_KEY" \
  -H "Accept: application/json" \
  -d "confidenceMinimum=90" \
  -d "limit=500" \
  | python3 scripts/import_abuseipdb.py
```

**API reference**: https://docs.abuseipdb.com/

#### 3. VirusTotal

Check domains, IPs, URLs, and file hashes against 70+ antivirus engines. Free tier: 4 lookups/minute, 500/day.

```bash
export VT_API_KEY="your-key-here"

# Check a domain
curl -s "https://www.virustotal.com/api/v3/domains/giftshop.club" \
  -H "x-apikey: $VT_API_KEY" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
malicious = stats.get('malicious', 0)
print(f\"Detections: {malicious} engines flagged as malicious\")
if malicious > 0:
    print('ACTION: Add to iocs.json known_malicious_domains')
"

# Check a URL
curl -s -X POST "https://www.virustotal.com/api/v3/urls" \
  -H "x-apikey: $VT_API_KEY" \
  -d "url=https://suspicious-site.example/payload"
```

**API reference**: https://developers.virustotal.com/reference/overview

#### 4. Shodan

Search for exposed services and known-malicious infrastructure. Free tier available with limited queries.

```bash
export SHODAN_API_KEY="your-key-here"

# Check a specific IP
curl -s "https://api.shodan.io/shodan/host/185.220.101.42?key=$SHODAN_API_KEY" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(f\"IP: {data.get('ip_str')}\")
print(f\"Org: {data.get('org')}\")
print(f\"OS: {data.get('os')}\")
print(f\"Ports: {data.get('ports')}\")
if data.get('tags'):
    print(f\"Tags: {data['tags']}\")
"

# Search for C2 infrastructure patterns
curl -s "https://api.shodan.io/shodan/host/search?key=$SHODAN_API_KEY&query=product:cobalt+strike"
```

**API reference**: https://developer.shodan.io/api

#### 5. MISP (Malware Information Sharing Platform)

For organizations running their own MISP instance or connecting to community instances.

```bash
export MISP_URL="https://your-misp-instance.org"
export MISP_API_KEY="your-key-here"

# Search for IOCs related to MCP/skill attacks
curl -s -X POST "$MISP_URL/events/restSearch" \
  -H "Authorization: $MISP_API_KEY" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"tags": ["mcp", "supply-chain"], "published": true, "limit": 50}' \
  | python3 scripts/import_misp.py

# Get specific attributes (domains, IPs)
curl -s -X POST "$MISP_URL/attributes/restSearch" \
  -H "Authorization: $MISP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"type": ["domain", "ip-dst", "url"], "to_ids": true, "limit": 200}'
```

**API reference**: https://www.misp-project.org/openapi/

#### 6. OpenCTI (Open Cyber Threat Intelligence)

GraphQL-based threat intelligence platform.

```bash
export OPENCTI_URL="https://your-opencti-instance.org"
export OPENCTI_TOKEN="your-token-here"

# Query indicators
curl -s -X POST "$OPENCTI_URL/graphql" \
  -H "Authorization: Bearer $OPENCTI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { indicators(first: 100, filters: { mode: and, filters: [{ key: \"pattern_type\", values: [\"stix\"] }], filterGroups: [] }) { edges { node { name pattern valid_from } } } }"
  }'
```

**API reference**: https://docs.opencti.io/latest/deployment/integrations/

#### 7. URLhaus (abuse.ch)

Free, no API key needed. Tracks malicious URLs used for malware distribution.

```bash
# Check a URL
curl -s -X POST "https://urlhaus-api.abuse.ch/v1/url/" \
  -d "url=https://suspicious.example/malware.exe"

# Get recent additions (last 24h)
curl -s "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/" \
  | python3 scripts/import_urlhaus.py

# Download the full feed (CSV, updated every 5 min)
curl -s "https://urlhaus.abuse.ch/downloads/csv_recent/" > /tmp/urlhaus_recent.csv
```

**API reference**: https://urlhaus-api.abuse.ch/

#### 8. ThreatFox (abuse.ch)

Free IOC sharing platform. Tracks C2, malware configs, and payloads.

```bash
# Query IOCs by tag
curl -s -X POST "https://threatfox-api.abuse.ch/api/v1/" \
  -H "Content-Type: application/json" \
  -d '{"query": "taginfo", "tag": "cobalt-strike", "limit": 50}'

# Get recent IOCs
curl -s -X POST "https://threatfox-api.abuse.ch/api/v1/" \
  -H "Content-Type: application/json" \
  -d '{"query": "get_iocs", "days": 7}'
```

**API reference**: https://threatfox.abuse.ch/api/

### Writing an import script

All import scripts follow the same pattern: fetch from API, extract relevant IOCs, merge into `iocs.json`. Here's a template (also available at `scripts/import_template.py`):

```python
#!/usr/bin/env python3
"""Import IOCs from an external API into iocs.json."""

import json
import sys
from pathlib import Path

IOCS_PATH = Path(__file__).parent.parent / "references" / "iocs.json"


def load_iocs():
    if IOCS_PATH.exists():
        return json.loads(IOCS_PATH.read_text())
    return {}


def save_iocs(iocs):
    IOCS_PATH.write_text(json.dumps(iocs, indent=2) + "\n")


def merge_domains(iocs, new_domains):
    """Merge new malicious domains into the IOC library."""
    existing = iocs.setdefault("suspicious_network", {})
    known = existing.setdefault("known_malicious_domains", [])
    existing_domains = {e["domain"].lower() for e in known}

    added = 0
    for entry in new_domains:
        if entry["domain"].lower() not in existing_domains:
            known.append(entry)
            existing_domains.add(entry["domain"].lower())
            added += 1

    return added


def merge_ips(iocs, new_patterns):
    """Merge new suspicious IP patterns."""
    existing = iocs.setdefault("suspicious_network", {})
    patterns = existing.setdefault("suspicious_patterns", [])

    added = 0
    for p in new_patterns:
        if p not in patterns:
            patterns.append(p)
            added += 1

    return added


def main():
    data = json.load(sys.stdin)
    iocs = load_iocs()

    # --- Adapt this section for each API ---
    new_domains = []
    for item in data.get("results", []):
        new_domains.append({
            "domain": item["indicator"],
            "incident": f"Imported from API on {item.get('date', 'unknown')}",
            "reference": item.get("reference", ""),
        })

    added = merge_domains(iocs, new_domains)
    # --- End API-specific section ---

    save_iocs(iocs)
    print(f"Merged {added} new IOCs into {IOCS_PATH}", file=sys.stderr)


if __name__ == "__main__":
    main()
```

### Automating IOC updates

#### With cron (Linux/macOS)

```bash
# Edit crontab
crontab -e

# Fetch OTX pulses every 6 hours
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
      - name: Fetch OTX IOCs
        env:
          OTX_API_KEY: ${{ secrets.OTX_API_KEY }}
        run: |
          curl -s -H "X-OTX-API-KEY: $OTX_API_KEY" \
            "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50" \
            | python3 scripts/import_otx.py
      - name: Fetch URLhaus IOCs
        run: |
          curl -s "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/" \
            | python3 scripts/import_urlhaus.py
      - name: Commit updated IOCs
        run: |
          git config user.name "IOC Bot"
          git config user.email "bot@example.com"
          git add references/iocs.json
          git diff --cached --quiet || git commit -m "chore: update IOC database"
          git push
```

### Custom IOC providers

You can add your own IOC provider by:

1. Creating a script in `scripts/import_<provider>.py` following the template above
2. Adding the API details to `references/threat-sources.md`
3. Adding a cron job or CI step to run it periodically

The merge functions in the template handle deduplication automatically -- you can run imports multiple times safely.

### Environment variables for API keys

Store API keys securely. Never commit them to the repository.

| Variable | Service | Free tier |
|---|---|---|
| `OTX_API_KEY` | AlienVault OTX | Yes (unlimited) |
| `ABUSEIPDB_KEY` | AbuseIPDB | Yes (1,000/day) |
| `VT_API_KEY` | VirusTotal | Yes (500/day) |
| `SHODAN_API_KEY` | Shodan | Yes (limited) |
| `MISP_API_KEY` | MISP instance | Self-hosted |
| `OPENCTI_TOKEN` | OpenCTI instance | Self-hosted |

URLhaus and ThreatFox from abuse.ch require **no API key**.

---

## Threat database

The agent maintains a local JSON database at `.security/mcp-sentinel-threats.json` that grows with each scan.

## Benchmarks

### v2 runtime plugin (22 regression cases in `tests/test_hook.py`)

| Category | Cases | Result |
|---|---|---|
| Benign tool calls correctly allowed | 5 | 5/5 |
| Credential-harvesting attacks blocked | 4 | 4/4 |
| Network exfil blocked (incl. Postmark `giftshop.club` IOC) | 4 | 4/4 |
| Dangerous commands blocked (`curl\|bash`, reverse shell, `.bashrc` hijack) | 4 | 4/4 |
| Prompt injection detection | 2 | 2/2 |
| Fail-open on malformed / empty input | 3 | 3/3 |
| **Total** | **22** | **22/22** |

Overhead: ~30-80 ms per tool call. Zero LLM tokens in normal operation.

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
├── plugins/                                     # v2 runtime protection
│   ├── security-agent.ts                        # OpenCode plugin (tool.execute.before)
│   └── sentinel_preflight.py                    # Python pattern matcher (called by plugin)
├── scripts/                                     # install/uninstall + IOC import helpers
│   ├── install.sh
│   ├── uninstall.sh
│   └── import_template.py                       # template for writing API import scripts
├── skills/
│   └── security-agent/
│       └── SKILL.md                             # v1 static scanner skill
├── references/
│   ├── iocs.json                                # indicator library
│   ├── threat-sources.md                        # vulnerability database + API reference
│   └── threat-db-template.json                  # local threat DB schema
└── tests/
    └── test_hook.py                             # regression tests for the Python hook
```
