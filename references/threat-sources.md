# Threat Intelligence Sources -- Reference Guide

This document contains detailed information about each threat source the OpenCode Security Agent uses, including both web-search sources (v1 static scanner) and API-based sources (IOC imports).

## Table of Contents

### Web search sources (v1 static scanner)
1. GitHub Advisory Database
2. VulnerableMCP.info
3. MCPScan.ai
4. Snyk / ToxicSkills Research
5. ClawHub / OpenClaw Registry
6. OWASP Frameworks
7. Reddit r/ClaudeAI
8. Anthropic Discord
9. GitHub Issues on MCP repos

### API sources (IOC imports for v2 runtime)
10. AlienVault OTX
11. AbuseIPDB
12. VirusTotal
13. Shodan
14. MISP
15. OpenCTI
16. URLhaus (abuse.ch)
17. ThreatFox (abuse.ch)

---

## Web Search Sources

### 1. GitHub Advisory Database

**URL**: https://github.com/advisories
**Type**: Formal CVE database
**Reliability**: Very high -- peer-reviewed, linked to NVD
**Search strategy**:
- Search by package name: `[package] type:reviewed`
- Search by ecosystem: filter by npm, pip, etc.
**What you'll find**: CVE IDs, CVSS scores, affected version ranges, patched versions

### 2. VulnerableMCP.info

**URL**: https://vulnerablemcp.info
**Type**: Dedicated MCP vulnerability tracker
**Reliability**: High -- specialized, community-maintained
**Note**: This is one of the most targeted sources -- always check here first for MCP-specific issues.

### 3. MCPScan.ai

**URL**: https://mcpscan.ai
**Type**: Automated MCP security scanner
**Reliability**: High -- automated analysis

### 4. Snyk / ToxicSkills

**URL**: https://snyk.io
**Type**: Enterprise security research
**Key research**: "ToxicSkills" study identified 1,467 malicious ClawHub skills

### 5. ClawHub / OpenClaw

**URL**: https://openclaw.ai
**Type**: Skill registry with security scanning
**Reliability**: Medium-high -- has VirusTotal integration

### 6. OWASP Frameworks

**URLs**:
- https://owasp.org/www-project-agentic-skills-top-10/
- https://owasp.org/www-project-mcp-top-10/

**Type**: Security frameworks and classification

### 7. Reddit r/ClaudeAI

**URL**: https://reddit.com/r/ClaudeAI
**Type**: Community early warning
**Caveat**: Community reports need cross-referencing.

### 8. Anthropic Discord

**Type**: Community early warning
**Channels**: #mcp, #claude-code

### 9. GitHub Issues on MCP repos

**Key repos to monitor**:
- `modelcontextprotocol/servers` -- official MCP server implementations
- `modelcontextprotocol/specification` -- protocol spec issues

---

## API Sources (IOC Imports)

These sources provide structured APIs that can be used to automatically import IOCs into `references/iocs.json`. See the README section "Integrating External IOC / Threat Intelligence APIs" for usage examples.

### 10. AlienVault OTX (Open Threat Exchange)

**URL**: https://otx.alienvault.com
**API docs**: https://otx.alienvault.com/assets/s/v2/api_doc.html
**Type**: Community threat intelligence platform
**Reliability**: High -- large community, curated pulses
**API key**: Required (free registration)
**Rate limits**: Generous free tier
**Data types**: Domains, IPs, URLs, file hashes, YARA rules
**Import script**: `scripts/import_otx.py`
**Key endpoints**:
- `GET /api/v1/pulses/subscribed` -- IOCs from subscribed pulses
- `GET /api/v1/indicators/domain/{domain}/general` -- domain reputation
- `GET /api/v1/indicators/IPv4/{ip}/general` -- IP reputation

### 11. AbuseIPDB

**URL**: https://www.abuseipdb.com
**API docs**: https://docs.abuseipdb.com/
**Type**: IP reputation database
**Reliability**: High -- community-reported, confidence scoring
**API key**: Required (free: 1,000 checks/day)
**Data types**: IP addresses with abuse confidence scores
**Import script**: `scripts/import_abuseipdb.py`
**Key endpoints**:
- `GET /api/v2/check` -- check a single IP
- `GET /api/v2/blacklist` -- bulk export of known-bad IPs

### 12. VirusTotal

**URL**: https://www.virustotal.com
**API docs**: https://developers.virustotal.com/reference/overview
**Type**: Multi-engine malware/URL scanner
**Reliability**: Very high -- 70+ antivirus engines
**API key**: Required (free: 4 lookups/min, 500/day)
**Data types**: Domains, IPs, URLs, file hashes
**Import script**: `scripts/import_virustotal.py`
**Key endpoints**:
- `GET /api/v3/domains/{domain}` -- domain analysis
- `GET /api/v3/ip_addresses/{ip}` -- IP analysis
- `POST /api/v3/urls` -- submit URL for scanning

### 13. Shodan

**URL**: https://www.shodan.io
**API docs**: https://developer.shodan.io/api
**Type**: Internet-wide scan database
**Reliability**: Very high -- direct observation
**API key**: Required (free tier with limited queries)
**Data types**: IPs, open ports, services, banners, vulnerabilities
**Import script**: `scripts/import_shodan.py`
**Key endpoints**:
- `GET /shodan/host/{ip}` -- host details
- `GET /shodan/host/search` -- search by query

### 14. MISP (Malware Information Sharing Platform)

**URL**: https://www.misp-project.org
**API docs**: https://www.misp-project.org/openapi/
**Type**: Threat sharing platform (self-hosted or community instances)
**Reliability**: Very high -- structured, vetted IOCs
**API key**: Required (instance-specific)
**Data types**: Domains, IPs, URLs, file hashes, email addresses, YARA
**Import script**: `scripts/import_misp.py`
**Key endpoints**:
- `POST /events/restSearch` -- search events by tag/date
- `POST /attributes/restSearch` -- search individual IOC attributes

### 15. OpenCTI

**URL**: https://www.opencti.io
**API docs**: https://docs.opencti.io/latest/deployment/integrations/
**Type**: Cyber threat intelligence platform (GraphQL API)
**Reliability**: High -- STIX-based structured intelligence
**API key**: Required (instance-specific)
**Data types**: STIX indicators, threat actors, campaigns, attack patterns
**Import script**: `scripts/import_opencti.py`

### 16. URLhaus (abuse.ch)

**URL**: https://urlhaus.abuse.ch
**API docs**: https://urlhaus-api.abuse.ch/
**Type**: Malicious URL tracker
**Reliability**: High -- dedicated malware URL tracking
**API key**: Not required
**Rate limits**: Generous
**Data types**: URLs used for malware distribution
**Import script**: `scripts/import_urlhaus.py`
**Key endpoints**:
- `POST /v1/url/` -- check a URL
- `GET /v1/urls/recent/limit/{limit}/` -- recent malicious URLs

### 17. ThreatFox (abuse.ch)

**URL**: https://threatfox.abuse.ch
**API docs**: https://threatfox.abuse.ch/api/
**Type**: IOC sharing platform
**Reliability**: High -- focused on C2 and malware indicators
**API key**: Not required
**Data types**: Domains, IPs, URLs associated with malware/C2
**Import script**: `scripts/import_threatfox.py`
**Key endpoints**:
- `POST /api/v1/` with `query: get_iocs` -- recent IOCs
- `POST /api/v1/` with `query: taginfo` -- IOCs by tag

---

## Search priority order

### For v1 static scans (web search)
1. vulnerablemcp.info (most targeted)
2. GitHub Advisory Database (most authoritative)
3. mcpscan.ai (automated, quick results)
4. Snyk (deep research)
5. GitHub Issues (specific to the repo)
6. Reddit (early warnings)
7. ClawHub (if skill is from that registry)
8. Discord references (hardest to search)

### For v2 runtime IOC imports (API)
1. URLhaus + ThreatFox (free, no API key, malware-focused)
2. AlienVault OTX (free, broad coverage)
3. AbuseIPDB (free tier, IP reputation)
4. VirusTotal (authoritative, but rate-limited)
5. MISP / OpenCTI (if you have an instance)
6. Shodan (infrastructure intelligence)
