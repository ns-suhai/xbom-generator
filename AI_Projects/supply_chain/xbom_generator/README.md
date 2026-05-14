# xBOM Generator

Extended Bill of Materials (xBOM) generator for binary and source analysis. Produces CycloneDX-compliant BOMs covering software dependencies, SaaS services, ML models, cryptographic assets, secrets, agent skills, and MCP server configurations.

## Features

- **SBOM** — Software Bill of Materials from binary decomposition (requires `syft`)
- **SaaSBOM** — Detect SaaS/API endpoints referenced in code
- **ML-BOM** — Identify ML model files and frameworks
- **CBOM** — Cryptographic asset inventory (algorithms, certificates, key sizes)
- **Secrets** — Detect exposed credentials and API keys (requires `trufflehog`)
- **SkillBOM** — Agent supply chain analysis for skills, plugins, and MCP configs
- **MCP-BOM** — MCP server configuration analysis with permission mapping
- **Agent Manifest** — Autonomy classification (L0–L4) based on tool access

### SkillBOM Detection Capabilities

| Category | Severity | What it detects |
|----------|----------|-----------------|
| Shell execution | HIGH | Bash tool use, subprocess calls, dangerous shell commands |
| Data exfiltration | CRITICAL | POST to external URLs, ngrok/webhook.site/pastebin |
| Prompt injection | CRITICAL | Instruction override attempts, hidden HTML comments |
| Credential access | HIGH | SSH keys, API keys, .env files, credential stores |
| File system overreach | HIGH | Writing to system files, chmod 777, shell profiles |
| Network tunneling | CRITICAL | ngrok, netcat listeners, reverse shells, SSH tunnels |
| Permission escalation | MEDIUM | dangerouslySkipPermissions, --no-verify |
| Obfuscation | HIGH | Base64 decode piped to shell, hex-encoded payloads |
| Hardcoded C2 | HIGH | Public IP addresses in code (excludes version strings) |
| Hardcoded credentials | HIGH | Tokens, openids, API keys in code or referenced scripts |
| Suspicious API endpoints | MEDIUM | Unknown/unverified API domains |
| Affiliate tracking | MEDIUM | Invite codes, referral IDs, affiliate parameters |

### Cross-File Execution Tracing

The SkillBOM analyzer follows script references in skill files:

```
SKILL.md → "uv run scripts/main.py" → scripts/main.py (scanned for patterns)
```

Supported script invocation patterns:
- `uv run <script.py>`
- `python3 <script.py>`, `python <script.py>`
- `node <script.js>`, `ruby <script.rb>`
- `bash <script.sh>`, `sh <script.sh>`
- `./<script.py>` (directly executable)

Referenced scripts are:
1. Scanned for all detection patterns (same as skill files)
2. Checked for hardcoded public IP addresses
3. Included in the execution graph (network targets, file access, env vars)

## Installation

```bash
pip install -e .
```

Optional dependencies for full analysis:
```bash
# SBOM generation
brew install syft

# Secret scanning
brew install trufflehog

# File type detection
pip install python-magic
```

## Usage

### CLI

```bash
# Scan a package file (zip, tar.gz, jar, deb, rpm, etc.)
xbom scan package.tar.gz

# Scan a directory directly (skill folder, plugin, source tree)
xbom scan ./my-skill/

# Output as HTML report
xbom scan ./my-skill/ --format html

# Both JSON and HTML
xbom scan package.zip --format both --output-dir ./reports/

# Skip specific analyzers
xbom scan ./project/ --skip-analyzers sbom,secrets

# Enable Netskope telemetry enrichment
xbom scan package.jar --enrich

# Verbose logging
xbom scan ./skill/ --verbose
```

### Python API

```python
from pathlib import Path
from xbom.scanner import scan_directory, scan_package

# Scan a directory
result = scan_directory(Path("./my-skill/"))

# Scan a package
result = scan_package(Path("artifact.tar.gz"))

# Access results
print(f"SAFE {result.safe_level.value} ({result.safe_level.label})")
print(f"Risk score: {result.risk_score:.2f}")
print(f"Skills: {len(result.skill_entries)} files")

for entry in result.skill_entries:
    print(f"  {entry.name}: {entry.metadata['finding_count']} findings")
    print(f"  Max severity: {entry.metadata['max_severity']}")
    print(f"  Referenced scripts: {entry.metadata.get('referenced_scripts', [])}")
    graph = entry.metadata["execution_graph"]
    print(f"  Execution graph: {len(graph['nodes'])} nodes")
```

## Output

### SAFE Score (1-5)

| Level | Label | Score Range |
|-------|-------|-------------|
| 5 | Excellent | >= 4.5 |
| 4 | Good | >= 3.5 |
| 3 | Moderate | >= 2.5 |
| 2 | Needs Work | >= 1.5 |
| 1 | Critical | < 1.5 |

### CycloneDX JSON

Output follows CycloneDX 1.6 specification with xBOM extensions:
- Components (SBOM, ML-BOM)
- Services (SaaSBOM)
- Cryptographic properties (CBOM)
- Custom properties for skills, secrets, and agent manifest

### Execution Graph

Each skill produces an execution graph mapping:
- **tool_call** — Claude/agent tools invoked (Bash, Read, Write, etc.)
- **shell_command** — CLI tools called (curl, npm, docker, etc.)
- **network_target** — External domains contacted
- **file_access** — Sensitive file paths accessed
- **skill_call** — Other skills invoked
- **mcp_call** — MCP server tools called
- **env_access** — Environment variables read
- **referenced_script** — Scripts executed by the skill

## Architecture

```
xbom/
├── scanner.py          # Orchestrator: scan_package() and scan_directory()
├── unpacker.py         # Extract archives (zip, tar, jar, deb, rpm)
├── classifier.py       # Classify files by type (magic bytes + extensions)
├── analyzers/
│   ├── sbom.py         # Software dependencies (via syft)
│   ├── saasbom.py      # SaaS/API endpoint detection
│   ├── mlbom.py        # ML model identification
│   ├── cbom.py         # Cryptographic asset detection
│   ├── secrets.py      # Secret/credential scanning (via trufflehog)
│   ├── skillbom.py     # Agent skill analysis + cross-file tracing
│   └── mcp.py          # MCP server configuration analysis
├── scoring/
│   └── risk_scorer.py  # Composite SAFE score (weighted dimensions)
├── enrichment/
│   ├── ecosystem_enricher.py   # Skill ecosystem metadata
│   └── netskope_telemetry.py   # SaaS traffic enrichment
├── models/
│   └── bom_types.py    # Data models (BomEntry, ScanResult, etc.)
├── agent_manifest.py   # Autonomy level classification (L0-L4)
├── assembler.py        # CycloneDX JSON output
├── report/
│   └── html_generator.py  # HTML report generation
└── cli.py              # Click CLI entry point
```

## Development

```bash
# Run tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=xbom --cov-report=term-missing

# Type checking
mypy xbom/ --strict
```

## License

Internal use only.
