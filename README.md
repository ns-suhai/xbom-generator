# xBOM Generator

Extended Bill of Materials (xBOM) generator for software supply chain security. Produces **SBOM, SaaSBOM, ML-BOM, CBOM, secret detection, and AI agent skill scanning** from a single binary scan, output as CycloneDX v1.6 JSON.

```
$ xbom scan ai-app-v1.0.zip --format html

Scanning ai-app-v1.0.zip...
  Unpacking... done.

  SAFE 4 - Good (score: 4.20)

  SBOM:    127 components
  SaaSBOM: 6 services
  ML-BOM:  2 models
  CBOM:    11 crypto assets
  Secrets: 1 findings
  Skills:  3 files (2 clean, 1 CRITICAL)
  Duration: 283ms

  CycloneDX JSON: ./xbom-output/xbom-ai-app-v1.0.json
  HTML Report:    ./xbom-output/xbom-ai-app-v1.0.html
```

## What It Detects

| BOM Type | What | How | Output |
|----------|------|-----|--------|
| **SBOM** | Software components, dependencies, licenses | [syft](https://github.com/anchore/syft) (230+ package types) | CycloneDX components |
| **SaaSBOM** | API endpoints, cloud services, data flows | String extraction + URL filtering | CycloneDX services |
| **ML-BOM** | ML models (.onnx, .pt, .h5, .tflite, .safetensors) | File detection + metadata extraction | CycloneDX ML components |
| **CBOM** | Crypto algorithms, certificates, keys | Pattern matching + cert extraction | CycloneDX crypto properties |
| **Secrets** | API keys, tokens, credentials | [detect-secrets](https://github.com/Yelp/detect-secrets) (700+ patterns) | CycloneDX vulnerabilities |
| **SkillBOM** | AI agent skills, plugins, MCP configs | Static pattern analysis + Execution Graph | CycloneDX components |

**Netskope differentiator:** SaaSBOM entries can be enriched with real network telemetry from Netskope cloud activity logs, showing actual traffic volume, last seen date, and data classification. RL Spectra Assure cannot do this.

**Agent supply chain differentiator:** SkillBOM detects malicious AI agent skills (SKILL.md, plugins, MCP server configs) embedded in packages. Inspired by [Manifold Manifest](https://www.manifold.security/blog/manifest-ai-supply-chain-intelligence) research showing 800K+ skills across registries with 1,184 confirmed malicious. xBOM builds a local Execution Graph for each skill and flags 9 categories of malicious patterns. No other xBOM tool provides this.

## Installation

```bash
# Install xbom
pip install -e .

# Install syft (for SBOM generation)
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# detect-secrets is bundled as a pip dependency
```

### Prerequisites

- Python 3.11+
- [syft](https://github.com/anchore/syft) (optional, for SBOM)
- libmagic (`brew install libmagic` on macOS, `apt install libmagic1` on Debian)

## Usage

### Basic scan (JSON output)

```bash
xbom scan package.jar
```

Output: `./xbom-output/xbom-package.json` (CycloneDX v1.6)

### HTML report

```bash
xbom scan package.jar --format html
```

Opens an interactive single-file HTML report with:
- Risk score badge with radar chart breakdown
- Tabbed navigation (SBOM, SaaSBOM, ML-BOM, CBOM, Secrets, Skills)
- Search and filter across all BOM types
- Export CycloneDX JSON button

### Both JSON and HTML

```bash
xbom scan package.jar --format both --output-dir ./reports
```

### With Netskope telemetry enrichment

```bash
export NETSKOPE_API_TOKEN="your-token"
export NETSKOPE_TENANT_URL="https://your-tenant.goskope.com"

xbom scan package.jar --enrich
```

SaaSBOM entries gain: `actual_traffic_volume`, `last_seen`, `data_classification`, `bytes_sent`, `bytes_received`.

### AI Agent Skill Scanning (SkillBOM)

xBOM automatically detects and analyzes AI agent supply chain assets when found in packages. No extra flags needed.

**What it detects:**

| File Pattern | Asset Type |
|-------------|-----------|
| `SKILL.md`, `skill.md`, `skills/*.md` | SKILL.md standard files |
| `plugin.json`, `plugin.yaml` | Agent plugins |
| `.mcp.json`, `mcp.json`, `mcp-config.*` | MCP server configs |
| `action.yml`, `action.yaml` | GitHub Actions (composite) |
| `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` | Agent instruction files |
| `.claude/`, `.cursor/`, `.copilot/` | Agent config directories |

**What it flags (9 detection categories):**

| Category | Severity | Examples |
|----------|----------|---------|
| Data exfiltration | CRITICAL | `curl -X POST`, webhook URLs, ngrok, pastebin |
| Prompt injection | CRITICAL | "ignore previous instructions", hidden comments |
| Network tunneling | CRITICAL | ngrok, reverse shells, port forwarding |
| Shell execution | HIGH | Bash tool calls, `subprocess`, piped commands |
| Credential access | HIGH | `~/.ssh`, `API_KEY`, `.env`, keychain |
| File system overreach | HIGH | Writing to `/etc`, `~/.bashrc`, `chmod 777` |
| Obfuscation | HIGH | Base64 piped to sh, hex-encoded strings |
| Permission escalation | MEDIUM | `dangerouslySkipPermissions`, `--no-verify` |
| Typosquatting | MEDIUM | Skill names similar to well-known tools |

**Execution Graph:** For each skill file, xBOM builds a local Execution Graph that maps tool calls, shell commands, network targets, file access, skill-to-skill calls, MCP server calls, and environment variable access.

**Example: Scanning a package with skills**

```bash
$ xbom scan agent-toolkit-v2.zip --format both

Scanning agent-toolkit-v2.zip...
  Unpacking... done.

  SAFE 4 - Good (score: 4.20)

  SBOM:    42 components
  SaaSBOM: 3 services
  ML-BOM:  0 models
  CBOM:    2 crypto assets
  Secrets: 0 findings
  Skills:  3 files (2 clean, 1 CRITICAL)
  Duration: 2193ms

  CycloneDX JSON: ./xbom-output/xbom-agent-toolkit-v2.json
  HTML Report:    ./xbom-output/xbom-agent-toolkit-v2.html
```

The malicious skill `skills/evil-helper.md` was detected with CRITICAL severity (prompt injection + data exfiltration), pulling the overall score from 5.0 down to 4.20 via the 20% skills risk dimension.

**Execution Graph output (in CycloneDX JSON):**

```json
{
  "execution_graph": {
    "nodes": [
      {"id": "Bash", "type": "tool_call"},
      {"id": "curl", "type": "shell_command"},
      {"id": "evil.ngrok.io", "type": "network_target"},
      {"id": "~/.ssh/id_rsa", "type": "file_access"},
      {"id": "env:API_KEY", "type": "env_access"}
    ],
    "edges": [
      {"from": "skill:evil-helper", "to": "Bash", "type": "tool_call"},
      {"from": "skill:evil-helper", "to": "curl", "type": "shell_command"},
      {"from": "skill:evil-helper", "to": "evil.ngrok.io", "type": "network_target"},
      {"from": "skill:evil-helper", "to": "~/.ssh/id_rsa", "type": "file_access"},
      {"from": "skill:evil-helper", "to": "env:API_KEY", "type": "env_access"}
    ]
  }
}
```

**Ecosystem enrichment (future):** The `BaseEcosystemEnricher` interface is ready for external intelligence providers (e.g., author reputation, cross-registry duplicate detection) once API availability is confirmed.

### Skip specific analyzers

```bash
xbom scan package.jar --skip-analyzers sbom,secrets

# Skip skill scanning if not needed
xbom scan package.jar --skip-analyzers skillbom
```

### All options

```
xbom scan <package_path> [OPTIONS]

Options:
  --format [json|html|both]   Output format (default: json)
  --output-dir PATH           Output directory (default: ./xbom-output)
  --enrich                    Enable Netskope telemetry enrichment
  --validate-secrets          Enable live secret validation (requires network)
  --max-extract-size TEXT     Max extraction size (default: 1GB)
  --skip-analyzers TEXT       Comma-separated analyzer names to skip
  --verbose                   Enable verbose logging to stderr
  --version                   Show version
  --help                      Show help
```

## Supported Package Formats

| Format | Extensions |
|--------|-----------|
| Java | `.jar`, `.war`, `.ear` |
| Python | `.whl`, `.tar.gz` |
| Debian | `.deb` |
| RPM | `.rpm` |
| Generic | `.zip`, `.tar`, `.tar.gz`, `.tar.bz2`, `.tar.xz` |
| Android | `.apk`, `.aar` |

## Risk Score (SAFE Levels)

Each scan produces a composite risk score (1-5) based on weighted dimensions. When AI agent skill files are detected, a Skills dimension is added and weights are rebalanced:

| Dimension | Standard Weight | With Skills |
|-----------|----------------|-------------|
| Vulnerabilities | 30% | 25% |
| Secrets | 25% | 20% |
| Crypto | 20% | 15% |
| SaaS | 15% | 12% |
| ML | 10% | 8% |
| **Skills** | -- | **20%** |

Skills scoring: No findings = 5.0, MEDIUM = 4.0, HIGH = 2.5, CRITICAL = 1.0.

| Level | Score | Meaning |
|-------|-------|---------|
| SAFE 5 | 4.5 - 5.0 | Excellent - no significant findings |
| SAFE 4 | 3.5 - 4.4 | Good - minor issues |
| SAFE 3 | 2.5 - 3.4 | Moderate - needs attention |
| SAFE 2 | 1.5 - 2.4 | Needs Work - significant issues |
| SAFE 1 | < 1.5 | Critical Risk - active secrets or broken crypto |

## Architecture

```
INPUT (binary package)
    |
    v
[Unpacker] ----> zip bomb protection (1GB limit)
    |
    v
[Classifier] --> python-magic file identification
    |
    +---> [SBOM Analyzer] ---- syft (230+ package types)
    +---> [SaaS Analyzer] ---- string extraction + URL filtering
    +---> [ML Analyzer] ------ .onnx/.pt/.h5 detection + metadata
    +---> [Crypto Analyzer] -- algorithm patterns + cert extraction
    +---> [Secrets Analyzer] - detect-secrets (700+ patterns)
    +---> [Skill Analyzer] -- 9 pattern categories + Execution Graph
    |
    v
[Risk Scorer] --> composite SAFE 1-5 score
    |
    v
[Assembler] ----> CycloneDX v1.6 JSON
    |
    v
[Report] -------> Interactive HTML (Tailwind + Alpine.js + Chart.js)
```

All analyzers implement a pluggable interface (`BaseAnalyzer`). Adding a new BOM type = adding one Python file.

## Local Docker Deployment (Colima)

Run xBOM in a Docker container without installing Python dependencies on your host. The `deploy.sh` script manages the full lifecycle: build, scan, test, and cleanup.

### Prerequisites

- [Colima](https://github.com/abiosoft/colima) with Docker runtime
- Docker CLI (`brew install docker`)

```bash
# Install Colima + Docker CLI (if not already installed)
brew install colima docker

# Start the Colima VM
colima start
```

### Quick Start

```bash
cd xbom_generator

# Check environment is ready
./deploy.sh status

# Build the Docker image (auto-builds on first scan if skipped)
./deploy.sh build

# Scan a package
./deploy.sh scan path/to/package.jar

# Scan with HTML report and verbose logging
./deploy.sh scan path/to/app.zip --format both --verbose

# Scan with Netskope enrichment
export NETSKOPE_API_TOKEN="your-token"
export NETSKOPE_TENANT_URL="https://your-tenant.goskope.com"
./deploy.sh scan path/to/package.jar --enrich
```

### deploy.sh Commands

| Command | Description |
|---------|-------------|
| `./deploy.sh status` | Check Colima VM, Docker daemon, image, and syft version |
| `./deploy.sh build` | Build the `xbom-generator:latest` Docker image |
| `./deploy.sh scan <file> [opts]` | Scan a binary package (all xbom options passed through) |
| `./deploy.sh test` | Run the test suite inside the container |
| `./deploy.sh shell` | Open an interactive bash shell in the container |
| `./deploy.sh clean` | Remove the image and all containers |

### Volume Mounts and Output

- **Input:** The directory containing your package is mounted read-only into the container.
- **Output:** Reports are written to `xbom_generator/output/` on the host.
- **Outside `$HOME`:** Colima mounts `$HOME` by default via virtiofs. Files outside `$HOME` (e.g. `/tmp`, `/var`) are automatically staged to a temporary directory under the project, then cleaned up after the scan.

```bash
# Files under $HOME -- direct volume mount (fast)
./deploy.sh scan ~/Downloads/artifact.jar

# Files outside $HOME -- auto-staged transparently
./deploy.sh scan /tmp/build-output/artifact.jar

# Output always lands here
ls -lh output/
```

### Example: Full Scan Workflow

```bash
# 1. Verify environment
./deploy.sh status

# 2. Scan a JAR with both JSON and HTML output
./deploy.sh scan ~/builds/my-service-1.0.jar --format both

# 3. View results
open output/xbom-my-service-1.0.html    # HTML report in browser
cat output/xbom-my-service-1.0.json     # CycloneDX JSON

# 4. Debug inside the container if needed
./deploy.sh shell
xbom scan /input/my-file.zip --verbose   # run manually inside container
```

## GitHub Action

```yaml
# .github/workflows/xbom.yml
name: xBOM Scan
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./xbom_generator
        with:
          package: path/to/build/artifact.jar
          format: both
```

The action posts a summary as a PR comment and uploads the CycloneDX JSON as a build artifact.

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests (152 tests, 89% coverage)
pytest

# Run with verbose output
pytest -v --tb=short

# Type checking
mypy xbom/
```

### Project structure

```
xbom_generator/
├── xbom/
│   ├── cli.py                  # Click CLI entry point
│   ├── scanner.py              # Orchestrator
│   ├── unpacker.py             # Archive extraction + zip bomb protection
│   ├── classifier.py           # File type identification
│   ├── assembler.py            # CycloneDX v1.6 JSON output
│   ├── exceptions.py           # Custom exceptions
│   ├── analyzers/
│   │   ├── base.py             # BaseAnalyzer ABC
│   │   ├── sbom.py             # syft wrapper
│   │   ├── saasbom.py          # URL/endpoint extraction
│   │   ├── mlbom.py            # ML model detection
│   │   ├── cbom.py             # Crypto detection
│   │   ├── secrets.py          # detect-secrets wrapper
│   │   └── skillbom.py         # Skill/plugin/MCP pattern analysis + Execution Graph
│   ├── enrichment/
│   │   ├── netskope_telemetry.py  # SaaSBOM network enrichment
│   │   └── ecosystem_enricher.py  # Ecosystem enrichment interface (future)
│   ├── scoring/
│   │   └── risk_scorer.py      # SAFE 1-5 composite score
│   ├── report/
│   │   └── html_generator.py   # Interactive HTML report
│   └── models/
│       └── bom_types.py        # Data classes
├── action.yml                  # GitHub Action
├── deploy.sh                   # Local Docker deployment script (Colima)
├── Dockerfile                  # Container image definition
├── tests/                      # 152 tests, 89% coverage
└── pyproject.toml
```

## Comparison with RL Spectra Assure

| Capability | xBOM Generator | RL Spectra Assure |
|-----------|---------------|-------------------|
| SBOM | syft (230+ types) | Binary decomposition (400+ formats) |
| SaaSBOM | String extraction + **Netskope enrichment** | String extraction only |
| ML-BOM | File detection + metadata | 8,000+ model signatures |
| CBOM | Pattern matching + certs | Deep crypto analysis |
| Secrets | detect-secrets (700+ patterns) | Binary scan + validation |
| **SkillBOM** | **9 pattern categories + Execution Graph** | **Not available** |
| Risk Score | SAFE 1-5 composite (conditional skills dimension) | SAFE 1-5 (proprietary) |
| **Network Enrichment** | **Netskope telemetry (unique)** | **Not available** |
| Binary Analysis | Basic (manifest + strings) | Deep recursive (16 engines) |
| Malware Detection | Not included | 16 engines + 400B threat intel |

**Key differentiators:**
1. **Network-enriched SaaSBOM.** RL tells you "this binary references api.openai.com." We tell you "this binary sent 50GB to api.openai.com last week."
2. **AI agent skill scanning.** RL doesn't scan for malicious SKILL.md, plugins, or MCP configs. We detect prompt injection, data exfiltration, credential access, and 6 more attack categories — with a full Execution Graph showing what each skill calls, accesses, and connects to.

## License

Apache-2.0
