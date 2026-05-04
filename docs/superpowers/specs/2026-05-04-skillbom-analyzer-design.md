# SkillBom Analyzer Design Spec

**Date:** 2026-05-04
**Status:** Approved (v2 — fully local, no external API)
**Branch:** HACK-200

## Overview

Add a SkillBom analyzer to xBOM that detects and assesses agent supply chain assets
(SKILL.md, plugins, MCP configs, agent instructions) found inside binary packages.
All analysis runs locally: static pattern detection + Execution Graph generation.

An Ecosystem Graph enrichment interface is provided for future integration with
external intelligence providers (e.g., Manifold Manifest) once API availability
and commercial terms are confirmed.

Inspired by [Manifold's Manifest](https://www.manifold.security/blog/manifest-ai-supply-chain-intelligence):
scanning skills in isolation produces noise. Context matters — Execution Graphs
(what a skill does) and Ecosystem Graphs (who published it, author reputation).
We build the Execution Graph locally; Ecosystem Graph is deferred behind an
enrichment interface.

## Architecture

```
[Classifier] -- new "skills" category --> [SkillBom Analyzer]
                                                |
                                    +-----------+-----------+
                                    |                       |
                              Static Analysis       Execution Graph
                              (9 pattern categories) (local parsing)
                                    |                       |
                                    +------> BomEntry ------+
                                                |
                                    [Ecosystem Enricher] (interface only, future)
                                                |
                                          [Risk Scorer]
                                     new "skills" dimension
                                   (conditional, 20% when present)
```

## 1. Classifier Change (classifier.py)

Add a `"skills"` category. Matched by filename/path before MIME detection:

| Pattern | Match Type |
|---------|------------|
| `SKILL.md`, `skill.md`, `skills/*.md` | Filename / glob |
| `plugin.json`, `plugin.yaml` | Filename |
| `.mcp.json`, `mcp.json`, `mcp-config.*` | Filename |
| `action.yml`, `action.yaml` | Filename |
| `AGENTS.md`, `CLAUDE.md` | Filename |
| `.claude/`, `.cursor/`, `.copilot/` | Parent directory |

Name-based matching runs first; files matching skill patterns are classified as
`"skills"` regardless of MIME type.

## 2. SkillBom Analyzer (analyzers/skillbom.py)

New `BaseAnalyzer` subclass. For each file in the `"skills"` category:

1. Read file content as UTF-8 text
2. Run 9 static pattern checks (regex-based)
3. Build Execution Graph from content
4. Produce one `BomEntry` per file

### 2.1 Static Pattern Categories

| Category | Examples | Severity |
|----------|---------|----------|
| shell_execution | `Bash`, `exec`, `subprocess`, `curl \|`, piped commands | HIGH |
| data_exfiltration | URLs receiving data, `curl -X POST`, webhook URLs, `ngrok`, pastebin | CRITICAL |
| prompt_injection | "ignore previous instructions", "you are now", role overrides, hidden base64 instructions | CRITICAL |
| credential_access | `.env`, `API_KEY`, `TOKEN`, `~/.ssh`, `~/.aws`, keychain | HIGH |
| file_system_overreach | Writing `/etc`, `~/.bashrc`, `~/.zshrc`, `chmod 777` | HIGH |
| network_tunneling | `ngrok`, reverse shells, `nc -l`, port forwarding | CRITICAL |
| permission_escalation | `dangerouslySkipPermissions`, `bypassPermissions`, `--no-verify` | MEDIUM |
| obfuscation | Base64-encoded commands, hex strings, unicode homoglyphs | HIGH |
| typosquatting_signal | Skill name similar to well-known skills (local Levenshtein check against a bundled list) | MEDIUM |

### 2.2 Execution Graph (Local)

Built by parsing the skill file content to extract:

| What | How | Example |
|------|-----|---------|
| Tool calls | Regex for known tool names: `Bash`, `Read`, `Write`, `Edit`, `Glob`, `Grep`, `WebFetch` | `Bash` -> tool_call |
| Shell commands | Parse `curl`, `wget`, `npm`, `pip install`, `git clone`, `docker run` | `curl` -> shell_command |
| Network targets | URL/domain extraction from instructions | `api.openai.com` -> network_target |
| File system targets | Path patterns: `/etc/`, `~/.ssh`, `~/.aws`, `$HOME/` | `~/.ssh/id_rsa` -> file_access |
| Skill-to-skill calls | References: `/skill-name`, `skill: "name"`, skill imports | `skill:deploy` -> skill_call |
| MCP server calls | `mcp__server__tool` patterns, MCP config references | `mcp__slack__send` -> mcp_call |
| Environment access | `$ENV_VAR`, `os.environ`, `process.env` patterns | `$API_KEY` -> env_access |

Output format stored in BomEntry metadata:

```json
{
  "execution_graph": {
    "nodes": [
      {"id": "Bash", "type": "tool_call"},
      {"id": "curl", "type": "shell_command"},
      {"id": "api.openai.com", "type": "network_target"},
      {"id": "~/.ssh/id_rsa", "type": "file_access"}
    ],
    "edges": [
      {"from": "skill:deploy-helper", "to": "Bash", "type": "tool_call"},
      {"from": "Bash", "to": "curl", "type": "invokes"},
      {"from": "curl", "to": "api.openai.com", "type": "connects_to"}
    ]
  }
}
```

The Execution Graph feeds into the static analysis: network targets found in the
graph are cross-checked against the data_exfiltration patterns; tool calls inform
the shell_execution and permission_escalation checks.

### 2.3 BomEntry Schema

```python
BomEntry(
    bom_type=BomType.SKILLBOM,
    component_type=ComponentType.SKILL,
    name="deployment-helper",  # extracted from content or filename
    version=None,
    metadata={
        "file_path": "skills/deploy.md",
        "file_type": "skill_md",       # skill_md | plugin | mcp_config | action | agent_instruction
        "findings": [
            {
                "category": "prompt_injection",
                "severity": "CRITICAL",
                "pattern": "ignore previous instructions",
                "line": 42,
            }
        ],
        "finding_count": 1,
        "max_severity": "CRITICAL",
        "execution_graph": {
            "nodes": [...],
            "edges": [...],
        },
        # Ecosystem enrichment (future, populated by enricher implementations):
        "ecosystem": None,
    },
)
```

## 3. Ecosystem Enrichment Interface (enrichment/ecosystem_enricher.py)

Abstract interface for future external intelligence providers. Not implemented
in this iteration — ships as interface + no-op default only.

```python
from abc import ABC, abstractmethod
from xbom.models.bom_types import BomEntry


class BaseEcosystemEnricher(ABC):
    """Interface for ecosystem graph enrichment providers.

    Implementations may query external APIs (e.g., Manifold Manifest)
    to add author reputation, cross-registry duplicate detection,
    and ecosystem-level risk context to SkillBom entries.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name (e.g., 'manifest', 'custom')."""
        ...

    @abstractmethod
    def enrich(self, entries: list[BomEntry]) -> list[BomEntry]:
        """Enrich SkillBom entries with ecosystem context.

        Args:
            entries: List of BomEntry objects (may include non-SKILLBOM types).

        Returns:
            Entries with ecosystem metadata added to SKILLBOM entries.
            Non-SKILLBOM entries are passed through unchanged.
        """
        ...

    def is_available(self) -> bool:
        """Check if the enrichment provider is configured and reachable."""
        return True


class NoOpEcosystemEnricher(BaseEcosystemEnricher):
    """Default no-op enricher. Sets ecosystem metadata to None."""

    @property
    def name(self) -> str:
        return "noop"

    def enrich(self, entries: list[BomEntry]) -> list[BomEntry]:
        return entries
```

When an ecosystem enricher is implemented (e.g., `ManifestEnricher`), it would:
- Be registered in `scanner.py` alongside the no-op default
- Populate `metadata["ecosystem"]` with:
  - `verdict`: clean | high_risk | unknown
  - `author_trust`: 0.0-1.0 reputation score
  - `duplicates`: cross-registry duplicate count
  - `related_skills`: list of similar/cloned skills
- Be activated via a CLI flag (e.g., `--ecosystem-enrich manifest`)

## 4. Model Changes (models/bom_types.py)

```python
class BomType(str, Enum):
    SBOM = "sbom"
    SAASBOM = "saasbom"
    MLBOM = "mlbom"
    CBOM = "cbom"
    SECRETS = "secrets"
    SKILLBOM = "skillbom"     # NEW

class ComponentType(str, Enum):
    LIBRARY = "library"
    SERVICE = "service"
    MODEL = "model"
    CRYPTO_ASSET = "crypto-asset"
    SECRET = "secret"
    SKILL = "skill"           # NEW
```

Add to `ScanResult`:
```python
@property
def skill_entries(self) -> tuple[BomEntry, ...]:
    return tuple(e for e in self.entries if e.bom_type == BomType.SKILLBOM)
```

## 5. Risk Scorer Change (scoring/risk_scorer.py)

Conditional weighting. When any SKILLBOM entries exist, add a "skills" dimension
and redistribute weights:

| Dimension | Without Skills | With Skills |
|-----------|---------------|-------------|
| Vulnerabilities | 30% | 25% |
| Secrets | 25% | 20% |
| Crypto | 20% | 15% |
| SaaS | 15% | 12% |
| ML | 10% | 8% |
| **Skills** | -- | **20%** |

### Skills Scoring Logic

```
No findings                     -> 5.0
Only MEDIUM findings            -> 4.0
Any HIGH finding                -> 2.5
Any CRITICAL finding            -> 1.0
```

When ecosystem enrichment is available in the future, a `high_risk` ecosystem
verdict would floor the score at 1.5.

## 6. HTML Report Change (report/html_generator.py)

Add a **"Skills"** tab between Secrets and Warnings:

- Table columns: File, Type, Findings, Max Severity, Exec Graph Summary
- Severity badges: CRITICAL=red, HIGH=orange, MEDIUM=yellow, clean=green
- Execution Graph summary: comma-separated list of node types and counts
- Expandable findings list per row (category, pattern, line number)

Update `_build_report_data()` to include `"skillbom"` key in summary and data.

## 7. CLI Change (cli.py)

Add Skills line to scan output summary:

```
  Skills:  3 files (2 clean, 1 HIGH)
```

No new CLI flags required.

## 8. Files to Create/Modify

| File | Action |
|------|--------|
| `xbom/analyzers/skillbom.py` | Create -- analyzer with 9 pattern categories + execution graph |
| `xbom/enrichment/ecosystem_enricher.py` | Create -- ABC interface + NoOp default (future extension point) |
| `xbom/models/bom_types.py` | Modify -- add SKILLBOM enum, SKILL type, skill_entries property |
| `xbom/classifier.py` | Modify -- add "skills" category with name-based matching |
| `xbom/scanner.py` | Modify -- register SkillBomAnalyzer + NoOpEcosystemEnricher |
| `xbom/scoring/risk_scorer.py` | Modify -- conditional skills dimension + rebalanced weights |
| `xbom/report/html_generator.py` | Modify -- add Skills tab |
| `xbom/cli.py` | Modify -- add Skills line in summary output |
| `tests/test_skillbom_analyzer.py` | Create -- analyzer + execution graph tests |
| `tests/test_ecosystem_enricher.py` | Create -- interface + no-op tests |
| `tests/test_risk_scorer.py` | Modify -- conditional weight tests |
| `tests/test_classifier.py` | Modify -- skills category tests |
| `tests/test_html_report.py` | Modify -- Skills tab tests |
| `tests/test_cli.py` | Modify -- Skills summary line tests |

## 9. Test Strategy

- Unit tests for each of the 9 pattern categories (craft SKILL.md with known patterns)
- Tests for clean skills (no false positives on legitimate patterns like deployment skills)
- Execution Graph: test node/edge extraction from sample skill files
- Ecosystem enricher: test ABC interface, test NoOp passthrough
- Risk scorer: verify weight rebalancing triggers only when skills present
- Integration: scan a zip containing SKILL.md files, verify end-to-end output
- Target: maintain 80%+ coverage
