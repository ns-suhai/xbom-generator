# EVAL DEFINITION: xbom-generator

## Project Summary

xBOM Generator: Extended Bill of Materials from binary analysis.
Pipeline: unpack -> classify -> analyze -> score -> assemble -> report

## Baseline (2026-05-13)

- Tests: 158 collected
- Coverage: 31% (target: 80%)
- Branch: HACK-200

---

## Capability Evals

### CAP-1: Unpacker (zip bomb protection + multi-format)

| ID | Criterion | Grader | Command |
|----|-----------|--------|---------|
| CAP-1.1 | Extract .zip/.jar/.whl/.ear/.war/.apk/.aar correctly | code | `pytest tests/test_unpacker.py -k zip` |
| CAP-1.2 | Extract .tar.gz/.tgz/.tar.bz2/.tar.xz correctly | code | `pytest tests/test_unpacker.py -k tar` |
| CAP-1.3 | Extract .deb packages (ar + data.tar.*) | code | `pytest tests/test_unpacker.py -k deb` |
| CAP-1.4 | Extract .rpm packages (lead + headers + cpio) | code | `pytest tests/test_unpacker.py -k rpm` |
| CAP-1.5 | Reject extraction exceeding max_bytes (zip bomb) | code | `pytest tests/test_unpacker.py -k limit` |
| CAP-1.6 | Reject path traversal attempts (../../) | code | `pytest tests/test_unpacker.py -k traversal` |
| CAP-1.7 | Raise UnsupportedFormatError for unknown formats | code | `pytest tests/test_unpacker.py -k unsupported` |

### CAP-2: Classifier

| ID | Criterion | Grader | Command |
|----|-----------|--------|---------|
| CAP-2.1 | Classify Python/JS/Go/Rust source files | code | `pytest tests/test_classifier.py` |
| CAP-2.2 | Identify ML model files (.onnx, .pt, .h5) | code | `pytest tests/test_classifier.py -k model` |
| CAP-2.3 | Identify skill files (SKILL.md, skill.yaml) | code | `pytest tests/test_classifier.py -k skill` |

### CAP-3: SBOM Analyzer

| ID | Criterion | Grader | Command |
|----|-----------|--------|---------|
| CAP-3.1 | Detect dependencies from lock files | code | `pytest tests/test_sbom_analyzer.py` |
| CAP-3.2 | Generate BomEntry with purl and version | code | `pytest tests/test_sbom_analyzer.py -k purl` |
| CAP-3.3 | Handle missing syft gracefully (DependencyMissing) | code | `pytest tests/test_sbom_analyzer.py -k missing` |

### CAP-4: SaaSBOM Analyzer

| ID | Criterion | Grader | Command |
|----|-----------|--------|---------|
| CAP-4.1 | Detect API endpoints in source code | code | `pytest tests/test_saasbom_analyzer.py` |
| CAP-4.2 | Extract protocol (HTTP/gRPC/WebSocket) | code | `pytest tests/test_saasbom_analyzer.py -k protocol` |

### CAP-5: ML-BOM Analyzer

| ID | Criterion | Grader | Command |
|----|-----------|--------|---------|
| CAP-5.1 | Detect ML model files and frameworks | code | `pytest tests/test_mlbom_analyzer.py` |
| CAP-5.2 | Identify TensorFlow/PyTorch/ONNX/Hugging Face | code | `pytest tests/test_mlbom_analyzer.py -k framework` |

### CAP-6: CBOM Analyzer (Cryptography)

| ID | Criterion | Grader | Command |
|----|-----------|--------|---------|
| CAP-6.1 | Detect crypto algorithms in code | code | `pytest tests/test_cbom_analyzer.py` |
| CAP-6.2 | Flag weak algorithms (MD5, SHA1, DES, RC4) | code | `pytest tests/test_cbom_analyzer.py -k weak` |
| CAP-6.3 | Identify quantum-safe algorithms | code | `pytest tests/test_cbom_analyzer.py -k quantum` |

### CAP-7: Secrets Analyzer

| ID | Criterion | Grader | Command |
|----|-----------|--------|---------|
| CAP-7.1 | Detect exposed secrets (API keys, tokens) | code | `pytest tests/test_secrets_analyzer.py` |
| CAP-7.2 | Classify secret types (AWS, GitHub, generic) | code | `pytest tests/test_secrets_analyzer.py -k classify` |

### CAP-8: SkillBOM Analyzer

| ID | Criterion | Grader | Command |
|----|-----------|--------|---------|
| CAP-8.1 | Detect SKILL.md and skill config files | code | `pytest tests/test_skillbom_analyzer.py` |
| CAP-8.2 | Assess skill risk (command injection, filesystem access) | code | `pytest tests/test_skillbom_analyzer.py -k risk` |
| CAP-8.3 | Report severity levels (CRITICAL/HIGH/MEDIUM) | code | `pytest tests/test_skillbom_analyzer.py -k severity` |

### CAP-9: Risk Scorer

| ID | Criterion | Grader | Command |
|----|-----------|--------|---------|
| CAP-9.1 | Compute weighted composite score (1.0-5.0) | code | `pytest tests/test_risk_scorer.py` |
| CAP-9.2 | Rebalance weights when skills present | code | `pytest tests/test_risk_scorer.py -k skill` |
| CAP-9.3 | Active secrets → score 1.0 (CRITICAL) | code | `pytest tests/test_risk_scorer.py -k active` |
| CAP-9.4 | Map score to SAFE level (1-5) correctly | code | `pytest tests/test_risk_scorer.py -k safe_level` |

### CAP-10: Assembler (CycloneDX output)

| ID | Criterion | Grader | Command |
|----|-----------|--------|---------|
| CAP-10.1 | Produce valid CycloneDX v1.6 JSON | code | `pytest tests/test_assembler.py -k cyclonedx` |
| CAP-10.2 | Map SaaSBOM entries to services[] | code | `pytest tests/test_assembler.py -k service` |
| CAP-10.3 | Map secrets to vulnerabilities[] | code | `pytest tests/test_assembler.py -k vuln` |
| CAP-10.4 | Include crypto properties for CBOM | code | `pytest tests/test_assembler.py -k crypto` |
| CAP-10.5 | Include ML model type and framework | code | `pytest tests/test_assembler.py -k ml` |

### CAP-11: HTML Report

| ID | Criterion | Grader | Command |
|----|-----------|--------|---------|
| CAP-11.1 | Generate valid HTML with all sections | code | `pytest tests/test_html_report.py` |
| CAP-11.2 | Include Skills tab when skill entries present | code | `pytest tests/test_html_report.py -k skill` |

### CAP-12: CLI Interface

| ID | Criterion | Grader | Command |
|----|-----------|--------|---------|
| CAP-12.1 | `xbom scan` produces JSON output | code | `pytest tests/test_cli.py -k json` |
| CAP-12.2 | `xbom scan --format html` produces HTML | code | `pytest tests/test_cli.py -k html` |
| CAP-12.3 | `--skip-analyzers` skips specified analyzers | code | `pytest tests/test_cli.py -k skip` |
| CAP-12.4 | `--max-extract-size` parses KB/MB/GB | code | `pytest tests/test_cli.py -k size` |
| CAP-12.5 | Exit code 1 on scan failure | code | `pytest tests/test_cli.py -k error` |

### CAP-13: Scanner Pipeline (Integration)

| ID | Criterion | Grader | Command |
|----|-----------|--------|---------|
| CAP-13.1 | Full pipeline: unpack→classify→analyze→score | code | `pytest tests/test_scanner.py` |
| CAP-13.2 | Graceful degradation when analyzer unavailable | code | `pytest tests/test_scanner.py -k unavailable` |
| CAP-13.3 | Netskope enrichment toggle | code | `pytest tests/test_scanner.py -k enrich` |

### CAP-14: Enrichment

| ID | Criterion | Grader | Command |
|----|-----------|--------|---------|
| CAP-14.1 | Ecosystem enricher processes entries | code | `pytest tests/test_ecosystem_enricher.py` |
| CAP-14.2 | Netskope telemetry adds traffic metadata | code | `pytest tests/test_netskope_enrichment.py` |

### CAP-15: Execution Graph

| ID | Criterion | Grader | Command |
|----|-----------|--------|---------|
| CAP-15.1 | Build and execute analysis DAG | code | `pytest tests/test_execution_graph.py` |

---

## Regression Evals

### REG-1: Core Pipeline Stability

```bash
# All 158 existing tests must pass
cd /Users/hsu/Documents/Workspace/Projects/AI_Projects/supply_chain/xbom_generator
python3 -m pytest --tb=short -q 2>&1 | grep -E "passed|failed"
```

**Threshold**: pass^3 = 100% (all 3 consecutive runs must pass)

### REG-2: No Regressions in Output Format

| Check | Grader | Validation |
|-------|--------|------------|
| CycloneDX specVersion == "1.6" | code | `jq '.specVersion' output.json == "1.6"` |
| bomFormat == "CycloneDX" | code | `jq '.bomFormat' output.json == "CycloneDX"` |
| Metadata includes safe-level | code | `jq '.metadata.properties[] | select(.name=="xbom:safe-level")' output.json` |
| Metadata includes risk-score | code | `jq '.metadata.properties[] | select(.name=="xbom:risk-score")' output.json` |

### REG-3: GitHub Action Compatibility

| Check | Grader | Validation |
|-------|--------|------------|
| action.yml is valid YAML | code | `python3 -c "import yaml; yaml.safe_load(open('action.yml'))"` |
| Required input 'package' exists | code | grep in action.yml |
| Output 'safe-level' declared | code | grep in action.yml |

---

## Success Metrics

| Metric | Target | Current |
|--------|--------|---------|
| Test count | >= 158 | 158 |
| Coverage | >= 80% | 31% |
| pass@1 (capability) | >= 70% | TBD |
| pass@3 (capability) | >= 90% | TBD |
| pass^3 (regression) | 100% | TBD |
| mypy --strict | 0 errors | TBD |

---

## Anti-Patterns to Watch

- [ ] Tests that mock too much (hide real integration bugs)
- [ ] Flaky tests from tempdir race conditions
- [ ] Overfitting: tests that only work with specific fixture data
- [ ] Score thresholds tested at exact boundary (float precision)
- [ ] Tests that require network access (should be mocked)

---

## Run Commands

```bash
# Full eval run
cd /Users/hsu/Documents/Workspace/Projects/AI_Projects/supply_chain/xbom_generator
python3 -m pytest --cov=xbom --cov-report=term-missing -v

# Individual capability check
python3 -m pytest tests/test_unpacker.py -v
python3 -m pytest tests/test_scanner.py -v

# Type check
python3 -m mypy xbom/ --strict

# Quick regression
python3 -m pytest -x -q
```
