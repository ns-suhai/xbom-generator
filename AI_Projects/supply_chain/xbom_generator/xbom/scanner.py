"""Main scanner orchestrator: unpack -> classify -> analyze -> score -> assemble."""

from __future__ import annotations

import logging
import tempfile
import time
from pathlib import Path

from xbom.agent_manifest import compute_agent_manifest
from xbom.analyzers.base import BaseAnalyzer
from xbom.analyzers.cbom import CbomAnalyzer
from xbom.analyzers.mcp import McpBomAnalyzer
from xbom.analyzers.mlbom import MlBomAnalyzer
from xbom.analyzers.saasbom import SaasBomAnalyzer
from xbom.analyzers.sbom import SbomAnalyzer
from xbom.analyzers.secrets import SecretsAnalyzer
from xbom.analyzers.skillbom import SkillBomAnalyzer
from xbom.enrichment.ecosystem_enricher import NoOpEcosystemEnricher
from xbom.classifier import classify_files
from xbom.exceptions import DependencyMissingError
from xbom.models.bom_types import BomEntry, BomType, SafeLevel, ScanResult
from xbom.scoring.risk_scorer import compute_risk_score
from xbom.unpacker import DEFAULT_MAX_EXTRACT_BYTES, extract_package

logger = logging.getLogger(__name__)

# Default analyzer order
_DEFAULT_ANALYZERS: list[type[BaseAnalyzer]] = [
    SbomAnalyzer,
    SaasBomAnalyzer,
    MlBomAnalyzer,
    CbomAnalyzer,
    SecretsAnalyzer,
    SkillBomAnalyzer,
    McpBomAnalyzer,
]


def _run_analyzers(
    extracted_dir: Path,
    skip: set[str],
    enrich: bool,
) -> tuple[list[BomEntry], list[str], list[str]]:
    """Run all analyzers on a classified directory.

    Returns:
        Tuple of (entries, errors, warnings).
    """
    all_entries: list[BomEntry] = []
    errors: list[str] = []
    warnings: list[str] = []

    # Classify
    classified = classify_files(extracted_dir)
    total_files = sum(len(v) for v in classified.values())
    if total_files == 0:
        warnings.append("No files found after extraction. All BOMs will be empty.")

    # Run analyzers
    for analyzer_cls in _DEFAULT_ANALYZERS:
        analyzer = analyzer_cls()
        if analyzer.name in skip:
            logger.info("Skipping analyzer: %s", analyzer.name)
            continue

        if not analyzer.is_available():
            msg = f"{analyzer.name} analyzer unavailable (missing dependency)"
            warnings.append(msg)
            logger.warning(msg)
            continue

        try:
            entries = analyzer.analyze(extracted_dir, classified)
            all_entries.extend(entries)
        except DependencyMissingError as exc:
            warnings.append(str(exc))
            logger.warning("Analyzer %s: %s", analyzer.name, exc)
        except Exception as exc:
            msg = f"{analyzer.name} analyzer failed: {exc}"
            errors.append(msg)
            logger.error(msg, exc_info=True)

    # Enrich SaaSBOM (optional)
    if enrich:
        try:
            from xbom.enrichment.netskope_telemetry import enrich_saasbom
            all_entries = enrich_saasbom(all_entries)
        except Exception as exc:
            warnings.append(f"Netskope enrichment unavailable: {exc}")
            logger.warning("Enrichment failed: %s", exc)

    # Ecosystem enrichment for skills (extensible)
    if any(e.bom_type == BomType.SKILLBOM for e in all_entries):
        try:
            ecosystem_enricher = NoOpEcosystemEnricher()
            all_entries = ecosystem_enricher.enrich(all_entries)
        except Exception as exc:
            warnings.append(f"Ecosystem enrichment failed: {exc}")
            logger.warning("Ecosystem enrichment failed: %s", exc)

    return all_entries, errors, warnings


def _build_result(
    source_path: Path,
    all_entries: list[BomEntry],
    errors: list[str],
    warnings: list[str],
    start_ms: int,
) -> ScanResult:
    """Build a ScanResult from analyzed entries."""
    entries_tuple = tuple(all_entries)
    score, dimension_scores = compute_risk_score(entries_tuple)
    safe_level = SafeLevel.from_score(score)
    agent_manifest = compute_agent_manifest(entries_tuple)
    duration_ms = int(time.time() * 1000) - start_ms

    return ScanResult(
        package_path=str(source_path),
        entries=entries_tuple,
        risk_score=score,
        safe_level=safe_level,
        dimension_scores=dimension_scores,
        agent_manifest=agent_manifest,
        scan_duration_ms=duration_ms,
        errors=tuple(errors),
        warnings=tuple(warnings),
    )


def scan_directory(
    directory: Path,
    skip_analyzers: set[str] | None = None,
    enrich: bool = False,
) -> ScanResult:
    """Scan a directory directly without unpacking.

    Use this to scan skill folders, plugin directories, or any source tree.

    Args:
        directory: Path to the directory to scan.
        skip_analyzers: Set of analyzer names to skip.
        enrich: Whether to enrich SaaSBOM with Netskope telemetry.

    Returns:
        ScanResult with all BOM entries, risk score, and SAFE level.
    """
    start_ms = int(time.time() * 1000)
    skip = skip_analyzers or set()

    all_entries, errors, warnings = _run_analyzers(directory, skip, enrich)
    return _build_result(directory, all_entries, errors, warnings, start_ms)


def scan_package(
    package_path: Path,
    max_extract_bytes: int = DEFAULT_MAX_EXTRACT_BYTES,
    skip_analyzers: set[str] | None = None,
    enrich: bool = False,
) -> ScanResult:
    """Scan a binary package and produce a full xBOM scan result.

    Args:
        package_path: Path to the binary package file.
        max_extract_bytes: Maximum extraction size (zip bomb protection).
        skip_analyzers: Set of analyzer names to skip.
        enrich: Whether to enrich SaaSBOM with Netskope telemetry.

    Returns:
        ScanResult with all BOM entries, risk score, and SAFE level.
    """
    start_ms = int(time.time() * 1000)
    skip = skip_analyzers or set()

    # Step 1: Extract
    with tempfile.TemporaryDirectory(prefix="xbom-") as tmp:
        extracted_dir = extract_package(
            package_path,
            dest_dir=Path(tmp),
            max_bytes=max_extract_bytes,
        )
        all_entries, errors, warnings = _run_analyzers(extracted_dir, skip, enrich)

    return _build_result(package_path, all_entries, errors, warnings, start_ms)
