"""Composite SAFE-style risk scorer (1-5)."""

from __future__ import annotations

import logging
from typing import Any

from xbom.models.bom_types import BomEntry, BomType, DimensionScore

logger = logging.getLogger(__name__)

# Weights for each dimension (without skills)
_WEIGHTS_DEFAULT = {
    "vulnerabilities": 0.30,
    "secrets": 0.25,
    "crypto": 0.20,
    "saas": 0.15,
    "ml": 0.10,
}

# Rebalanced weights when skill files are present
_WEIGHTS_WITH_SKILLS = {
    "vulnerabilities": 0.25,
    "secrets": 0.20,
    "crypto": 0.15,
    "saas": 0.12,
    "ml": 0.08,
    "skills": 0.20,
}


def _score_vulnerabilities(entries: tuple[BomEntry, ...]) -> float:
    """Score based on SBOM component vulnerability indicators."""
    sbom = [e for e in entries if e.bom_type == BomType.SBOM]
    if not sbom:
        return 5.0  # No components = no vulnerability risk
    # Simple heuristic: more components = slightly lower score (more attack surface)
    count = len(sbom)
    if count > 500:
        return 3.0
    if count > 100:
        return 3.5
    if count > 50:
        return 4.0
    return 4.5


def _score_secrets(entries: tuple[BomEntry, ...]) -> float:
    """Score based on exposed secrets."""
    secrets = [e for e in entries if e.bom_type == BomType.SECRETS]
    if not secrets:
        return 5.0
    active = [s for s in secrets if s.metadata.get("is_active") is True]
    if active:
        return 1.0
    if len(secrets) > 5:
        return 2.0
    if len(secrets) > 2:
        return 3.0
    return 3.5


def _score_crypto(entries: tuple[BomEntry, ...]) -> float:
    """Score based on cryptographic asset quality."""
    crypto = [e for e in entries if e.bom_type == BomType.CBOM]
    if not crypto:
        return 5.0
    weak = [c for c in crypto if c.metadata.get("strength") == "weak"]
    quantum_safe = [c for c in crypto if c.metadata.get("quantum_level", 0) >= 1]
    if weak:
        return 2.0
    if quantum_safe:
        return 5.0
    return 4.0


def _score_saas(entries: tuple[BomEntry, ...]) -> float:
    """Score based on SaaS/API endpoint characteristics."""
    saas = [e for e in entries if e.bom_type == BomType.SAASBOM]
    if not saas:
        return 5.0
    # Enriched entries get a better score (known, verified)
    enriched = [s for s in saas if s.metadata.get("actual_traffic_volume")]
    if enriched:
        return 4.5
    if len(saas) > 20:
        return 3.0
    if len(saas) > 10:
        return 3.5
    return 4.0


def _score_ml(entries: tuple[BomEntry, ...]) -> float:
    """Score based on ML model characteristics."""
    models = [e for e in entries if e.bom_type == BomType.MLBOM]
    if not models:
        return 5.0
    unknown = [m for m in models if m.metadata.get("framework") == "Unknown"]
    if unknown:
        return 3.0
    return 4.5


def _score_skills(entries: tuple[BomEntry, ...]) -> float:
    """Score based on SkillBom findings severity and lineage signals."""
    skills = [e for e in entries if e.bom_type == BomType.SKILLBOM]
    if not skills:
        return 5.0
    max_sev = None
    total_findings = 0
    has_version = False
    has_referenced_scripts = False

    for s in skills:
        sev = s.metadata.get("max_severity")
        total_findings += s.metadata.get("finding_count", 0)
        if sev == "CRITICAL":
            return 1.0
        if sev == "HIGH":
            max_sev = "HIGH"
        elif sev == "MEDIUM" and max_sev is None:
            max_sev = "MEDIUM"
        # Lineage signals
        provenance = s.metadata.get("provenance", {})
        if provenance.get("version"):
            has_version = True
        if s.metadata.get("referenced_scripts"):
            has_referenced_scripts = True

    base_score = 5.0
    if max_sev == "HIGH":
        base_score = 2.5
    elif max_sev == "MEDIUM":
        base_score = 4.0

    # Lineage penalties (only apply when provenance data is present)
    if has_version is False and total_findings > 0:
        base_score -= 0.3  # No version pinning + findings → harder to audit
    if has_referenced_scripts and total_findings > 3:
        base_score -= 0.5  # Scripts with many findings → higher risk

    return max(1.0, min(5.0, base_score))


def compute_risk_score(
    entries: tuple[BomEntry, ...],
) -> tuple[float, tuple[DimensionScore, ...]]:
    """Compute composite risk score from all BOM entries.

    Returns:
        Tuple of (overall_score, dimension_scores).
        Score range: 1.0 (critical) to 5.0 (excellent).
    """
    has_skills = any(e.bom_type == BomType.SKILLBOM for e in entries)
    weights = _WEIGHTS_WITH_SKILLS if has_skills else _WEIGHTS_DEFAULT

    scorers: dict[str, Any] = {
        "vulnerabilities": _score_vulnerabilities,
        "secrets": _score_secrets,
        "crypto": _score_crypto,
        "saas": _score_saas,
        "ml": _score_ml,
    }
    if has_skills:
        scorers["skills"] = _score_skills

    dimensions: list[DimensionScore] = []
    weighted_sum = 0.0
    total_weight = 0.0

    for name, scorer in scorers.items():
        weight = weights[name]
        score = scorer(entries)
        dimensions.append(DimensionScore(
            name=name,
            score=score,
            weight=weight,
        ))
        weighted_sum += score * weight
        total_weight += weight

    overall = weighted_sum / total_weight if total_weight > 0 else 5.0

    logger.info(
        "Risk score: %.2f (SAFE %d) | %s",
        overall,
        5 if overall >= 4.5 else 4 if overall >= 3.5 else 3 if overall >= 2.5 else 2 if overall >= 1.5 else 1,
        ", ".join(f"{d.name}={d.score:.1f}" for d in dimensions),
    )
    return overall, tuple(dimensions)
