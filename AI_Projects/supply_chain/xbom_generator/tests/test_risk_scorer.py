"""Tests for the risk scorer."""

from xbom.models.bom_types import BomEntry, BomType, ComponentType, SafeLevel
from xbom.scoring.risk_scorer import compute_risk_score


def test_empty_entries_is_excellent() -> None:
    score, dims = compute_risk_score(())
    assert score == 5.0
    assert SafeLevel.from_score(score) == SafeLevel.EXCELLENT


def test_secrets_lower_score() -> None:
    entries = tuple(
        BomEntry(BomType.SECRETS, ComponentType.SECRET, f"secret-{i}", None,
                 {"type": "api-key", "is_active": None})
        for i in range(3)
    )
    score, dims = compute_risk_score(entries)
    secrets_dim = next(d for d in dims if d.name == "secrets")
    assert secrets_dim.score < 5.0


def test_active_secrets_critical() -> None:
    entries = (
        BomEntry(BomType.SECRETS, ComponentType.SECRET, "aws-key", None,
                 {"type": "aws-key", "is_active": True}),
    )
    score, dims = compute_risk_score(entries)
    secrets_dim = next(d for d in dims if d.name == "secrets")
    assert secrets_dim.score == 1.0


def test_weak_crypto_lowers_score() -> None:
    entries = (
        BomEntry(BomType.CBOM, ComponentType.CRYPTO_ASSET, "MD5", None,
                 {"algorithm": "MD5", "strength": "weak", "quantum_level": 0}),
    )
    score, dims = compute_risk_score(entries)
    crypto_dim = next(d for d in dims if d.name == "crypto")
    assert crypto_dim.score <= 2.0


def test_quantum_safe_crypto_is_excellent() -> None:
    entries = (
        BomEntry(BomType.CBOM, ComponentType.CRYPTO_ASSET, "Kyber", None,
                 {"algorithm": "CRYSTALS-Kyber", "strength": "acceptable", "quantum_level": 3}),
    )
    score, dims = compute_risk_score(entries)
    crypto_dim = next(d for d in dims if d.name == "crypto")
    assert crypto_dim.score == 5.0


def test_many_components_lowers_vuln_score() -> None:
    entries = tuple(
        BomEntry(BomType.SBOM, ComponentType.LIBRARY, f"lib-{i}", "1.0", {})
        for i in range(200)
    )
    score, dims = compute_risk_score(entries)
    vuln_dim = next(d for d in dims if d.name == "vulnerabilities")
    assert vuln_dim.score < 4.5


def test_safe_level_mapping() -> None:
    assert SafeLevel.from_score(5.0) == SafeLevel.EXCELLENT
    assert SafeLevel.from_score(4.5) == SafeLevel.EXCELLENT
    assert SafeLevel.from_score(4.0) == SafeLevel.GOOD
    assert SafeLevel.from_score(3.0) == SafeLevel.MODERATE
    assert SafeLevel.from_score(2.0) == SafeLevel.NEEDS_WORK
    assert SafeLevel.from_score(1.0) == SafeLevel.CRITICAL


def test_dimension_weights_sum_to_one() -> None:
    score, dims = compute_risk_score(())
    total_weight = sum(d.weight for d in dims)
    assert abs(total_weight - 1.0) < 0.01


def test_no_skills_uses_original_weights() -> None:
    entries = (
        BomEntry(BomType.SBOM, ComponentType.LIBRARY, "x", "1.0", {}),
    )
    _, dims = compute_risk_score(entries)
    dim_names = [d.name for d in dims]
    assert "skills" not in dim_names
    assert dims[0].weight == 0.30  # vulnerabilities


def test_skills_dimension_added_when_skillbom_present() -> None:
    entries = (
        BomEntry(BomType.SKILLBOM, ComponentType.SKILL, "test", None,
                 {"findings": [], "max_severity": None}),
    )
    _, dims = compute_risk_score(entries)
    dim_names = [d.name for d in dims]
    assert "skills" in dim_names


def test_skills_rebalanced_weights() -> None:
    entries = (
        BomEntry(BomType.SKILLBOM, ComponentType.SKILL, "test", None,
                 {"findings": [], "max_severity": None}),
    )
    _, dims = compute_risk_score(entries)
    weight_map = {d.name: d.weight for d in dims}
    assert weight_map["skills"] == 0.20
    assert weight_map["vulnerabilities"] == 0.25
    assert abs(sum(weight_map.values()) - 1.0) < 0.01


def test_skills_clean_scores_excellent() -> None:
    entries = (
        BomEntry(BomType.SKILLBOM, ComponentType.SKILL, "clean", None,
                 {"findings": [], "max_severity": None}),
    )
    _, dims = compute_risk_score(entries)
    skills_dim = next(d for d in dims if d.name == "skills")
    assert skills_dim.score == 5.0


def test_skills_critical_finding_scores_one() -> None:
    entries = (
        BomEntry(BomType.SKILLBOM, ComponentType.SKILL, "evil", None,
                 {"findings": [{"severity": "CRITICAL"}], "max_severity": "CRITICAL"}),
    )
    _, dims = compute_risk_score(entries)
    skills_dim = next(d for d in dims if d.name == "skills")
    assert skills_dim.score == 1.0


def test_skills_high_finding_scores_2_5() -> None:
    entries = (
        BomEntry(BomType.SKILLBOM, ComponentType.SKILL, "risky", None,
                 {"findings": [{"severity": "HIGH"}], "max_severity": "HIGH"}),
    )
    _, dims = compute_risk_score(entries)
    skills_dim = next(d for d in dims if d.name == "skills")
    assert skills_dim.score == 2.5


def test_skills_medium_finding_scores_4() -> None:
    entries = (
        BomEntry(BomType.SKILLBOM, ComponentType.SKILL, "mild", None,
                 {"findings": [{"severity": "MEDIUM"}], "max_severity": "MEDIUM"}),
    )
    _, dims = compute_risk_score(entries)
    skills_dim = next(d for d in dims if d.name == "skills")
    assert skills_dim.score == 4.0


def test_skills_weights_sum_to_one() -> None:
    entries = (
        BomEntry(BomType.SKILLBOM, ComponentType.SKILL, "s", None,
                 {"findings": [], "max_severity": None}),
    )
    _, dims = compute_risk_score(entries)
    total = sum(d.weight for d in dims)
    assert abs(total - 1.0) < 0.01
