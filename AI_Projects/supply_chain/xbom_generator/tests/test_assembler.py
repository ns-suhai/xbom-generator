"""Tests for the CycloneDX assembler."""

import json

from xbom.assembler import assemble_cyclonedx, to_json
from xbom.models.bom_types import (
    BomEntry,
    BomType,
    ComponentType,
    DimensionScore,
    SafeLevel,
    ScanResult,
)


def _make_scan_result(entries: tuple[BomEntry, ...] = ()) -> ScanResult:
    return ScanResult(
        package_path="test.jar",
        entries=entries,
        risk_score=4.2,
        safe_level=SafeLevel.GOOD,
        dimension_scores=(
            DimensionScore("vulns", 4.5, 0.30),
            DimensionScore("secrets", 5.0, 0.25),
        ),
    )


def test_assemble_empty_scan() -> None:
    result = _make_scan_result()
    doc = assemble_cyclonedx(result)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert "components" not in doc
    assert "services" not in doc


def test_assemble_sbom_components() -> None:
    entries = (
        BomEntry(BomType.SBOM, ComponentType.LIBRARY, "lodash", "4.17.21",
                 {"purl": "pkg:npm/lodash@4.17.21", "licenses": ["MIT"], "type": "library", "cpe": ""}),
        BomEntry(BomType.SBOM, ComponentType.LIBRARY, "express", "4.18.2",
                 {"purl": "pkg:npm/express@4.18.2", "licenses": ["MIT"], "type": "library", "cpe": ""}),
    )
    result = _make_scan_result(entries)
    doc = assemble_cyclonedx(result)
    assert len(doc["components"]) == 2
    assert doc["components"][0]["name"] == "lodash"
    assert doc["components"][0]["version"] == "4.17.21"


def test_assemble_saasbom_services() -> None:
    entries = (
        BomEntry(BomType.SAASBOM, ComponentType.SERVICE, "stripe-api", None,
                 {"url": "https://api.stripe.com/v1", "protocol": "https"}),
    )
    result = _make_scan_result(entries)
    doc = assemble_cyclonedx(result)
    assert len(doc["services"]) == 1
    assert doc["services"][0]["endpoints"] == ["https://api.stripe.com/v1"]


def test_assemble_secrets_as_vulnerabilities() -> None:
    entries = (
        BomEntry(BomType.SECRETS, ComponentType.SECRET, "AWS Access Key", None,
                 {"type": "aws-access-key", "file_path": "config.py", "is_active": True}),
    )
    result = _make_scan_result(entries)
    doc = assemble_cyclonedx(result)
    assert len(doc["vulnerabilities"]) == 1
    assert "SECRET-" in doc["vulnerabilities"][0]["id"]


def test_assemble_mlbom_components() -> None:
    entries = (
        BomEntry(BomType.MLBOM, ComponentType.MODEL, "bert-base", "1.0",
                 {"framework": "pytorch"}),
    )
    result = _make_scan_result(entries)
    doc = assemble_cyclonedx(result)
    assert doc["components"][0]["type"] == "machine-learning-model"


def test_assemble_cbom_components() -> None:
    entries = (
        BomEntry(BomType.CBOM, ComponentType.CRYPTO_ASSET, "AES-256-CBC", None,
                 {"algorithm": "AES", "quantum_level": 1}),
    )
    result = _make_scan_result(entries)
    doc = assemble_cyclonedx(result)
    assert "cryptoProperties" in doc["components"][0]


def test_safe_level_in_metadata() -> None:
    result = _make_scan_result()
    doc = assemble_cyclonedx(result)
    props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert props["xbom:safe-level"] == "4"
    assert props["xbom:risk-score"] == "4.20"


def test_to_json_produces_valid_json() -> None:
    entries = (
        BomEntry(BomType.SBOM, ComponentType.LIBRARY, "test", "1.0", {}),
    )
    result = _make_scan_result(entries)
    raw = to_json(result)
    doc = json.loads(raw)
    assert doc["bomFormat"] == "CycloneDX"


def test_mixed_bom_types() -> None:
    entries = (
        BomEntry(BomType.SBOM, ComponentType.LIBRARY, "lib", "1.0", {}),
        BomEntry(BomType.SAASBOM, ComponentType.SERVICE, "api", None, {"url": "https://api.example.com"}),
        BomEntry(BomType.MLBOM, ComponentType.MODEL, "model", "2.0", {"framework": "tf"}),
        BomEntry(BomType.CBOM, ComponentType.CRYPTO_ASSET, "RSA", None, {"algorithm": "RSA"}),
        BomEntry(BomType.SECRETS, ComponentType.SECRET, "key", None, {"type": "api-key"}),
    )
    result = _make_scan_result(entries)
    doc = assemble_cyclonedx(result)
    assert len(doc["components"]) == 3  # SBOM + MLBOM + CBOM
    assert len(doc["services"]) == 1    # SAASBOM
    assert len(doc["vulnerabilities"]) == 1  # SECRETS
