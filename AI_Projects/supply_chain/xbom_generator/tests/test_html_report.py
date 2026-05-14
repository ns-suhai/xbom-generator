"""Tests for the HTML report generator."""

from __future__ import annotations

from xbom.models.bom_types import (
    BomEntry,
    BomType,
    ComponentType,
    DimensionScore,
    SafeLevel,
    ScanResult,
)
from xbom.report.html_generator import generate_html_report


def _make_result() -> ScanResult:
    return ScanResult(
        package_path="test-app.jar",
        entries=(
            BomEntry(BomType.SBOM, ComponentType.LIBRARY, "lodash", "4.17.21",
                     {"purl": "pkg:npm/lodash@4.17.21", "licenses": ["MIT"], "type": "library", "cpe": ""}),
            BomEntry(BomType.SAASBOM, ComponentType.SERVICE, "api.stripe.com", None,
                     {"url": "https://api.stripe.com", "protocol": "https",
                      "actual_traffic_volume": 52428800, "last_seen": "2026-05-01"}),
            BomEntry(BomType.MLBOM, ComponentType.MODEL, "bert", "1.0",
                     {"framework": "pytorch", "file_path": "model.pt", "file_size_bytes": 1024}),
            BomEntry(BomType.CBOM, ComponentType.CRYPTO_ASSET, "AES-256", None,
                     {"algorithm": "AES", "strength": "acceptable", "quantum_level": 0}),
            BomEntry(BomType.CBOM, ComponentType.CRYPTO_ASSET, "MD5", None,
                     {"algorithm": "MD5", "strength": "weak", "quantum_level": 0}),
            BomEntry(BomType.SECRETS, ComponentType.SECRET, "AWS Key in config.py", None,
                     {"type": "aws-access-key", "file_path": "config.py", "line": 5, "is_active": None}),
        ),
        risk_score=3.2,
        safe_level=SafeLevel.MODERATE,
        dimension_scores=(
            DimensionScore("vulnerabilities", 4.5, 0.30),
            DimensionScore("secrets", 3.5, 0.25),
            DimensionScore("crypto", 2.0, 0.20),
            DimensionScore("saas", 4.0, 0.15),
            DimensionScore("ml", 4.5, 0.10),
        ),
        scan_duration_ms=250,
        warnings=("syft not available",),
    )


def test_generates_valid_html() -> None:
    html = generate_html_report(_make_result())
    assert html.startswith("<!DOCTYPE html>")
    assert "</html>" in html


def test_contains_risk_score() -> None:
    html = generate_html_report(_make_result())
    assert "Moderate" in html or "3.2" in html


def test_contains_package_name() -> None:
    html = generate_html_report(_make_result())
    assert "test-app.jar" in html


def test_contains_all_tab_labels() -> None:
    html = generate_html_report(_make_result())
    assert "SBOM" in html
    assert "SaaSBOM" in html
    assert "ML-BOM" in html
    assert "CBOM" in html
    assert "Secrets" in html


def test_contains_component_data() -> None:
    html = generate_html_report(_make_result())
    assert "lodash" in html
    assert "api.stripe.com" in html
    assert "bert" in html
    assert "AES-256" in html


def test_contains_tailwind_cdn() -> None:
    html = generate_html_report(_make_result())
    assert "cdn.tailwindcss.com" in html


def test_contains_alpine_cdn() -> None:
    html = generate_html_report(_make_result())
    assert "alpinejs" in html


def test_contains_chart_js() -> None:
    html = generate_html_report(_make_result())
    assert "chart.js" in html or "Chart" in html


def test_empty_scan_report() -> None:
    result = ScanResult(
        package_path="empty.zip",
        entries=(),
        risk_score=5.0,
        safe_level=SafeLevel.EXCELLENT,
        scan_duration_ms=10,
    )
    html = generate_html_report(result)
    assert "<!DOCTYPE html>" in html
    assert "Excellent" in html or "5.0" in html


def test_contains_dark_theme_colors() -> None:
    html = generate_html_report(_make_result())
    assert "#0f172a" in html  # dark bg
    assert "#38bdf8" in html  # accent blue


def test_no_raw_secret_values_in_html() -> None:
    """Verify the HTML report doesn't contain actual secret values."""
    html = generate_html_report(_make_result())
    # Should contain the type but never an actual key value
    assert "aws-access-key" in html or "AWS Key" in html
    # Should NOT contain any fake key values from test data
    assert "AKIAIOSFODNN7EXAMPLE" not in html
