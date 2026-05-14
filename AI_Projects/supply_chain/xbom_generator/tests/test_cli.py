"""Tests for the CLI module."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from xbom.cli import main, _parse_size
from xbom.models.bom_types import (
    BomEntry,
    BomType,
    ComponentType,
    DimensionScore,
    SafeLevel,
    ScanResult,
)


def _make_mock_result(package_path: str = "test.jar") -> ScanResult:
    return ScanResult(
        package_path=package_path,
        entries=(
            BomEntry(BomType.SBOM, ComponentType.LIBRARY, "lodash", "4.17.21", {"purl": "", "licenses": ["MIT"], "type": "library", "cpe": ""}),
            BomEntry(BomType.SAASBOM, ComponentType.SERVICE, "api.stripe.com", None, {"url": "https://api.stripe.com", "protocol": "https"}),
            BomEntry(BomType.MLBOM, ComponentType.MODEL, "bert", "1.0", {"framework": "pytorch", "file_path": "model.pt", "file_size_bytes": 1024}),
            BomEntry(BomType.CBOM, ComponentType.CRYPTO_ASSET, "AES-256", None, {"algorithm": "AES", "strength": "acceptable", "quantum_level": 0}),
            BomEntry(BomType.SECRETS, ComponentType.SECRET, "AWS Key", None, {"type": "aws-key", "file_path": "config.py", "line": 5, "is_active": None}),
        ),
        risk_score=3.8,
        safe_level=SafeLevel.GOOD,
        dimension_scores=(
            DimensionScore("vulnerabilities", 4.5, 0.30),
            DimensionScore("secrets", 3.5, 0.25),
            DimensionScore("crypto", 4.0, 0.20),
            DimensionScore("saas", 4.0, 0.15),
            DimensionScore("ml", 4.5, 0.10),
        ),
        scan_duration_ms=150,
        warnings=("syft not available",),
    )


def test_parse_size_gb() -> None:
    assert _parse_size("1GB") == 1024 ** 3


def test_parse_size_mb() -> None:
    assert _parse_size("500MB") == 500 * 1024 ** 2


def test_parse_size_kb() -> None:
    assert _parse_size("100KB") == 100 * 1024


def test_parse_size_bytes() -> None:
    assert _parse_size("1024") == 1024


def test_scan_command_json_output(sample_jar: Path, tmp_dir: Path) -> None:
    runner = CliRunner()
    out_dir = str(tmp_dir / "out")
    with patch("xbom.cli.scan_package", return_value=_make_mock_result(str(sample_jar))):
        result = runner.invoke(main, [
            "scan", str(sample_jar),
            "--format", "json",
            "--output-dir", out_dir,
        ])
    assert result.exit_code == 0
    assert "SAFE 4" in result.output
    assert "1 components" in result.output
    assert "1 services" in result.output
    assert "1 models" in result.output
    assert "CycloneDX JSON" in result.output


def test_scan_command_shows_warnings(sample_jar: Path, tmp_dir: Path) -> None:
    runner = CliRunner()
    out_dir = str(tmp_dir / "out")
    with patch("xbom.cli.scan_package", return_value=_make_mock_result()):
        result = runner.invoke(main, [
            "scan", str(sample_jar),
            "--output-dir", out_dir,
        ])
    assert "Warning: syft not available" in result.output


def test_scan_command_html_output(sample_jar: Path, tmp_dir: Path) -> None:
    runner = CliRunner()
    out_dir = str(tmp_dir / "out")
    with patch("xbom.cli.scan_package", return_value=_make_mock_result(str(sample_jar))):
        result = runner.invoke(main, [
            "scan", str(sample_jar),
            "--format", "html",
            "--output-dir", out_dir,
        ])
    assert result.exit_code == 0
    assert "HTML Report" in result.output


def test_scan_command_error_handling(sample_jar: Path, tmp_dir: Path) -> None:
    runner = CliRunner()
    with patch("xbom.cli.scan_package", side_effect=RuntimeError("boom")):
        result = runner.invoke(main, [
            "scan", str(sample_jar),
            "--output-dir", str(tmp_dir / "out"),
        ])
    assert result.exit_code == 1
    assert "Error: boom" in result.output


def test_scan_nonexistent_file(tmp_dir: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        "scan", str(tmp_dir / "nonexistent.jar"),
    ])
    # Click validates exists=True before our code runs
    assert result.exit_code != 0


def test_version_flag() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_scan_both_format(sample_jar: Path, tmp_dir: Path) -> None:
    runner = CliRunner()
    out_dir = str(tmp_dir / "out")
    with patch("xbom.cli.scan_package", return_value=_make_mock_result(str(sample_jar))):
        result = runner.invoke(main, [
            "scan", str(sample_jar),
            "--format", "both",
            "--output-dir", out_dir,
        ])
    assert result.exit_code == 0
    assert "CycloneDX JSON" in result.output
    assert "HTML Report" in result.output


def test_scan_verbose_flag(sample_jar: Path, tmp_dir: Path) -> None:
    runner = CliRunner()
    with patch("xbom.cli.scan_package", return_value=_make_mock_result()):
        result = runner.invoke(main, [
            "scan", str(sample_jar),
            "--verbose",
            "--output-dir", str(tmp_dir / "out"),
        ])
    assert result.exit_code == 0
