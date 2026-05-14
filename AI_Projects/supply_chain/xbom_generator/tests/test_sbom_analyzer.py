"""Tests for the SBOM analyzer (syft wrapper) with mocked subprocess."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from xbom.analyzers.sbom import SbomAnalyzer
from xbom.exceptions import DependencyMissingError
from xbom.models.bom_types import BomType


_SAMPLE_CYCLONEDX = json.dumps({
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": [
        {
            "type": "library",
            "name": "lodash",
            "version": "4.17.21",
            "purl": "pkg:npm/lodash@4.17.21",
            "licenses": [{"license": {"id": "MIT"}}],
        },
        {
            "type": "library",
            "name": "express",
            "version": "4.18.2",
            "purl": "pkg:npm/express@4.18.2",
            "licenses": [{"license": {"name": "MIT"}}],
        },
        {
            "type": "library",
            "name": "no-license-lib",
            "version": "1.0.0",
        },
    ]
})


@patch("xbom.analyzers.sbom.shutil.which", return_value="/usr/local/bin/syft")
@patch("xbom.analyzers.sbom.subprocess.run")
def test_parse_syft_output(mock_run: MagicMock, mock_which: MagicMock, tmp_dir: Path) -> None:
    mock_run.return_value = MagicMock(returncode=0, stdout=_SAMPLE_CYCLONEDX, stderr="")
    analyzer = SbomAnalyzer()
    entries = analyzer.analyze(tmp_dir, {})

    assert len(entries) == 3
    assert entries[0].name == "lodash"
    assert entries[0].version == "4.17.21"
    assert entries[0].bom_type == BomType.SBOM
    assert "MIT" in entries[0].metadata["licenses"]
    assert entries[0].metadata["purl"] == "pkg:npm/lodash@4.17.21"


@patch("xbom.analyzers.sbom.shutil.which", return_value="/usr/local/bin/syft")
@patch("xbom.analyzers.sbom.subprocess.run")
def test_handles_empty_output(mock_run: MagicMock, mock_which: MagicMock, tmp_dir: Path) -> None:
    mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
    analyzer = SbomAnalyzer()
    entries = analyzer.analyze(tmp_dir, {})
    assert entries == []


@patch("xbom.analyzers.sbom.shutil.which", return_value="/usr/local/bin/syft")
@patch("xbom.analyzers.sbom.subprocess.run")
def test_handles_invalid_json(mock_run: MagicMock, mock_which: MagicMock, tmp_dir: Path) -> None:
    mock_run.return_value = MagicMock(returncode=0, stdout="not json{{{", stderr="")
    analyzer = SbomAnalyzer()
    entries = analyzer.analyze(tmp_dir, {})
    assert entries == []


@patch("xbom.analyzers.sbom.shutil.which", return_value="/usr/local/bin/syft")
@patch("xbom.analyzers.sbom.subprocess.run")
def test_handles_nonzero_exit_with_output(mock_run: MagicMock, mock_which: MagicMock, tmp_dir: Path) -> None:
    mock_run.return_value = MagicMock(returncode=1, stdout=_SAMPLE_CYCLONEDX, stderr="warning")
    analyzer = SbomAnalyzer()
    entries = analyzer.analyze(tmp_dir, {})
    assert len(entries) == 3  # Still parses partial output


@patch("xbom.analyzers.sbom.shutil.which", return_value="/usr/local/bin/syft")
@patch("xbom.analyzers.sbom.subprocess.run")
def test_handles_nonzero_exit_no_output(mock_run: MagicMock, mock_which: MagicMock, tmp_dir: Path) -> None:
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="fatal error")
    analyzer = SbomAnalyzer()
    entries = analyzer.analyze(tmp_dir, {})
    assert entries == []


@patch("xbom.analyzers.sbom.shutil.which", return_value="/usr/local/bin/syft")
@patch("xbom.analyzers.sbom.subprocess.run", side_effect=TimeoutError("timed out"))
def test_handles_timeout(mock_run: MagicMock, mock_which: MagicMock, tmp_dir: Path) -> None:
    import subprocess
    mock_run.side_effect = subprocess.TimeoutExpired(cmd="syft", timeout=120)
    analyzer = SbomAnalyzer()
    entries = analyzer.analyze(tmp_dir, {})
    assert entries == []


@patch("xbom.analyzers.sbom.shutil.which", return_value=None)
def test_syft_not_installed(mock_which: MagicMock, tmp_dir: Path) -> None:
    analyzer = SbomAnalyzer()
    assert not analyzer.is_available()
    with pytest.raises(DependencyMissingError, match="syft not found"):
        analyzer.analyze(tmp_dir, {})


@patch("xbom.analyzers.sbom.shutil.which", return_value="/usr/local/bin/syft")
def test_is_available(mock_which: MagicMock) -> None:
    analyzer = SbomAnalyzer()
    assert analyzer.is_available()


def test_analyzer_name() -> None:
    assert SbomAnalyzer().name == "sbom"


@patch("xbom.analyzers.sbom.shutil.which", return_value="/usr/local/bin/syft")
@patch("xbom.analyzers.sbom.subprocess.run")
def test_components_without_licenses(mock_run: MagicMock, mock_which: MagicMock, tmp_dir: Path) -> None:
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout=json.dumps({"components": [{"name": "bare-lib", "version": "1.0"}]}),
        stderr="",
    )
    analyzer = SbomAnalyzer()
    entries = analyzer.analyze(tmp_dir, {})
    assert len(entries) == 1
    assert entries[0].metadata["licenses"] == []
