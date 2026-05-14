"""Tests for the secrets analyzer (detect-secrets wrapper) with mocked subprocess."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from xbom.analyzers.secrets import SecretsAnalyzer
from xbom.models.bom_types import BomType


_SAMPLE_DETECT_SECRETS_OUTPUT = json.dumps({
    "results": {
        "app/config.py": [
            {
                "type": "AWS Access Key",
                "line_number": 1,
                "hashed_secret": "abc123",
            }
        ],
        "app/db.py": [
            {
                "type": "Private Key",
                "line_number": 10,
                "hashed_secret": "def456",
            },
            {
                "type": "Basic Auth Credentials",
                "line_number": 15,
                "hashed_secret": "ghi789",
            },
        ],
    }
})


@patch("xbom.analyzers.secrets.subprocess.run")
def test_parse_detect_secrets_output(mock_run: MagicMock, tmp_dir: Path) -> None:
    # Mock is_available check
    mock_run.side_effect = [
        MagicMock(returncode=0),  # version check
        MagicMock(returncode=0, stdout=_SAMPLE_DETECT_SECRETS_OUTPUT, stderr=""),  # scan
    ]
    analyzer = SecretsAnalyzer()
    entries = analyzer.analyze(tmp_dir, {})

    assert len(entries) == 3
    assert entries[0].bom_type == BomType.SECRETS
    assert entries[0].metadata["type"] == "AWS Access Key"
    assert entries[0].metadata["file_path"] == "app/config.py"
    assert entries[0].metadata["line"] == 1


@patch("xbom.analyzers.secrets.subprocess.run")
def test_no_secrets_found(mock_run: MagicMock, tmp_dir: Path) -> None:
    mock_run.side_effect = [
        MagicMock(returncode=0),  # version check
        MagicMock(returncode=0, stdout=json.dumps({"results": {}}), stderr=""),
    ]
    analyzer = SecretsAnalyzer()
    entries = analyzer.analyze(tmp_dir, {})
    assert entries == []


@patch("xbom.analyzers.secrets.subprocess.run")
def test_empty_output(mock_run: MagicMock, tmp_dir: Path) -> None:
    mock_run.side_effect = [
        MagicMock(returncode=0),  # version check
        MagicMock(returncode=0, stdout="", stderr=""),
    ]
    analyzer = SecretsAnalyzer()
    entries = analyzer.analyze(tmp_dir, {})
    assert entries == []


@patch("xbom.analyzers.secrets.subprocess.run")
def test_invalid_json_output(mock_run: MagicMock, tmp_dir: Path) -> None:
    mock_run.side_effect = [
        MagicMock(returncode=0),  # version check
        MagicMock(returncode=0, stdout="not json", stderr=""),
    ]
    analyzer = SecretsAnalyzer()
    entries = analyzer.analyze(tmp_dir, {})
    assert entries == []


@patch("xbom.analyzers.secrets.subprocess.run", side_effect=FileNotFoundError)
def test_detect_secrets_not_installed(mock_run: MagicMock, tmp_dir: Path) -> None:
    analyzer = SecretsAnalyzer()
    assert not analyzer.is_available()
    entries = analyzer.analyze(tmp_dir, {})
    assert entries == []


@patch("xbom.analyzers.secrets.subprocess.run")
def test_timeout(mock_run: MagicMock, tmp_dir: Path) -> None:
    import subprocess
    mock_run.side_effect = [
        MagicMock(returncode=0),  # version check
        subprocess.TimeoutExpired(cmd="detect-secrets", timeout=120),
    ]
    analyzer = SecretsAnalyzer()
    entries = analyzer.analyze(tmp_dir, {})
    assert entries == []


@patch("xbom.analyzers.secrets.subprocess.run")
def test_secret_values_not_in_entries(mock_run: MagicMock, tmp_dir: Path) -> None:
    """Verify actual secret values are never stored in BomEntry."""
    mock_run.side_effect = [
        MagicMock(returncode=0),
        MagicMock(returncode=0, stdout=_SAMPLE_DETECT_SECRETS_OUTPUT, stderr=""),
    ]
    analyzer = SecretsAnalyzer()
    entries = analyzer.analyze(tmp_dir, {})

    for entry in entries:
        # The entry should have hashed_secret but NEVER the actual secret value
        assert "hashed_secret" in entry.metadata
        # is_active should be None (not validated yet)
        assert entry.metadata["is_active"] is None


def test_analyzer_name() -> None:
    assert SecretsAnalyzer().name == "secrets"
