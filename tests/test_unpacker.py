"""Tests for the package unpacker."""

from pathlib import Path

import pytest

from xbom.exceptions import (
    ExtractionError,
    ResourceLimitError,
    UnsupportedFormatError,
)
from xbom.unpacker import extract_package


def test_extract_jar(sample_jar: Path, tmp_dir: Path) -> None:
    dest = tmp_dir / "out"
    result = extract_package(sample_jar, dest)
    assert result == dest
    assert (dest / "META-INF" / "MANIFEST.MF").exists()
    assert (dest / "com" / "example" / "Main.class").exists()


def test_extract_whl(sample_whl: Path, tmp_dir: Path) -> None:
    dest = tmp_dir / "out"
    result = extract_package(sample_whl, dest)
    assert (dest / "sample" / "__init__.py").exists()


def test_extract_zip_with_model(sample_with_model: Path, tmp_dir: Path) -> None:
    dest = tmp_dir / "out"
    extract_package(sample_with_model, dest)
    assert (dest / "models" / "classifier.onnx").exists()
    assert (dest / "config.json").exists()


def test_unsupported_format(tmp_dir: Path) -> None:
    fake = tmp_dir / "file.xyz"
    fake.write_text("not an archive")
    with pytest.raises(UnsupportedFormatError, match="Unsupported format"):
        extract_package(fake)


def test_file_not_found(tmp_dir: Path) -> None:
    with pytest.raises(ExtractionError, match="File not found"):
        extract_package(tmp_dir / "nonexistent.jar")


def test_corrupt_archive(corrupt_zip: Path) -> None:
    with pytest.raises(ExtractionError, match="corrupted"):
        extract_package(corrupt_zip)


def test_zip_bomb_protection(zip_bomb: Path, tmp_dir: Path) -> None:
    """Extraction should abort when exceeding max_bytes."""
    dest = tmp_dir / "out"
    with pytest.raises(ResourceLimitError, match="limit"):
        # Set a 1KB limit so the 10MB file triggers the bomb protection
        extract_package(zip_bomb, dest, max_bytes=1024)


def test_auto_creates_dest_dir(sample_jar: Path, tmp_dir: Path) -> None:
    dest = tmp_dir / "deep" / "nested" / "out"
    extract_package(sample_jar, dest)
    assert dest.exists()
    assert any(dest.rglob("*"))


def test_extract_to_temp_dir(sample_jar: Path) -> None:
    """When no dest_dir given, creates a temp directory."""
    result = extract_package(sample_jar)
    assert result.exists()
    assert "xbom-" in result.name
