"""Tests for the package unpacker."""

from pathlib import Path

import pytest

from xbom.exceptions import (
    ExtractionError,
    ResourceLimitError,
    UnsupportedFormatError,
)
from xbom.unpacker import extract_package


# --- .deb extraction tests ---


def test_extract_deb(sample_deb: Path, tmp_dir: Path) -> None:
    """Should extract data.tar contents from a .deb archive."""
    dest = tmp_dir / "out"
    result = extract_package(sample_deb, dest)
    assert result == dest
    assert (dest / "usr" / "bin" / "hello").exists()
    assert (dest / "usr" / "share" / "doc" / "README").exists()


def test_extract_deb_bomb_protection(sample_deb: Path, tmp_dir: Path) -> None:
    """Should abort deb extraction when exceeding max_bytes."""
    dest = tmp_dir / "out"
    with pytest.raises(ResourceLimitError, match="limit"):
        extract_package(sample_deb, dest, max_bytes=1)


def test_extract_deb_corrupt(tmp_dir: Path) -> None:
    """Should raise ExtractionError for corrupt .deb files."""
    corrupt = tmp_dir / "corrupt.deb"
    corrupt.write_bytes(b"!<arch>\nnot-valid-ar-content")
    with pytest.raises(ExtractionError, match="Failed to extract"):
        extract_package(corrupt)


# --- .rpm extraction tests ---


def test_extract_rpm(sample_rpm: Path, tmp_dir: Path) -> None:
    """Should extract cpio payload from an .rpm archive."""
    dest = tmp_dir / "out"
    result = extract_package(sample_rpm, dest)
    assert result == dest
    assert (dest / "usr" / "bin" / "hello").exists()
    assert (dest / "usr" / "share" / "doc" / "README").exists()


def test_extract_rpm_bomb_protection(sample_rpm: Path, tmp_dir: Path) -> None:
    """Should abort rpm extraction when exceeding max_bytes."""
    dest = tmp_dir / "out"
    with pytest.raises(ResourceLimitError, match="limit"):
        extract_package(sample_rpm, dest, max_bytes=1)


def test_extract_rpm_corrupt(tmp_dir: Path) -> None:
    """Should raise ExtractionError for corrupt .rpm files."""
    corrupt = tmp_dir / "corrupt.rpm"
    corrupt.write_bytes(b"\xed\xab\xee\xdb" + b"\x00" * 50)
    with pytest.raises(ExtractionError, match="Failed to extract"):
        extract_package(corrupt)


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
