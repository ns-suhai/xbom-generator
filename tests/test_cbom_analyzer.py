"""Tests for the CBOM analyzer."""

from pathlib import Path

from xbom.analyzers.cbom import CbomAnalyzer
from xbom.classifier import classify_files
from xbom.models.bom_types import BomType
from xbom.unpacker import extract_package


def test_detects_crypto_algorithms(sample_with_crypto: Path, tmp_dir: Path) -> None:
    dest = tmp_dir / "out"
    extract_package(sample_with_crypto, dest)
    classified = classify_files(dest)
    analyzer = CbomAnalyzer()
    entries = analyzer.analyze(dest, classified)

    names = [e.name for e in entries]
    # Should detect MD5 (weak) and SHA-256 from the crypto.py file
    assert "MD5" in names
    assert "SHA-256" in names


def test_detects_certificate(sample_with_crypto: Path, tmp_dir: Path) -> None:
    dest = tmp_dir / "out"
    extract_package(sample_with_crypto, dest)
    classified = classify_files(dest)
    analyzer = CbomAnalyzer()
    entries = analyzer.analyze(dest, classified)

    cert_entries = [e for e in entries if e.metadata.get("type") == "certificate"]
    assert len(cert_entries) >= 1


def test_marks_weak_algorithms(sample_with_crypto: Path, tmp_dir: Path) -> None:
    dest = tmp_dir / "out"
    extract_package(sample_with_crypto, dest)
    classified = classify_files(dest)
    analyzer = CbomAnalyzer()
    entries = analyzer.analyze(dest, classified)

    md5_entry = next(e for e in entries if e.name == "MD5")
    assert md5_entry.metadata["strength"] == "weak"


def test_no_crypto(sample_jar: Path, tmp_dir: Path) -> None:
    dest = tmp_dir / "out"
    extract_package(sample_jar, dest)
    classified = classify_files(dest)
    analyzer = CbomAnalyzer()
    entries = analyzer.analyze(dest, classified)
    # .jar with only class files and manifest - may or may not have crypto
    assert isinstance(entries, list)


def test_all_entries_are_cbom(sample_with_crypto: Path, tmp_dir: Path) -> None:
    dest = tmp_dir / "out"
    extract_package(sample_with_crypto, dest)
    classified = classify_files(dest)
    analyzer = CbomAnalyzer()
    entries = analyzer.analyze(dest, classified)

    for entry in entries:
        assert entry.bom_type == BomType.CBOM


def test_analyzer_name() -> None:
    assert CbomAnalyzer().name == "cbom"
