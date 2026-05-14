"""Tests for the SaaSBOM analyzer."""

from pathlib import Path

from xbom.analyzers.saasbom import SaasBomAnalyzer
from xbom.classifier import classify_files
from xbom.models.bom_types import BomType
from xbom.unpacker import extract_package


def test_finds_urls(sample_with_urls: Path, tmp_dir: Path) -> None:
    dest = tmp_dir / "out"
    extract_package(sample_with_urls, dest)
    classified = classify_files(dest)
    analyzer = SaasBomAnalyzer()
    entries = analyzer.analyze(dest, classified)

    names = [e.name for e in entries]
    assert "api.stripe.com" in names
    assert "api.openai.com" in names


def test_filters_localhost(sample_with_urls: Path, tmp_dir: Path) -> None:
    dest = tmp_dir / "out"
    extract_package(sample_with_urls, dest)
    classified = classify_files(dest)
    analyzer = SaasBomAnalyzer()
    entries = analyzer.analyze(dest, classified)

    names = [e.name for e in entries]
    assert "localhost" not in names


def test_empty_package(tmp_dir: Path) -> None:
    empty = tmp_dir / "empty"
    empty.mkdir()
    classified = classify_files(empty)
    analyzer = SaasBomAnalyzer()
    entries = analyzer.analyze(empty, classified)
    assert entries == []


def test_all_entries_are_saasbom(sample_with_urls: Path, tmp_dir: Path) -> None:
    dest = tmp_dir / "out"
    extract_package(sample_with_urls, dest)
    classified = classify_files(dest)
    analyzer = SaasBomAnalyzer()
    entries = analyzer.analyze(dest, classified)

    for entry in entries:
        assert entry.bom_type == BomType.SAASBOM


def test_deduplicates_domains(tmp_dir: Path) -> None:
    """Same domain from multiple files should only appear once."""
    import zipfile
    pkg = tmp_dir / "dupe.zip"
    with zipfile.ZipFile(pkg, "w") as zf:
        zf.writestr("a.py", 'url = "https://api.example.io/v1"\n')
        zf.writestr("b.py", 'url = "https://api.example.io/v2"\n')
    dest = tmp_dir / "out"
    extract_package(pkg, dest)
    classified = classify_files(dest)
    analyzer = SaasBomAnalyzer()
    entries = analyzer.analyze(dest, classified)
    assert len([e for e in entries if e.name == "api.example.io"]) == 1


def test_analyzer_name() -> None:
    assert SaasBomAnalyzer().name == "saasbom"
