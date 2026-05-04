"""Tests for the ML-BOM analyzer."""

from pathlib import Path

from xbom.analyzers.mlbom import MlBomAnalyzer
from xbom.classifier import classify_files
from xbom.models.bom_types import BomType
from xbom.unpacker import extract_package


def test_detects_onnx_model(sample_with_model: Path, tmp_dir: Path) -> None:
    dest = tmp_dir / "out"
    extract_package(sample_with_model, dest)
    classified = classify_files(dest)
    analyzer = MlBomAnalyzer()
    entries = analyzer.analyze(dest, classified)

    assert len(entries) == 1
    assert entries[0].name == "classifier"
    assert entries[0].metadata["framework"] == "ONNX"


def test_no_models(sample_jar: Path, tmp_dir: Path) -> None:
    dest = tmp_dir / "out"
    extract_package(sample_jar, dest)
    classified = classify_files(dest)
    analyzer = MlBomAnalyzer()
    entries = analyzer.analyze(dest, classified)
    assert entries == []


def test_all_entries_are_mlbom(sample_with_model: Path, tmp_dir: Path) -> None:
    dest = tmp_dir / "out"
    extract_package(sample_with_model, dest)
    classified = classify_files(dest)
    analyzer = MlBomAnalyzer()
    entries = analyzer.analyze(dest, classified)

    for entry in entries:
        assert entry.bom_type == BomType.MLBOM


def test_reads_config_json(tmp_dir: Path) -> None:
    """Model card metadata from config.json should be extracted."""
    import zipfile, json
    pkg = tmp_dir / "model_pkg.zip"
    with zipfile.ZipFile(pkg, "w") as zf:
        zf.writestr("model/weights.pt", b"fake pytorch model")
        zf.writestr("model/config.json", json.dumps({
            "model_type": "bert",
            "_name_or_path": "bert-base-uncased",
        }))
    dest = tmp_dir / "out"
    extract_package(pkg, dest)
    classified = classify_files(dest)
    analyzer = MlBomAnalyzer()
    entries = analyzer.analyze(dest, classified)

    assert len(entries) == 1
    assert entries[0].metadata.get("architecture") == "bert"
    assert entries[0].metadata.get("source") == "bert-base-uncased"


def test_analyzer_name() -> None:
    assert MlBomAnalyzer().name == "mlbom"
