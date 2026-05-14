"""Tests for the file classifier."""

from pathlib import Path

from xbom.classifier import classify_files


def test_classify_jar_contents(sample_jar: Path, tmp_dir: Path) -> None:
    from xbom.unpacker import extract_package

    dest = tmp_dir / "out"
    extract_package(sample_jar, dest)
    classified = classify_files(dest)

    # Should have at least some files classified
    total = sum(len(v) for v in classified.values())
    assert total > 0


def test_classify_with_model(sample_with_model: Path, tmp_dir: Path) -> None:
    from xbom.unpacker import extract_package

    dest = tmp_dir / "out"
    extract_package(sample_with_model, dest)
    classified = classify_files(dest)

    # .onnx file should be classified as model
    model_names = [p.name for p in classified["models"]]
    assert "classifier.onnx" in model_names


def test_classify_with_crypto(sample_with_crypto: Path, tmp_dir: Path) -> None:
    from xbom.unpacker import extract_package

    dest = tmp_dir / "out"
    extract_package(sample_with_crypto, dest)
    classified = classify_files(dest)

    # .pem file should be classified as certificate
    cert_names = [p.name for p in classified["certificates"]]
    assert "server.pem" in cert_names


def test_classify_empty_dir(tmp_dir: Path) -> None:
    empty = tmp_dir / "empty"
    empty.mkdir()
    classified = classify_files(empty)
    total = sum(len(v) for v in classified.values())
    assert total == 0


def test_classify_skips_zero_byte_files(tmp_dir: Path) -> None:
    d = tmp_dir / "files"
    d.mkdir()
    (d / "empty.txt").write_text("")
    (d / "nonempty.txt").write_text("content")
    classified = classify_files(d)
    total = sum(len(v) for v in classified.values())
    assert total == 1  # only nonempty.txt


def test_all_categories_present(tmp_dir: Path) -> None:
    d = tmp_dir / "files"
    d.mkdir()
    (d / "test.py").write_text("print('hello')")
    classified = classify_files(d)
    expected_keys = {"executables", "libraries", "configs", "models",
                     "certificates", "scripts", "skills", "data", "unknown"}
    assert set(classified.keys()) == expected_keys


def test_classify_skill_md(tmp_dir: Path) -> None:
    d = tmp_dir / "pkg"
    d.mkdir()
    (d / "SKILL.md").write_text("# My Skill\nDo something useful")
    result = classify_files(d)
    assert len(result["skills"]) == 1
    assert result["skills"][0].name == "SKILL.md"


def test_classify_plugin_json(tmp_dir: Path) -> None:
    d = tmp_dir / "pkg"
    d.mkdir()
    (d / "plugin.json").write_text('{"name": "my-plugin"}')
    result = classify_files(d)
    assert len(result["skills"]) == 1


def test_classify_mcp_config(tmp_dir: Path) -> None:
    d = tmp_dir / "pkg"
    d.mkdir()
    (d / ".mcp.json").write_text('{"servers": {}}')
    result = classify_files(d)
    assert len(result["skills"]) == 1


def test_classify_agent_instructions(tmp_dir: Path) -> None:
    d = tmp_dir / "pkg"
    d.mkdir()
    (d / "CLAUDE.md").write_text("# Instructions")
    (d / "AGENTS.md").write_text("# Agents")
    result = classify_files(d)
    assert len(result["skills"]) == 2


def test_classify_action_yml(tmp_dir: Path) -> None:
    d = tmp_dir / "pkg"
    d.mkdir()
    (d / "action.yml").write_text("name: My Action\nruns:\n  using: composite")
    result = classify_files(d)
    assert len(result["skills"]) == 1


def test_classify_claude_dir(tmp_dir: Path) -> None:
    d = tmp_dir / "pkg"
    d.mkdir()
    claude_dir = d / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_text('{"key": "val"}')
    result = classify_files(d)
    assert len(result["skills"]) == 1


def test_classify_skill_not_stealing_configs(tmp_dir: Path) -> None:
    d = tmp_dir / "pkg"
    d.mkdir()
    (d / "package.json").write_text('{"name": "app"}')
    result = classify_files(d)
    assert len(result["skills"]) == 0
    assert len(result["configs"]) == 1
