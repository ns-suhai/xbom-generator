"""Tests for MCP-BOM analyzer."""
import json
import pytest
from pathlib import Path

from xbom.analyzers.mcp import McpBomAnalyzer, _detect_protocol, _detect_trust_level
from xbom.models.bom_types import BomType, ComponentType


@pytest.fixture
def analyzer():
    return McpBomAnalyzer()


@pytest.fixture
def mcp_config_dir(tmp_path):
    """Create a directory with sample MCP config files."""
    config = {
        "mcpServers": {
            "slack": {
                "command": "npx",
                "args": ["-y", "@anthropic/mcp-slack"],
                "env": {
                    "SLACK_BOT_TOKEN": "xoxb-...",
                    "SLACK_TEAM_ID": "T12345"
                }
            },
            "remote-api": {
                "url": "https://api.example.com/mcp/sse",
                "transport": "sse",
                "env": {
                    "API_KEY": "sk-..."
                }
            },
            "local-db": {
                "command": "/usr/local/bin/mcp-postgres",
                "args": ["--connection", "localhost:5432"]
            }
        }
    }
    config_path = tmp_path / ".mcp.json"
    config_path.write_text(json.dumps(config))
    return tmp_path


def test_analyzer_name(analyzer):
    assert analyzer.name == "mcp"


def test_analyzer_is_available(analyzer):
    assert analyzer.is_available() is True


def test_detects_mcp_servers(analyzer, mcp_config_dir):
    classified = {"mcp_configs": [mcp_config_dir / ".mcp.json"]}
    entries = analyzer.analyze(mcp_config_dir, classified)
    assert len(entries) == 3
    names = {e.name for e in entries}
    assert names == {"slack", "remote-api", "local-db"}


def test_all_entries_are_mcpbom(analyzer, mcp_config_dir):
    classified = {"mcp_configs": [mcp_config_dir / ".mcp.json"]}
    entries = analyzer.analyze(mcp_config_dir, classified)
    for entry in entries:
        assert entry.bom_type == BomType.MCPBOM
        assert entry.component_type == ComponentType.MCP_SERVER


def test_detects_protocol_stdio(analyzer, mcp_config_dir):
    classified = {"mcp_configs": [mcp_config_dir / ".mcp.json"]}
    entries = analyzer.analyze(mcp_config_dir, classified)
    slack = next(e for e in entries if e.name == "slack")
    assert slack.metadata["protocol"] == "MCP-stdio"


def test_detects_protocol_sse(analyzer, mcp_config_dir):
    classified = {"mcp_configs": [mcp_config_dir / ".mcp.json"]}
    entries = analyzer.analyze(mcp_config_dir, classified)
    remote = next(e for e in entries if e.name == "remote-api")
    assert remote.metadata["protocol"] == "MCP-SSE"


def test_detects_trust_level_local(analyzer, mcp_config_dir):
    classified = {"mcp_configs": [mcp_config_dir / ".mcp.json"]}
    entries = analyzer.analyze(mcp_config_dir, classified)
    slack = next(e for e in entries if e.name == "slack")
    assert slack.metadata["trust_level"] == "local"


def test_detects_trust_level_remote(analyzer, mcp_config_dir):
    classified = {"mcp_configs": [mcp_config_dir / ".mcp.json"]}
    entries = analyzer.analyze(mcp_config_dir, classified)
    remote = next(e for e in entries if e.name == "remote-api")
    assert remote.metadata["trust_level"] == "remote"


def test_detects_credential_refs(analyzer, mcp_config_dir):
    classified = {"mcp_configs": [mcp_config_dir / ".mcp.json"]}
    entries = analyzer.analyze(mcp_config_dir, classified)
    slack = next(e for e in entries if e.name == "slack")
    assert "SLACK_BOT_TOKEN" in slack.metadata["credential_refs"]


def test_no_credential_refs_when_none(analyzer, mcp_config_dir):
    classified = {"mcp_configs": [mcp_config_dir / ".mcp.json"]}
    entries = analyzer.analyze(mcp_config_dir, classified)
    local_db = next(e for e in entries if e.name == "local-db")
    assert "credential_refs" not in local_db.metadata


def test_empty_classified(analyzer, tmp_path):
    entries = analyzer.analyze(tmp_path, {"mcp_configs": []})
    assert entries == []


def test_invalid_json(analyzer, tmp_path):
    bad_file = tmp_path / ".mcp.json"
    bad_file.write_text("not json {{{")
    entries = analyzer.analyze(tmp_path, {"mcp_configs": [bad_file]})
    assert entries == []


def test_project_format(analyzer, tmp_path):
    """Test 'servers' key format (project .mcp.json)."""
    config = {
        "servers": {
            "github": {
                "command": "npx",
                "args": ["-y", "@anthropic/mcp-github"],
                "env": {"GITHUB_TOKEN": "ghp_..."}
            }
        }
    }
    config_path = tmp_path / "mcp.json"
    config_path.write_text(json.dumps(config))
    entries = analyzer.analyze(tmp_path, {"mcp_configs": [config_path]})
    assert len(entries) == 1
    assert entries[0].name == "github"


def test_detect_protocol_http():
    assert _detect_protocol({"url": "http://localhost:3000/api"}) == "MCP-HTTP"


def test_detect_protocol_with_sse_in_url():
    assert _detect_protocol({"url": "https://example.com/sse"}) == "MCP-SSE"


def test_detect_trust_level_localhost():
    assert _detect_trust_level({"url": "http://localhost:8080"}) == "local"
    assert _detect_trust_level({"url": "http://127.0.0.1:8080"}) == "local"


def test_detect_trust_level_remote_url():
    assert _detect_trust_level({"url": "https://api.external.com/mcp"}) == "remote"
