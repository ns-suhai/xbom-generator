"""Tests for Agent Manifest post-processor."""
import pytest

from xbom.agent_manifest import compute_agent_manifest, _classify_autonomy
from xbom.models.bom_types import (
    AgentManifest, AutonomyLevel, BomEntry, BomType, ComponentType,
)


def _skill_entry(name="test-skill", findings=None, execution_graph=None, provenance=None):
    """Helper to create a SkillBOM entry."""
    return BomEntry(
        bom_type=BomType.SKILLBOM,
        component_type=ComponentType.SKILL,
        name=name,
        metadata={
            "findings": findings or [],
            "finding_count": len(findings) if findings else 0,
            "max_severity": None,
            "execution_graph": execution_graph or {"nodes": [], "edges": []},
            "provenance": provenance or {"content_hash": "abc123"},
        },
    )


def _mcp_entry(name="test-server", protocol="MCP-stdio", trust_level="local", tools=None):
    """Helper to create an MCP-BOM entry."""
    metadata = {"protocol": protocol, "trust_level": trust_level}
    if tools is not None:
        metadata["tools_declared"] = tools
    return BomEntry(
        bom_type=BomType.MCPBOM,
        component_type=ComponentType.MCP_SERVER,
        name=name,
        metadata=metadata,
    )


def test_returns_none_when_no_agent_entries():
    entries = (
        BomEntry(bom_type=BomType.SBOM, component_type=ComponentType.LIBRARY, name="lodash"),
    )
    assert compute_agent_manifest(entries) is None


def test_returns_manifest_for_skill_entries():
    entries = (_skill_entry(),)
    result = compute_agent_manifest(entries)
    assert result is not None
    assert isinstance(result, AgentManifest)


def test_returns_manifest_for_mcp_entries():
    entries = (_mcp_entry(),)
    result = compute_agent_manifest(entries)
    assert result is not None


def test_autonomy_l1_no_capabilities():
    result = compute_agent_manifest((_skill_entry(),))
    assert result is not None
    assert result.autonomy_level == AutonomyLevel.TOOL_ASSISTED


def test_autonomy_l2_shell_access():
    entry = _skill_entry(
        findings=[{"category": "shell_execution", "severity": "HIGH"}]
    )
    result = compute_agent_manifest((entry,))
    assert result is not None
    assert result.autonomy_level == AutonomyLevel.SEMI_AUTONOMOUS


def test_autonomy_l2_network_via_mcp():
    entries = (
        _skill_entry(),
        _mcp_entry(trust_level="remote"),
    )
    result = compute_agent_manifest(entries)
    assert result is not None
    assert result.autonomy_level == AutonomyLevel.SEMI_AUTONOMOUS


def test_autonomy_l3_shell_network_file():
    entry = _skill_entry(
        findings=[{"category": "shell_execution", "severity": "HIGH"}],
        execution_graph={
            "nodes": [
                {"id": "curl", "type": "shell"},
                {"id": "https://api.example.com", "type": "network"},
                {"id": "/tmp/output.txt", "type": "file"},
            ],
            "edges": [],
        },
    )
    result = compute_agent_manifest((entry,))
    assert result is not None
    assert result.autonomy_level == AutonomyLevel.AUTONOMOUS_GUARDRAILS


def test_autonomy_l4_delegation_no_approval():
    entry = _skill_entry(
        execution_graph={
            "nodes": [
                {"id": "skill:deploy", "type": "skill_call"},
                {"id": "docker", "type": "shell"},
                {"id": "registry.io", "type": "network"},
                {"id": "/app/dist", "type": "file"},
            ],
            "edges": [],
        },
    )
    result = compute_agent_manifest((entry,))
    assert result is not None
    assert result.autonomy_level == AutonomyLevel.FULLY_AUTONOMOUS


def test_delegation_chains_detected():
    entry = _skill_entry(
        name="orchestrator",
        execution_graph={
            "nodes": [
                {"id": "skill:build", "type": "skill_call"},
                {"id": "skill:test", "type": "skill_call"},
            ],
            "edges": [],
        },
    )
    result = compute_agent_manifest((entry,))
    assert result is not None
    assert len(result.delegation_chains) == 2
    assert "orchestrator -> skill:build" in result.delegation_chains


def test_protocols_from_mcp():
    entries = (
        _mcp_entry("server1", protocol="MCP-stdio"),
        _mcp_entry("server2", protocol="MCP-HTTP"),
    )
    result = compute_agent_manifest(entries)
    assert result is not None
    assert "MCP-stdio" in result.communication_protocols
    assert "MCP-HTTP" in result.communication_protocols


def test_tool_count():
    entries = (
        _mcp_entry("s1", tools=5),
        _mcp_entry("s2", tools=10),
        _skill_entry("skill1"),
    )
    result = compute_agent_manifest(entries)
    assert result is not None
    assert result.total_tools_exposed == 16  # 5 + 10 + 1 skill


def test_trust_boundaries_network_targets():
    entry = _skill_entry(
        execution_graph={
            "nodes": [
                {"id": "api.github.com", "type": "network"},
                {"id": "registry.npmjs.org", "type": "network"},
            ],
            "edges": [],
        },
    )
    result = compute_agent_manifest((entry,))
    assert result is not None
    assert "api.github.com" in result.trust_boundaries["network_targets"]
    assert "registry.npmjs.org" in result.trust_boundaries["network_targets"]


def test_trust_boundaries_remote_mcp():
    entries = (
        _skill_entry(),
        _mcp_entry("ext-api", trust_level="remote"),
        _mcp_entry("local-db", trust_level="local"),
    )
    result = compute_agent_manifest(entries)
    assert result is not None
    assert "ext-api" in result.trust_boundaries["remote_mcp_servers"]
    assert "local-db" in result.trust_boundaries["local_mcp_servers"]


def test_classify_autonomy_function():
    assert _classify_autonomy(False, False, False, False, False) == AutonomyLevel.TOOL_ASSISTED
    assert _classify_autonomy(True, False, False, False, False) == AutonomyLevel.SEMI_AUTONOMOUS
    assert _classify_autonomy(False, True, False, False, False) == AutonomyLevel.SEMI_AUTONOMOUS
    assert _classify_autonomy(True, True, True, False, False) == AutonomyLevel.AUTONOMOUS_GUARDRAILS
    assert _classify_autonomy(True, True, True, True, False) == AutonomyLevel.FULLY_AUTONOMOUS
    assert _classify_autonomy(True, True, True, True, True) == AutonomyLevel.AUTONOMOUS_GUARDRAILS


def test_has_network_access_from_skill_graph():
    entry = _skill_entry(
        execution_graph={
            "nodes": [{"id": "example.com", "type": "network"}],
            "edges": [],
        },
    )
    result = compute_agent_manifest((entry,))
    assert result is not None
    assert result.has_network_access is True


def test_has_shell_access_from_graph():
    entry = _skill_entry(
        execution_graph={
            "nodes": [{"id": "docker", "type": "shell"}],
            "edges": [],
        },
    )
    result = compute_agent_manifest((entry,))
    assert result is not None
    assert result.has_shell_access is True
