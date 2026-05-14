"""Agent Manifest post-processor — computes autonomy, trust, and delegation from BOM entries."""

from __future__ import annotations

import logging
from typing import Any

from xbom.models.bom_types import AgentManifest, AutonomyLevel, BomEntry, BomType

logger = logging.getLogger(__name__)


def compute_agent_manifest(entries: tuple[BomEntry, ...]) -> AgentManifest | None:
    """Compute the Agent Manifest from all BOM entries.

    Returns None if no agent-related entries (skills or MCP) are present.
    """
    skill_entries = [e for e in entries if e.bom_type == BomType.SKILLBOM]
    mcp_entries = [e for e in entries if e.bom_type == BomType.MCPBOM]

    if not skill_entries and not mcp_entries:
        return None

    has_shell = _detect_shell_access(skill_entries)
    has_network = _detect_network_access(skill_entries, mcp_entries)
    has_file_write = _detect_file_write(skill_entries)
    delegation_chains = _detect_delegation_chains(skill_entries)
    protocols = _detect_protocols(mcp_entries, skill_entries)
    total_tools = _count_tools(mcp_entries, skill_entries)
    trust_boundaries = _compute_trust_boundaries(skill_entries, mcp_entries)

    autonomy_level = _classify_autonomy(
        has_shell=has_shell,
        has_network=has_network,
        has_file_write=has_file_write,
        has_delegation=len(delegation_chains) > 0,
        has_approval_gates=_detect_approval_gates(skill_entries),
    )

    manifest = AgentManifest(
        autonomy_level=autonomy_level,
        trust_boundaries=trust_boundaries,
        delegation_chains=delegation_chains,
        communication_protocols=protocols,
        total_tools_exposed=total_tools,
        has_network_access=has_network,
        has_shell_access=has_shell,
        has_file_write=has_file_write,
    )

    logger.info(
        "Agent Manifest: %s | tools=%d | protocols=%s | delegation=%d chains",
        autonomy_level.label, total_tools, protocols, len(delegation_chains),
    )
    return manifest


def _classify_autonomy(
    has_shell: bool,
    has_network: bool,
    has_file_write: bool,
    has_delegation: bool,
    has_approval_gates: bool,
) -> AutonomyLevel:
    """Classify autonomy level L1-L4 based on detected capabilities."""
    if has_delegation and not has_approval_gates:
        return AutonomyLevel.FULLY_AUTONOMOUS
    if has_shell and has_network and has_file_write:
        return AutonomyLevel.AUTONOMOUS_GUARDRAILS
    if has_shell or has_network:
        return AutonomyLevel.SEMI_AUTONOMOUS
    return AutonomyLevel.TOOL_ASSISTED


def _detect_shell_access(skill_entries: list[BomEntry]) -> bool:
    """Check if any skill grants shell/bash execution."""
    for entry in skill_entries:
        graph = entry.metadata.get("execution_graph", {})
        nodes = graph.get("nodes", [])
        if any(n.get("type") == "shell" for n in nodes):
            return True
        findings = entry.metadata.get("findings", [])
        if any(f.get("category") == "shell_execution" for f in findings):
            return True
    return False


def _detect_network_access(
    skill_entries: list[BomEntry], mcp_entries: list[BomEntry]
) -> bool:
    """Check if any entry grants network access."""
    if any(e.metadata.get("trust_level") == "remote" for e in mcp_entries):
        return True
    for entry in skill_entries:
        graph = entry.metadata.get("execution_graph", {})
        nodes = graph.get("nodes", [])
        if any(n.get("type") == "network" for n in nodes):
            return True
        findings = entry.metadata.get("findings", [])
        if any(f.get("category") == "data_exfiltration" for f in findings):
            return True
    return False


def _detect_file_write(skill_entries: list[BomEntry]) -> bool:
    """Check if any skill grants filesystem write access."""
    for entry in skill_entries:
        graph = entry.metadata.get("execution_graph", {})
        nodes = graph.get("nodes", [])
        if any(n.get("type") == "file" for n in nodes):
            return True
        findings = entry.metadata.get("findings", [])
        if any(f.get("category") == "filesystem_access" for f in findings):
            return True
    return False


def _detect_delegation_chains(skill_entries: list[BomEntry]) -> tuple[str, ...]:
    """Detect sub-agent delegation from execution graphs."""
    chains: list[str] = []
    for entry in skill_entries:
        graph = entry.metadata.get("execution_graph", {})
        nodes = graph.get("nodes", [])
        for node in nodes:
            if node.get("type") == "skill_call":
                chains.append(f"{entry.name} -> {node.get('id', 'unknown')}")
    return tuple(sorted(set(chains)))


def _detect_protocols(
    mcp_entries: list[BomEntry], skill_entries: list[BomEntry]
) -> tuple[str, ...]:
    """Detect communication protocols from MCP and skill entries."""
    protocols: set[str] = set()
    for entry in mcp_entries:
        protocol = entry.metadata.get("protocol", "")
        if protocol:
            protocols.add(protocol)
    for entry in skill_entries:
        graph = entry.metadata.get("execution_graph", {})
        nodes = graph.get("nodes", [])
        for node in nodes:
            if node.get("type") == "tool_call":
                protocols.add("tool_use")
                break
    return tuple(sorted(protocols))


def _count_tools(
    mcp_entries: list[BomEntry], skill_entries: list[BomEntry]
) -> int:
    """Count total tools exposed across MCP servers and skills."""
    total = 0
    for entry in mcp_entries:
        declared = entry.metadata.get("tools_declared")
        if isinstance(declared, int):
            total += declared
    # Each skill file itself is a tool
    total += len(skill_entries)
    return total


def _detect_approval_gates(skill_entries: list[BomEntry]) -> bool:
    """Check if any skill mentions human approval/confirmation gates."""
    approval_indicators = (
        "confirm", "approve", "permission", "ask user", "human-in-loop",
        "AskUserQuestion", "user approval",
    )
    for entry in skill_entries:
        provenance = entry.metadata.get("provenance", {})
        desc = provenance.get("description", "")
        if any(ind.lower() in desc.lower() for ind in approval_indicators):
            return True
    return False


def _compute_trust_boundaries(
    skill_entries: list[BomEntry], mcp_entries: list[BomEntry]
) -> dict[str, Any]:
    """Compute trust boundary summary."""
    network_targets: set[str] = set()
    file_paths: set[str] = set()
    remote_servers: list[str] = []

    for entry in skill_entries:
        graph = entry.metadata.get("execution_graph", {})
        nodes = graph.get("nodes", [])
        for node in nodes:
            node_id = node.get("id", "")
            node_type = node.get("type", "")
            if node_type == "network":
                network_targets.add(node_id)
            elif node_type == "file":
                file_paths.add(node_id)

    for entry in mcp_entries:
        if entry.metadata.get("trust_level") == "remote":
            remote_servers.append(entry.name)

    return {
        "network_targets": sorted(network_targets),
        "file_paths": sorted(file_paths),
        "remote_mcp_servers": remote_servers,
        "local_mcp_servers": [
            e.name for e in mcp_entries if e.metadata.get("trust_level") == "local"
        ],
    }
