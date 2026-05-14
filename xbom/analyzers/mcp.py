"""MCP-BOM analyzer - detect MCP server configurations and assess trust."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from xbom.analyzers.base import BaseAnalyzer
from xbom.models.bom_types import BomEntry, BomType, ComponentType

logger = logging.getLogger(__name__)

# Patterns indicating credential/secret references in MCP configs
_CREDENTIAL_PATTERNS = ("_KEY", "_TOKEN", "_SECRET", "_PASSWORD", "_API_KEY", "_AUTH")


def _detect_protocol(server_config: dict[str, Any]) -> str:
    """Detect the communication protocol for an MCP server."""
    if "url" in server_config:
        url = server_config["url"]
        if "sse" in url or "/sse" in url:
            return "MCP-SSE"
        return "MCP-HTTP"
    if server_config.get("transport") == "sse":
        return "MCP-SSE"
    if server_config.get("transport") in ("http", "streamable-http"):
        return "MCP-HTTP"
    return "MCP-stdio"


def _detect_trust_level(server_config: dict[str, Any]) -> str:
    """Determine trust level based on server config."""
    command = server_config.get("command", "")
    url = server_config.get("url", "")

    if url:
        if "localhost" in url or "127.0.0.1" in url:
            return "local"
        return "remote"
    if command in ("npx", "uvx", "node", "python", "python3", "bun"):
        return "local"
    if command.startswith("/") or command.startswith("./"):
        return "local"
    return "unknown"


def _extract_credential_refs(server_config: dict[str, Any]) -> list[str]:
    """Find environment variable references that look like credentials."""
    env_vars = server_config.get("env", {})
    cred_refs: list[str] = []
    for key in env_vars:
        upper_key = key.upper()
        if any(pat in upper_key for pat in _CREDENTIAL_PATTERNS):
            cred_refs.append(key)
    return cred_refs


def _count_tools(server_config: dict[str, Any]) -> int | None:
    """Extract tool count if declared in config."""
    tools = server_config.get("tools")
    if isinstance(tools, list):
        return len(tools)
    return None


class McpBomAnalyzer(BaseAnalyzer):
    """Analyzer for MCP server configuration files."""

    @property
    def name(self) -> str:
        return "mcp"

    def is_available(self) -> bool:
        return True

    def analyze(
        self, extracted_dir: Path, classified: dict[str, list[Path]]
    ) -> list[BomEntry]:
        """Analyze MCP config files and produce BOM entries."""
        mcp_files = classified.get("mcp_configs", [])
        if not mcp_files:
            return []

        entries: list[BomEntry] = []
        for config_path in mcp_files:
            try:
                content = config_path.read_text(encoding="utf-8")
                data = json.loads(content)
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to parse MCP config %s: %s", config_path, exc)
                continue

            servers = self._extract_servers(data)
            for server_name, server_config in servers.items():
                protocol = _detect_protocol(server_config)
                trust_level = _detect_trust_level(server_config)
                cred_refs = _extract_credential_refs(server_config)
                tool_count = _count_tools(server_config)

                metadata: dict[str, Any] = {
                    "protocol": protocol,
                    "trust_level": trust_level,
                    "config_file": config_path.name,
                    "command": server_config.get("command", ""),
                    "args": server_config.get("args", []),
                }
                if cred_refs:
                    metadata["credential_refs"] = cred_refs
                if tool_count is not None:
                    metadata["tools_declared"] = tool_count
                if server_config.get("url"):
                    metadata["url"] = server_config["url"]
                if server_config.get("env"):
                    metadata["env_var_count"] = len(server_config["env"])

                entries.append(BomEntry(
                    bom_type=BomType.MCPBOM,
                    component_type=ComponentType.MCP_SERVER,
                    name=server_name,
                    version=None,
                    metadata=metadata,
                ))

        logger.info("MCP-BOM: found %d server configurations", len(entries))
        return entries

    @staticmethod
    def _extract_servers(data: dict[str, Any]) -> dict[str, Any]:
        """Extract server definitions from various MCP config formats."""
        # Format 1: {"mcpServers": {"name": {...}}}  (claude_desktop_config.json)
        if "mcpServers" in data:
            servers = data["mcpServers"]
            if isinstance(servers, dict):
                return servers

        # Format 2: {"servers": {"name": {...}}}  (project .mcp.json)
        if "servers" in data:
            servers = data["servers"]
            if isinstance(servers, dict):
                return servers

        # Format 3: top-level server defs {"name": {"command": ...}}
        if all(isinstance(v, dict) for v in data.values()):
            has_server = any(
                "command" in v or "url" in v or "transport" in v
                for v in data.values()
            )
            if has_server:
                return data

        return {}
