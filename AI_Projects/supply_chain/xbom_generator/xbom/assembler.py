"""Merge BOM entries into CycloneDX v1.6 JSON output."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from xbom.exceptions import AssemblyError
from xbom.models.bom_types import BomEntry, BomType, ComponentType, ScanResult

logger = logging.getLogger(__name__)


def _entry_to_component(entry: BomEntry) -> dict[str, Any]:
    """Convert a BomEntry to a CycloneDX component dict."""
    component: dict[str, Any] = {
        "type": _map_component_type(entry.component_type),
        "name": entry.name,
    }
    if entry.version:
        component["version"] = entry.version
    if entry.metadata.get("purl"):
        component["purl"] = entry.metadata["purl"]
    if entry.metadata.get("licenses"):
        component["licenses"] = [
            {"license": {"id": lic}} if lic else {"license": {"name": "UNKNOWN"}}
            for lic in entry.metadata["licenses"]
        ]

    # ML-BOM: model card
    if entry.bom_type == BomType.MLBOM:
        component["type"] = "machine-learning-model"
        if entry.metadata.get("framework"):
            component.setdefault("properties", []).append(
                {"name": "ml:framework", "value": entry.metadata["framework"]}
            )

    # CBOM: crypto properties
    if entry.bom_type == BomType.CBOM:
        crypto_props = {}
        if entry.metadata.get("algorithm"):
            crypto_props["algorithmProperties"] = {
                "primitive": entry.metadata["algorithm"],
            }
        if entry.metadata.get("quantum_level"):
            crypto_props["nistQuantumSecurityLevel"] = entry.metadata["quantum_level"]
        if crypto_props:
            component["cryptoProperties"] = crypto_props

    return component


def _entry_to_service(entry: BomEntry) -> dict[str, Any]:
    """Convert a SaaSBOM entry to a CycloneDX service dict."""
    service: dict[str, Any] = {"name": entry.name}
    if entry.metadata.get("url"):
        service["endpoints"] = [entry.metadata["url"]]
    if entry.metadata.get("protocol"):
        service.setdefault("properties", []).append(
            {"name": "protocol", "value": entry.metadata["protocol"]}
        )
    # Network enrichment data
    for key in ("actual_traffic_volume", "last_seen", "data_classification"):
        if entry.metadata.get(key):
            service.setdefault("properties", []).append(
                {"name": f"netskope:{key}", "value": str(entry.metadata[key])}
            )
    return service


def _entry_to_vulnerability(entry: BomEntry) -> dict[str, Any]:
    """Convert a secrets entry to a CycloneDX vulnerability dict."""
    vuln: dict[str, Any] = {
        "id": f"SECRET-{uuid.uuid4().hex[:8].upper()}",
        "description": f"Exposed {entry.metadata.get('type', 'secret')}: {entry.name}",
        "source": {"name": "xbom-secrets-analyzer"},
        "properties": [],
    }
    if entry.metadata.get("file_path"):
        vuln["properties"].append(
            {"name": "file_path", "value": entry.metadata["file_path"]}
        )
    if entry.metadata.get("is_active") is not None:
        vuln["properties"].append(
            {"name": "is_active", "value": str(entry.metadata["is_active"])}
        )
    return vuln


def _entry_to_mcp_service(entry: BomEntry) -> dict[str, Any]:
    """Convert an MCP-BOM entry to a CycloneDX service dict."""
    service: dict[str, Any] = {"name": entry.name}
    props: list[dict[str, str]] = []
    props.append({"name": "xbom:agent:type", "value": "mcp-server"})
    if entry.metadata.get("protocol"):
        props.append({"name": "xbom:agent:protocol", "value": entry.metadata["protocol"]})
    if entry.metadata.get("trust_level"):
        props.append({"name": "xbom:agent:trust-level", "value": entry.metadata["trust_level"]})
    if entry.metadata.get("tools_declared") is not None:
        props.append({"name": "xbom:agent:tools-declared", "value": str(entry.metadata["tools_declared"])})
    if entry.metadata.get("credential_refs"):
        props.append({"name": "xbom:agent:credential-refs", "value": ",".join(entry.metadata["credential_refs"])})
    if entry.metadata.get("url"):
        service["endpoints"] = [entry.metadata["url"]]
    if props:
        service["properties"] = props
    return service


def _map_component_type(ct: ComponentType) -> str:
    return {
        ComponentType.LIBRARY: "library",
        ComponentType.SERVICE: "library",
        ComponentType.MODEL: "machine-learning-model",
        ComponentType.CRYPTO_ASSET: "library",
        ComponentType.SECRET: "library",
        ComponentType.MCP_SERVER: "library",
    }.get(ct, "library")


def assemble_cyclonedx(scan_result: ScanResult) -> dict[str, Any]:
    """Assemble a CycloneDX v1.6 JSON document from scan results.

    Args:
        scan_result: Complete scan result with all BOM entries.

    Returns:
        CycloneDX v1.6 JSON-serializable dict.

    Raises:
        AssemblyError: If assembly fails.
    """
    try:
        components = []
        services = []
        vulnerabilities = []

        for entry in scan_result.entries:
            if entry.bom_type == BomType.SAASBOM:
                services.append(_entry_to_service(entry))
            elif entry.bom_type == BomType.MCPBOM:
                services.append(_entry_to_mcp_service(entry))
            elif entry.bom_type == BomType.SECRETS:
                vulnerabilities.append(_entry_to_vulnerability(entry))
            else:
                components.append(_entry_to_component(entry))

        doc: dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": {
                    "components": [{
                        "type": "application",
                        "name": "xbom-generator",
                        "version": "0.1.0",
                    }]
                },
                "properties": [
                    {"name": "xbom:safe-level", "value": str(scan_result.safe_level.value)},
                    {"name": "xbom:risk-score", "value": f"{scan_result.risk_score:.2f}"},
                    {"name": "xbom:package", "value": scan_result.package_path},
                ],
            },
        }

        # Agent manifest properties
        if scan_result.agent_manifest is not None:
            am = scan_result.agent_manifest
            doc["metadata"]["properties"].extend([
                {"name": "xbom:agent:autonomy-level", "value": am.autonomy_level.label},
                {"name": "xbom:agent:total-tools", "value": str(am.total_tools_exposed)},
                {"name": "xbom:agent:has-shell", "value": str(am.has_shell_access).lower()},
                {"name": "xbom:agent:has-network", "value": str(am.has_network_access).lower()},
                {"name": "xbom:agent:has-file-write", "value": str(am.has_file_write).lower()},
            ])
            if am.communication_protocols:
                doc["metadata"]["properties"].append(
                    {"name": "xbom:agent:protocols", "value": ",".join(am.communication_protocols)}
                )
            if am.delegation_chains:
                doc["metadata"]["properties"].append(
                    {"name": "xbom:agent:delegation-chains", "value": str(len(am.delegation_chains))}
                )

        if components:
            doc["components"] = components
        if services:
            doc["services"] = services
        if vulnerabilities:
            doc["vulnerabilities"] = vulnerabilities

        logger.info(
            "Assembled CycloneDX: %d components, %d services, %d vulnerabilities",
            len(components), len(services), len(vulnerabilities),
        )
        return doc

    except Exception as exc:
        raise AssemblyError(f"Failed to assemble CycloneDX output: {exc}") from exc


def to_json(scan_result: ScanResult, indent: int = 2) -> str:
    """Serialize scan result to CycloneDX v1.6 JSON string."""
    doc = assemble_cyclonedx(scan_result)
    return json.dumps(doc, indent=indent, default=str)
