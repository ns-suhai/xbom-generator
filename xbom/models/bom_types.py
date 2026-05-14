"""Data models for xBOM entries and scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class BomType(str, Enum):
    SBOM = "sbom"
    SAASBOM = "saasbom"
    MLBOM = "mlbom"
    CBOM = "cbom"
    SECRETS = "secrets"
    SKILLBOM = "skillbom"
    MCPBOM = "mcpbom"


class ComponentType(str, Enum):
    LIBRARY = "library"
    SERVICE = "service"
    MODEL = "model"
    CRYPTO_ASSET = "crypto-asset"
    SECRET = "secret"
    SKILL = "skill"
    MCP_SERVER = "mcp-server"


class SafeLevel(int, Enum):
    CRITICAL = 1
    NEEDS_WORK = 2
    MODERATE = 3
    GOOD = 4
    EXCELLENT = 5

    @classmethod
    def from_score(cls, score: float) -> SafeLevel:
        if score >= 4.5:
            return cls.EXCELLENT
        if score >= 3.5:
            return cls.GOOD
        if score >= 2.5:
            return cls.MODERATE
        if score >= 1.5:
            return cls.NEEDS_WORK
        return cls.CRITICAL

    @property
    def label(self) -> str:
        return {1: "Critical Risk", 2: "Needs Work", 3: "Moderate",
                4: "Good", 5: "Excellent"}[self.value]

    @property
    def color(self) -> str:
        return {1: "#fb7185", 2: "#f97316", 3: "#fbbf24",
                4: "#38bdf8", 5: "#4ade80"}[self.value]


@dataclass(frozen=True)
class BomEntry:
    bom_type: BomType
    component_type: ComponentType
    name: str
    version: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DimensionScore:
    name: str
    score: float  # 1.0 - 5.0
    weight: float
    details: str = ""


class AutonomyLevel(int, Enum):
    TOOL_ASSISTED = 1
    SEMI_AUTONOMOUS = 2
    AUTONOMOUS_GUARDRAILS = 3
    FULLY_AUTONOMOUS = 4

    @property
    def label(self) -> str:
        return {1: "L1: Tool-Assisted", 2: "L2: Semi-Autonomous",
                3: "L3: Autonomous + Guardrails", 4: "L4: Fully Autonomous"}[self.value]


@dataclass(frozen=True)
class AgentManifest:
    autonomy_level: AutonomyLevel
    trust_boundaries: dict[str, Any] = field(default_factory=dict)
    delegation_chains: tuple[str, ...] = ()
    communication_protocols: tuple[str, ...] = ()
    total_tools_exposed: int = 0
    has_network_access: bool = False
    has_shell_access: bool = False
    has_file_write: bool = False


@dataclass(frozen=True)
class ScanResult:
    package_path: str
    entries: tuple[BomEntry, ...]
    risk_score: float
    safe_level: SafeLevel
    dimension_scores: tuple[DimensionScore, ...] = ()
    agent_manifest: AgentManifest | None = None
    scan_duration_ms: int = 0
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def sbom_entries(self) -> tuple[BomEntry, ...]:
        return tuple(e for e in self.entries if e.bom_type == BomType.SBOM)

    @property
    def saasbom_entries(self) -> tuple[BomEntry, ...]:
        return tuple(e for e in self.entries if e.bom_type == BomType.SAASBOM)

    @property
    def mlbom_entries(self) -> tuple[BomEntry, ...]:
        return tuple(e for e in self.entries if e.bom_type == BomType.MLBOM)

    @property
    def cbom_entries(self) -> tuple[BomEntry, ...]:
        return tuple(e for e in self.entries if e.bom_type == BomType.CBOM)

    @property
    def secrets_entries(self) -> tuple[BomEntry, ...]:
        return tuple(e for e in self.entries if e.bom_type == BomType.SECRETS)

    @property
    def skill_entries(self) -> tuple[BomEntry, ...]:
        return tuple(e for e in self.entries if e.bom_type == BomType.SKILLBOM)

    @property
    def mcp_entries(self) -> tuple[BomEntry, ...]:
        return tuple(e for e in self.entries if e.bom_type == BomType.MCPBOM)
