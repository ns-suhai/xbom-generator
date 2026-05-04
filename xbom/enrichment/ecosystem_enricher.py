"""Ecosystem enrichment interface for SkillBom entries.

Abstract base class for external intelligence providers (e.g., Manifold
Manifest) that add author reputation, cross-registry duplicate detection,
and ecosystem-level risk context.

The NoOpEcosystemEnricher is the default — passes entries through unchanged.
Concrete implementations can be activated via CLI flags when API availability
and commercial terms are confirmed.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from xbom.models.bom_types import BomEntry


class BaseEcosystemEnricher(ABC):
    """Interface for ecosystem graph enrichment providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def enrich(self, entries: list[BomEntry]) -> list[BomEntry]:
        ...

    def is_available(self) -> bool:
        return True


class NoOpEcosystemEnricher(BaseEcosystemEnricher):
    """Default no-op enricher. Passes entries through unchanged."""

    @property
    def name(self) -> str:
        return "noop"

    def enrich(self, entries: list[BomEntry]) -> list[BomEntry]:
        return entries
