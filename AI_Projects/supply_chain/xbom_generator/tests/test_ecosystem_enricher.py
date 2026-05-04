"""Tests for ecosystem enricher interface."""
from __future__ import annotations

import pytest

from xbom.enrichment.ecosystem_enricher import BaseEcosystemEnricher, NoOpEcosystemEnricher
from xbom.models.bom_types import BomEntry, BomType, ComponentType


def _make_skill_entry(name="test-skill"):
    return BomEntry(
        bom_type=BomType.SKILLBOM,
        component_type=ComponentType.SKILL,
        name=name,
        metadata={"ecosystem": None},
    )


def _make_sbom_entry():
    return BomEntry(
        bom_type=BomType.SBOM,
        component_type=ComponentType.LIBRARY,
        name="requests",
        version="2.28.0",
    )


def test_noop_enricher_name():
    assert NoOpEcosystemEnricher().name == "noop"


def test_noop_enricher_passes_through():
    enricher = NoOpEcosystemEnricher()
    entries = [_make_skill_entry(), _make_sbom_entry()]
    result = enricher.enrich(entries)
    assert result == entries
    assert len(result) == 2


def test_noop_enricher_is_available():
    assert NoOpEcosystemEnricher().is_available() is True


def test_noop_enricher_empty_list():
    assert NoOpEcosystemEnricher().enrich([]) == []


def test_base_enricher_is_abstract():
    with pytest.raises(TypeError):
        BaseEcosystemEnricher()
