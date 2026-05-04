"""Tests for Netskope telemetry enrichment with mocked API."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

from xbom.enrichment.netskope_telemetry import enrich_saasbom
from xbom.models.bom_types import BomEntry, BomType, ComponentType


def _make_saas_entry(name: str, url: str) -> BomEntry:
    return BomEntry(
        bom_type=BomType.SAASBOM,
        component_type=ComponentType.SERVICE,
        name=name,
        metadata={"url": url, "protocol": "https"},
    )


def _make_non_saas_entry() -> BomEntry:
    return BomEntry(
        bom_type=BomType.SBOM,
        component_type=ComponentType.LIBRARY,
        name="lodash",
        version="4.17.21",
    )


def test_enrichment_skipped_without_env_vars() -> None:
    """Should return entries unchanged when env vars not set."""
    entries = [_make_saas_entry("api.stripe.com", "https://api.stripe.com")]
    with patch.dict(os.environ, {}, clear=True):
        result = enrich_saasbom(entries)
    assert len(result) == 1
    assert "actual_traffic_volume" not in result[0].metadata


@patch("xbom.enrichment.netskope_telemetry.requests.get")
def test_enrichment_adds_traffic_data(mock_get: MagicMock) -> None:
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": [{
            "numbytes": 52428800,
            "timestamp": "2026-05-01T12:00:00Z",
            "dlp_profile": "PII",
            "client_bytes": 10485760,
            "server_bytes": 41943040,
        }]
    }
    mock_get.return_value = mock_resp

    entries = [_make_saas_entry("api.stripe.com", "https://api.stripe.com")]
    with patch.dict(os.environ, {
        "NETSKOPE_API_TOKEN": "test-token",
        "NETSKOPE_TENANT_URL": "https://tenant.goskope.com",
    }):
        result = enrich_saasbom(entries)

    assert result[0].metadata["actual_traffic_volume"] == 52428800
    assert result[0].metadata["data_classification"] == "PII"
    assert result[0].metadata["bytes_sent"] == 10485760


@patch("xbom.enrichment.netskope_telemetry.requests.get")
def test_enrichment_graceful_on_api_error(mock_get: MagicMock) -> None:
    """API failure should return unenriched entry, not crash."""
    import requests
    mock_get.side_effect = requests.ConnectionError("timeout")

    entries = [_make_saas_entry("api.stripe.com", "https://api.stripe.com")]
    with patch.dict(os.environ, {
        "NETSKOPE_API_TOKEN": "test-token",
        "NETSKOPE_TENANT_URL": "https://tenant.goskope.com",
    }):
        result = enrich_saasbom(entries)

    # Entry should be returned unchanged (not enriched, not lost)
    assert len(result) == 1
    assert "actual_traffic_volume" not in result[0].metadata


@patch("xbom.enrichment.netskope_telemetry.requests.get")
def test_enrichment_empty_api_response(mock_get: MagicMock) -> None:
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"data": []}
    mock_get.return_value = mock_resp

    entries = [_make_saas_entry("unknown-api.com", "https://unknown-api.com")]
    with patch.dict(os.environ, {
        "NETSKOPE_API_TOKEN": "test-token",
        "NETSKOPE_TENANT_URL": "https://tenant.goskope.com",
    }):
        result = enrich_saasbom(entries)

    assert len(result) == 1
    # No traffic data added since API returned empty
    assert "actual_traffic_volume" not in result[0].metadata


def test_non_saas_entries_passed_through() -> None:
    """Non-SaaSBOM entries should pass through unchanged."""
    entries = [_make_non_saas_entry(), _make_saas_entry("api.x.com", "https://api.x.com")]
    with patch.dict(os.environ, {}, clear=True):
        result = enrich_saasbom(entries)
    assert len(result) == 2
    assert result[0].bom_type == BomType.SBOM
    assert result[0].name == "lodash"
