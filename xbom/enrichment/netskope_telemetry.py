"""SaaSBOM enrichment via Netskope cloud activity API."""

from __future__ import annotations

import logging
import os
from dataclasses import replace

import requests  # type: ignore[import]

from xbom.exceptions import EnrichmentError
from xbom.models.bom_types import BomEntry, BomType

logger = logging.getLogger(__name__)

_API_TIMEOUT = 10
_NETSKOPE_TOKEN_ENV = "NETSKOPE_API_TOKEN"
_NETSKOPE_TENANT_ENV = "NETSKOPE_TENANT_URL"


def enrich_saasbom(entries: list[BomEntry]) -> list[BomEntry]:
    """Enrich SaaSBOM entries with Netskope network telemetry.

    Cross-references discovered URLs against Netskope cloud activity logs
    to add actual traffic volume, last seen date, and data classification.

    If the Netskope API is unreachable, returns entries unchanged (graceful degradation).
    """
    token = os.environ.get(_NETSKOPE_TOKEN_ENV)
    tenant = os.environ.get(_NETSKOPE_TENANT_ENV)

    if not token or not tenant:
        logger.warning(
            "Netskope enrichment skipped: set %s and %s env vars",
            _NETSKOPE_TOKEN_ENV, _NETSKOPE_TENANT_ENV,
        )
        return entries

    enriched: list[BomEntry] = []
    for entry in entries:
        if entry.bom_type != BomType.SAASBOM:
            enriched.append(entry)
            continue

        domain = entry.name
        try:
            data = _query_netskope(tenant, token, domain)
            new_metadata = {**entry.metadata, **data}
            enriched.append(BomEntry(
                bom_type=entry.bom_type,
                component_type=entry.component_type,
                name=entry.name,
                version=entry.version,
                metadata=new_metadata,
            ))
        except EnrichmentError:
            enriched.append(entry)

    return enriched


def _query_netskope(tenant: str, token: str, domain: str) -> dict[str, object]:
    """Query Netskope API for traffic data about a domain."""
    url = f"{tenant.rstrip('/')}/api/v2/events/data/application"
    headers = {"Netskope-Api-Token": token}
    params = {
        "query": f"hostname eq '{domain}'",
        "timeperiod": "last_30_days",
        "limit": 1,
    }

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=_API_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

        if not data.get("data"):
            return {}

        record = data["data"][0] if data["data"] else {}
        return {
            "actual_traffic_volume": record.get("numbytes", 0),
            "last_seen": record.get("timestamp", ""),
            "data_classification": record.get("dlp_profile", "unclassified"),
            "bytes_sent": record.get("client_bytes", 0),
            "bytes_received": record.get("server_bytes", 0),
        }

    except requests.RequestException as exc:
        raise EnrichmentError(f"Netskope API error for {domain}: {exc}") from exc
