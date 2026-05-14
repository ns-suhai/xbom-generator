"""SaaSBOM analyzer - extract URLs and API endpoints from binary strings."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from xbom.analyzers.base import BaseAnalyzer
from xbom.models.bom_types import BomEntry, BomType, ComponentType

logger = logging.getLogger(__name__)

# URL pattern: matches http(s) URLs
_URL_PATTERN = re.compile(
    r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'
)

# Known false positives to filter out
_IGNORE_DOMAINS = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
    "example.com", "example.org", "example.net",
    "schemas.xmlsoap.org", "www.w3.org", "xmlns.com",
    "purl.org", "docs.python.org", "docs.oracle.com",
    "creativecommons.org", "opensource.org",
}

_IGNORE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".css", ".woff", ".woff2", ".ttf", ".eot",
}


def _extract_domain(url: str) -> str:
    """Extract domain from a URL."""
    try:
        # Remove protocol
        after_proto = url.split("://", 1)[1] if "://" in url else url
        # Remove path and port
        domain = after_proto.split("/")[0].split(":")[0]
        return domain.lower()
    except (IndexError, ValueError):
        return ""


def _should_skip(url: str) -> bool:
    """Check if a URL should be filtered out."""
    domain = _extract_domain(url)
    if domain in _IGNORE_DOMAINS:
        return True
    if any(url.lower().endswith(ext) for ext in _IGNORE_EXTENSIONS):
        return True
    # Skip relative-looking URLs
    if "://" not in url:
        return True
    return False


class SaasBomAnalyzer(BaseAnalyzer):
    """Discover SaaS/API endpoints by scanning file contents for URLs."""

    @property
    def name(self) -> str:
        return "saasbom"

    def analyze(
        self,
        extracted_dir: Path,
        classified_files: dict[str, list[Path]],
    ) -> list[BomEntry]:
        seen_domains: set[str] = set()
        entries: list[BomEntry] = []

        # Scan all text-readable files
        scannable = (
            classified_files.get("scripts", [])
            + classified_files.get("configs", [])
            + classified_files.get("data", [])
        )

        for file_path in scannable:
            try:
                content = file_path.read_text(errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue

            for match in _URL_PATTERN.finditer(content):
                url = match.group(0).rstrip(".,;:\"')")
                if _should_skip(url):
                    continue

                domain = _extract_domain(url)
                if domain in seen_domains:
                    continue
                seen_domains.add(domain)

                protocol = "https" if url.startswith("https") else "http"
                entries.append(BomEntry(
                    bom_type=BomType.SAASBOM,
                    component_type=ComponentType.SERVICE,
                    name=domain,
                    version=None,
                    metadata={
                        "url": url,
                        "protocol": protocol,
                        "source_file": str(file_path.relative_to(extracted_dir)),
                    },
                ))

        logger.info("SaaSBOM: found %d unique service endpoints", len(entries))
        return entries
