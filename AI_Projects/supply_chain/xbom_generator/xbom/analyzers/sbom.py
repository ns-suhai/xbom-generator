"""SBOM analyzer wrapping Anchore syft CLI."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path

from xbom.analyzers.base import BaseAnalyzer
from xbom.exceptions import DependencyMissingError
from xbom.models.bom_types import BomEntry, BomType, ComponentType

logger = logging.getLogger(__name__)

SYFT_INSTALL_HINT = (
    "syft not found. Install: "
    "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh"
)


class SbomAnalyzer(BaseAnalyzer):
    """Generate SBOM using Anchore syft (230+ package types)."""

    @property
    def name(self) -> str:
        return "sbom"

    def is_available(self) -> bool:
        return shutil.which("syft") is not None

    def analyze(
        self,
        extracted_dir: Path,
        classified_files: dict[str, list[Path]],
    ) -> list[BomEntry]:
        if not self.is_available():
            raise DependencyMissingError(SYFT_INSTALL_HINT)

        try:
            result = subprocess.run(
                ["syft", str(extracted_dir), "-o", "cyclonedx-json"],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            logger.error("syft timed out after 120s on %s", extracted_dir)
            return []
        except FileNotFoundError:
            raise DependencyMissingError(SYFT_INSTALL_HINT)

        if result.returncode != 0:
            logger.warning("syft exited with code %d: %s", result.returncode, result.stderr[:500])
            # syft may still produce partial output on non-zero exit
            if not result.stdout.strip():
                return []

        return self._parse_cyclonedx(result.stdout)

    def _parse_cyclonedx(self, raw_json: str) -> list[BomEntry]:
        """Parse CycloneDX JSON output from syft into BomEntry list."""
        entries: list[BomEntry] = []
        try:
            doc = json.loads(raw_json)
        except json.JSONDecodeError:
            logger.error("Failed to parse syft CycloneDX JSON output")
            return []

        for component in doc.get("components", []):
            name = component.get("name", "unknown")
            version = component.get("version")
            licenses = [
                lic.get("license", {}).get("id", lic.get("license", {}).get("name", ""))
                for lic in component.get("licenses", [])
                if lic.get("license")
            ]
            purl = component.get("purl", "")

            entries.append(BomEntry(
                bom_type=BomType.SBOM,
                component_type=ComponentType.LIBRARY,
                name=name,
                version=version,
                metadata={
                    "purl": purl,
                    "licenses": licenses,
                    "type": component.get("type", "library"),
                    "cpe": component.get("cpe", ""),
                },
            ))

        logger.info("SBOM: found %d components via syft", len(entries))
        return entries
