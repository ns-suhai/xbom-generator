"""Base analyzer interface for all xBOM analyzers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from xbom.models.bom_types import BomEntry


class BaseAnalyzer(ABC):
    """Base class for all xBOM analyzers.

    Each analyzer inspects extracted package contents and produces
    BomEntry objects for its domain (SBOM, SaaS, ML, Crypto, Secrets).
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique analyzer name (e.g., 'sbom', 'saasbom')."""
        ...

    @abstractmethod
    def analyze(
        self,
        extracted_dir: Path,
        classified_files: dict[str, list[Path]],
    ) -> list[BomEntry]:
        """Analyze extracted files and return BOM entries.

        Args:
            extracted_dir: Root directory of extracted package contents.
            classified_files: Files grouped by category from classifier.

        Returns:
            List of BomEntry objects discovered by this analyzer.
        """
        ...

    def is_available(self) -> bool:
        """Check if analyzer dependencies are met. Default: True."""
        return True
