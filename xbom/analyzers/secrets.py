"""Secrets analyzer - wraps detect-secrets for pattern detection."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from xbom.analyzers.base import BaseAnalyzer
from xbom.models.bom_types import BomEntry, BomType, ComponentType

logger = logging.getLogger(__name__)


class SecretsAnalyzer(BaseAnalyzer):
    """Detect exposed secrets using detect-secrets (Yelp, 700+ patterns)."""

    @property
    def name(self) -> str:
        return "secrets"

    def _resolve_binary(self) -> str | None:
        """Resolve detect-secrets to an absolute path."""
        return shutil.which("detect-secrets")

    def is_available(self) -> bool:
        try:
            binary = self._resolve_binary()
            if not binary:
                return False
            subprocess.run(
                [binary, "--version"],
                capture_output=True, timeout=5,
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def analyze(
        self,
        extracted_dir: Path,
        classified_files: dict[str, list[Path]],
    ) -> list[BomEntry]:
        binary = self._resolve_binary()
        if not binary:
            logger.warning("detect-secrets not available, skipping secrets analysis")
            return []

        try:
            result = subprocess.run(
                [binary, "scan", str(extracted_dir), "--all-files"],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            logger.error("detect-secrets timed out on %s", extracted_dir)
            return []
        except FileNotFoundError:
            logger.warning("detect-secrets binary not found")
            return []

        if not result.stdout.strip():
            return []

        return self._parse_results(result.stdout, extracted_dir)

    def _parse_results(self, raw_json: str, extracted_dir: Path) -> list[BomEntry]:
        """Parse detect-secrets JSON output into BomEntry list."""
        entries: list[BomEntry] = []
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            logger.error("Failed to parse detect-secrets output")
            return []

        for file_path, secrets_list in data.get("results", {}).items():
            for secret in secrets_list:
                secret_type = secret.get("type", "Unknown")
                # NEVER include the actual secret value in the entry
                entries.append(BomEntry(
                    bom_type=BomType.SECRETS,
                    component_type=ComponentType.SECRET,
                    name=f"{secret_type} in {Path(file_path).name}",
                    version=None,
                    metadata={
                        "type": secret_type,
                        "file_path": file_path,
                        "line": secret.get("line_number", 0),
                        "is_active": None,  # Set by live validation if enabled
                        "hashed_secret": secret.get("hashed_secret", ""),
                    },
                ))

        logger.info("Secrets: found %d potential secrets", len(entries))
        return entries
