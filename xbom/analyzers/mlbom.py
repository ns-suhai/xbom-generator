"""ML-BOM analyzer - detect ML model files and extract metadata."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from xbom.analyzers.base import BaseAnalyzer
from xbom.models.bom_types import BomEntry, BomType, ComponentType

logger = logging.getLogger(__name__)

# Model file extensions and their frameworks
_MODEL_FORMATS: dict[str, str] = {
    ".onnx": "ONNX",
    ".pt": "PyTorch",
    ".pth": "PyTorch",
    ".h5": "TensorFlow/Keras",
    ".keras": "TensorFlow/Keras",
    ".tflite": "TensorFlow Lite",
    ".safetensors": "Hugging Face",
    ".pb": "TensorFlow",
    ".mlmodel": "Core ML",
}


class MlBomAnalyzer(BaseAnalyzer):
    """Detect ML model files and extract metadata."""

    @property
    def name(self) -> str:
        return "mlbom"

    def analyze(
        self,
        extracted_dir: Path,
        classified_files: dict[str, list[Path]],
    ) -> list[BomEntry]:
        entries: list[BomEntry] = []

        # Only consider files with known model extensions (reliable detection)
        model_files: set[Path] = set()
        for file_path in extracted_dir.rglob("*"):
            if file_path.is_file() and file_path.suffix.lower() in _MODEL_FORMATS:
                model_files.add(file_path)

        for model_path in model_files:
            ext = model_path.suffix.lower()
            framework = _MODEL_FORMATS.get(ext, "Unknown")
            metadata = {
                "framework": framework,
                "file_path": str(model_path.relative_to(extracted_dir)),
                "file_size_bytes": model_path.stat().st_size,
            }

            # Try to read model card / metadata from adjacent files
            model_card = self._find_model_card(model_path)
            if model_card:
                metadata.update(model_card)

            version_val = metadata.get("version")
            entries.append(BomEntry(
                bom_type=BomType.MLBOM,
                component_type=ComponentType.MODEL,
                name=model_path.stem,
                version=str(version_val) if version_val is not None else None,
                metadata=metadata,
            ))

        logger.info("ML-BOM: found %d model files", len(entries))
        return entries

    def _find_model_card(self, model_path: Path) -> dict[str, Any]:
        """Look for model card or metadata JSON near the model file."""
        candidates = [
            model_path.parent / "config.json",
            model_path.parent / "model_card.json",
            model_path.parent / "README.md",
        ]
        for candidate in candidates:
            if candidate.exists() and candidate.suffix == ".json":
                try:
                    data = json.loads(candidate.read_text())
                    result = {}
                    if "model_type" in data:
                        result["architecture"] = data["model_type"]
                    if "task_specific_params" in data:
                        result["task"] = str(data["task_specific_params"])
                    if "_name_or_path" in data:
                        result["source"] = data["_name_or_path"]
                    return result
                except (json.JSONDecodeError, OSError):
                    continue
        return {}
