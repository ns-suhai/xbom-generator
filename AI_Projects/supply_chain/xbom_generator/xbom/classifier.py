"""File type classifier using magic bytes."""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Category -> MIME type prefixes/patterns
_CATEGORY_RULES: list[tuple[str, list[str]]] = [
    ("executables", [
        "application/x-executable",
        "application/x-mach-binary",
        "application/x-dosexec",
        "application/x-pie-executable",
        "application/x-sharedlib",
    ]),
    ("libraries", [
        "application/java-archive",
        "application/x-java-archive",
        "application/x-archive",
        "application/x-object",
    ]),
    ("models", [
        "application/octet-stream",  # Needs extension check too
    ]),
    ("certificates", [
        "application/x-x509",
        "application/x-pem-file",
        "application/pkix-cert",
    ]),
    ("configs", [
        "application/json",
        "application/xml",
        "application/x-yaml",
        "text/x-yaml",
        "application/toml",
        "text/x-ini",
    ]),
    ("scripts", [
        "text/x-python",
        "text/x-script.python",
        "text/x-shellscript",
        "text/x-ruby",
        "application/javascript",
        "text/x-java",
        "text/x-c",
        "text/x-c++",
    ]),
]

_MODEL_EXTENSIONS = {
    ".onnx", ".pt", ".pth", ".h5", ".keras",
    ".tflite", ".safetensors", ".bin", ".pb",
    ".mlmodel", ".mlpackage",
}

_CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".p12", ".pfx", ".key"}

# Agent supply chain asset detection (name/path based)
_SKILL_FILENAMES = {
    "skill.md", "plugin.json", "plugin.yaml",
    ".mcp.json", "mcp.json",
    "action.yml", "action.yaml",
    "agents.md", "claude.md", "gemini.md",
}

_SKILL_FILENAME_PREFIXES = ("mcp-config",)

_SKILL_PARENT_DIRS = {".claude", ".cursor", ".copilot"}


def _is_skill_file(file_path: Path, extracted_dir: Path) -> bool:
    """Check if a file is an agent supply chain asset by name/path."""
    name_lower = file_path.name.lower()
    if name_lower in _SKILL_FILENAMES:
        return True
    if any(name_lower.startswith(p) for p in _SKILL_FILENAME_PREFIXES):
        return True
    try:
        rel = file_path.relative_to(extracted_dir)
        parts = rel.parts
        if any(p.lower() == "skills" and name_lower.endswith(".md") for p in parts):
            return True
        if any(p in _SKILL_PARENT_DIRS for p in parts):
            return True
    except ValueError:
        pass
    return False


def _get_mime_type(file_path: Path) -> str:
    """Get MIME type for a file using python-magic."""
    try:
        import magic
        return magic.from_file(str(file_path), mime=True)
    except ImportError:
        # Fallback: basic extension-based detection
        return _extension_fallback(file_path)
    except Exception:
        return "application/octet-stream"


def _extension_fallback(file_path: Path) -> str:
    """Fallback MIME detection based on file extension."""
    ext = file_path.suffix.lower()
    ext_map = {
        ".py": "text/x-python", ".js": "application/javascript",
        ".java": "text/x-java", ".rb": "text/x-ruby",
        ".sh": "text/x-shellscript", ".json": "application/json",
        ".xml": "application/xml", ".yaml": "application/x-yaml",
        ".yml": "application/x-yaml", ".toml": "application/toml",
        ".ini": "text/x-ini", ".cfg": "text/x-ini",
        ".jar": "application/java-archive",
        ".exe": "application/x-dosexec", ".dll": "application/x-dosexec",
        ".so": "application/x-sharedlib",
    }
    return ext_map.get(ext, "application/octet-stream")


def _categorize(file_path: Path, mime: str) -> str:
    """Determine file category from MIME type and extension."""
    ext = file_path.suffix.lower()

    # Extension-based overrides (more reliable for some types)
    if ext in _MODEL_EXTENSIONS:
        return "models"
    if ext in _CERT_EXTENSIONS:
        return "certificates"

    # MIME-based categorization
    for category, mime_patterns in _CATEGORY_RULES:
        for pattern in mime_patterns:
            if mime.startswith(pattern):
                return category

    # Text files that don't match specific categories
    if mime.startswith("text/"):
        return "data"

    return "unknown"


def classify_files(extracted_dir: Path) -> dict[str, list[Path]]:
    """Classify all files in extracted directory by type.

    Args:
        extracted_dir: Directory containing extracted package files.

    Returns:
        Dict mapping category names to lists of file paths.
        Categories: executables, libraries, configs, models,
        certificates, scripts, data, unknown.
    """
    result: dict[str, list[Path]] = {
        "executables": [],
        "libraries": [],
        "configs": [],
        "models": [],
        "certificates": [],
        "scripts": [],
        "skills": [],
        "data": [],
        "unknown": [],
    }

    for file_path in extracted_dir.rglob("*"):
        if not file_path.is_file():
            continue
        if file_path.stat().st_size == 0:
            continue

        # Skill files detected by name/path first (before MIME)
        if _is_skill_file(file_path, extracted_dir):
            result["skills"].append(file_path)
            continue

        mime = _get_mime_type(file_path)
        category = _categorize(file_path, mime)
        result[category].append(file_path)

    total = sum(len(v) for v in result.values())
    logger.info(
        "Classified %d files: %s",
        total,
        ", ".join(f"{k}={len(v)}" for k, v in result.items() if v),
    )
    return result
