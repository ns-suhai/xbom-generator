"""Package unpacker with zip bomb protection."""

from __future__ import annotations

import logging
import tarfile
import tempfile
import zipfile
from pathlib import Path

from xbom.exceptions import (
    ExtractionError,
    ResourceLimitError,
    UnsupportedFormatError,
)

logger = logging.getLogger(__name__)

# Supported archive extensions mapped to extraction strategy
_ZIP_EXTENSIONS = {".zip", ".jar", ".whl", ".ear", ".war", ".apk", ".aar"}
_TAR_EXTENSIONS = {".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz"}
_DEB_EXTENSIONS = {".deb"}
_RPM_EXTENSIONS = {".rpm"}

DEFAULT_MAX_EXTRACT_BYTES = 1024 * 1024 * 1024  # 1 GB


def _is_zip_like(path: Path) -> bool:
    return path.suffix.lower() in _ZIP_EXTENSIONS or zipfile.is_zipfile(path)


def _is_tar_like(path: Path) -> bool:
    suffix = "".join(path.suffixes[-2:]).lower() if len(path.suffixes) >= 2 else path.suffix.lower()
    return suffix in _TAR_EXTENSIONS or tarfile.is_tarfile(str(path))


def _extract_zip(
    archive_path: Path,
    dest: Path,
    max_bytes: int,
) -> int:
    """Extract a zip-like archive, tracking cumulative bytes."""
    cumulative = 0
    dest_resolved = dest.resolve()
    with zipfile.ZipFile(archive_path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            # Path traversal protection
            target = (dest / info.filename).resolve()
            if not str(target).startswith(str(dest_resolved)):
                logger.warning("Skipping path traversal attempt: %s", info.filename)
                continue
            if cumulative + info.file_size > max_bytes:
                raise ResourceLimitError(
                    f"Extraction aborted: would exceed {max_bytes / (1024**3):.1f}GB limit. "
                    f"Use --max-extract-size to increase."
                )
            zf.extract(info, dest)
            cumulative += info.file_size
    return cumulative


def _extract_tar(
    archive_path: Path,
    dest: Path,
    max_bytes: int,
) -> int:
    """Extract a tar archive, tracking cumulative bytes."""
    cumulative = 0
    with tarfile.open(str(archive_path), "r:*") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            if member.size < 0:
                continue
            if cumulative + member.size > max_bytes:
                raise ResourceLimitError(
                    f"Extraction aborted: would exceed {max_bytes / (1024**3):.1f}GB limit. "
                    f"Use --max-extract-size to increase."
                )
            # Security: prevent path traversal
            resolved = (dest / member.name).resolve()
            if not str(resolved).startswith(str(dest.resolve())):
                logger.warning("Skipping path traversal attempt: %s", member.name)
                continue
            tf.extract(member, dest, filter="data")
            cumulative += member.size
    return cumulative


def extract_package(
    package_path: Path,
    dest_dir: Path | None = None,
    max_bytes: int = DEFAULT_MAX_EXTRACT_BYTES,
) -> Path:
    """Extract a binary package to a temporary directory.

    Args:
        package_path: Path to the archive file.
        dest_dir: Optional destination directory. If None, creates a temp dir.
        max_bytes: Maximum cumulative extracted bytes (zip bomb protection).

    Returns:
        Path to directory containing extracted files.

    Raises:
        UnsupportedFormatError: Archive format not recognized.
        ExtractionError: Extraction failed (corrupt archive, I/O error).
        ResourceLimitError: Extracted content exceeds max_bytes.
    """
    if not package_path.exists():
        raise ExtractionError(f"File not found: {package_path}")

    if dest_dir is None:
        dest_dir = Path(tempfile.mkdtemp(prefix="xbom-"))

    dest_dir.mkdir(parents=True, exist_ok=True)

    try:
        if _is_zip_like(package_path):
            bytes_extracted = _extract_zip(package_path, dest_dir, max_bytes)
        elif _is_tar_like(package_path):
            bytes_extracted = _extract_tar(package_path, dest_dir, max_bytes)
        else:
            raise UnsupportedFormatError(
                f"Unsupported format: {package_path.suffix}. "
                f"Supported: {', '.join(sorted(_ZIP_EXTENSIONS | _TAR_EXTENSIONS))}"
            )
    except (zipfile.BadZipFile, tarfile.TarError) as exc:
        raise ExtractionError(
            f"Failed to extract {package_path.name}: archive may be corrupted. {exc}"
        ) from exc

    logger.info(
        "Extracted %s (%s bytes) to %s",
        package_path.name,
        f"{bytes_extracted:,}",
        dest_dir,
    )
    return dest_dir
