"""Package unpacker with zip bomb protection."""

from __future__ import annotations

import gzip
import io
import logging
import struct
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


_AR_MAGIC = b"!<arch>\n"
_RPM_MAGIC = b"\xed\xab\xee\xdb"


def _is_zip_like(path: Path) -> bool:
    return path.suffix.lower() in _ZIP_EXTENSIONS or zipfile.is_zipfile(path)


def _is_tar_like(path: Path) -> bool:
    suffix = "".join(path.suffixes[-2:]).lower() if len(path.suffixes) >= 2 else path.suffix.lower()
    return suffix in _TAR_EXTENSIONS or tarfile.is_tarfile(str(path))


def _is_deb_like(path: Path) -> bool:
    if path.suffix.lower() in _DEB_EXTENSIONS:
        return True
    try:
        with open(path, "rb") as f:
            return f.read(8) == _AR_MAGIC
    except OSError:
        return False


def _is_rpm_like(path: Path) -> bool:
    if path.suffix.lower() in _RPM_EXTENSIONS:
        return True
    try:
        with open(path, "rb") as f:
            return f.read(4) == _RPM_MAGIC
    except OSError:
        return False


def _extract_zip(
    archive_path: Path,
    dest: Path,
    max_bytes: int,
) -> int:
    """Extract a zip-like archive, tracking cumulative bytes."""
    cumulative = 0
    with zipfile.ZipFile(archive_path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
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
            tf.extract(member, dest, filter="data")  # type: ignore[call-arg]
            cumulative += member.size
    return cumulative


def _parse_ar_members(data: bytes) -> list[tuple[str, bytes]]:
    """Parse an ar archive into (name, content) pairs."""
    if not data.startswith(_AR_MAGIC):
        raise ValueError("Not a valid ar archive")
    members = []
    offset = 8  # skip "!<arch>\n"
    while offset < len(data):
        if offset + 60 > len(data):
            break
        header = data[offset : offset + 60]
        name = header[0:16].rstrip(b"/ ").decode("ascii", errors="replace")
        try:
            size = int(header[48:58].strip())
        except ValueError:
            raise ValueError(f"Invalid ar member size at offset {offset}")
        offset += 60
        content = data[offset : offset + size]
        members.append((name, content))
        offset += size
        # ar members are 2-byte aligned
        if size % 2 != 0:
            offset += 1
    return members


def _extract_deb(
    archive_path: Path,
    dest: Path,
    max_bytes: int,
) -> int:
    """Extract a .deb package (ar archive containing data.tar.*)."""
    raw = archive_path.read_bytes()
    try:
        members = _parse_ar_members(raw)
    except ValueError as exc:
        raise ExtractionError(
            f"Failed to extract {archive_path.name}: {exc}"
        ) from exc

    # Find data.tar.* member
    data_tar_content = None
    for name, content in members:
        if name.startswith("data.tar"):
            data_tar_content = content
            break

    if data_tar_content is None:
        raise ExtractionError(
            f"Failed to extract {archive_path.name}: no data.tar.* member found"
        )

    # Extract the data tarball
    try:
        cumulative = 0
        with tarfile.open(fileobj=io.BytesIO(data_tar_content), mode="r:*") as tf:
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
                resolved = (dest / member.name).resolve()
                if not str(resolved).startswith(str(dest.resolve())):
                    logger.warning("Skipping path traversal attempt: %s", member.name)
                    continue
                target = dest / member.name
                target.parent.mkdir(parents=True, exist_ok=True)
                extracted = tf.extractfile(member)
                if extracted is None:
                    continue
                target.write_bytes(extracted.read())
                cumulative += member.size
        return cumulative
    except tarfile.TarError as exc:
        raise ExtractionError(
            f"Failed to extract {archive_path.name}: {exc}"
        ) from exc


def _extract_cpio_newc(data: bytes, dest: Path, max_bytes: int) -> int:
    """Extract a cpio newc (SVR4) format archive."""
    cumulative = 0
    offset = 0
    while offset + 110 <= len(data):
        magic = data[offset : offset + 6]
        if magic != b"070701":
            break
        namesize = int(data[offset + 94 : offset + 102], 16)
        filesize = int(data[offset + 54 : offset + 62], 16)

        # Header is 110 bytes, then name, padded to 4 bytes
        name_start = offset + 110
        name_end = name_start + namesize - 1  # exclude null terminator
        name = data[name_start : name_end].decode("ascii", errors="replace")

        # Data starts after header+name padded to 4-byte boundary
        header_plus_name = 110 + namesize
        data_offset = offset + header_plus_name + ((4 - (header_plus_name % 4)) % 4)

        if name == "TRAILER!!!":
            break

        if filesize > 0:
            if cumulative + filesize > max_bytes:
                raise ResourceLimitError(
                    f"Extraction aborted: would exceed {max_bytes / (1024**3):.1f}GB limit. "
                    f"Use --max-extract-size to increase."
                )
            file_path = dest / name
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_bytes(data[data_offset : data_offset + filesize])
            cumulative += filesize

        # Advance past data, padded to 4-byte boundary
        next_offset = data_offset + filesize
        offset = next_offset + ((4 - (next_offset % 4)) % 4)

    return cumulative


def _extract_rpm(
    archive_path: Path,
    dest: Path,
    max_bytes: int,
) -> int:
    """Extract an .rpm package (lead + headers + compressed cpio payload)."""
    raw = archive_path.read_bytes()

    # Validate RPM magic
    if raw[:4] != _RPM_MAGIC:
        raise ExtractionError(
            f"Failed to extract {archive_path.name}: invalid RPM magic"
        )

    # Skip the 96-byte lead
    offset = 96

    # Skip signature and main headers (each starts with 8e ad e8 01)
    for _header_name in ("signature", "main"):
        if offset + 16 > len(raw):
            raise ExtractionError(
                f"Failed to extract {archive_path.name}: truncated RPM header"
            )
        hdr_magic = raw[offset : offset + 4]
        if hdr_magic != b"\x8e\xad\xe8\x01":
            raise ExtractionError(
                f"Failed to extract {archive_path.name}: invalid RPM header magic"
            )
        nindex = struct.unpack(">I", raw[offset + 8 : offset + 12])[0]
        hsize = struct.unpack(">I", raw[offset + 12 : offset + 16])[0]
        # Header structure: 16-byte intro + nindex*16 (index entries) + hsize (store)
        offset += 16 + nindex * 16 + hsize
        # Signature header is padded to 8-byte boundary
        if _header_name == "signature":
            offset += (8 - (offset % 8)) % 8

    # Remaining data is the compressed payload (usually gzip)
    payload = raw[offset:]
    if not payload:
        raise ExtractionError(
            f"Failed to extract {archive_path.name}: no payload found"
        )

    # Decompress (try gzip first)
    try:
        cpio_data = gzip.decompress(payload)
    except (gzip.BadGzipFile, OSError) as exc:
        raise ExtractionError(
            f"Failed to extract {archive_path.name}: cannot decompress payload. {exc}"
        ) from exc

    # Parse cpio
    try:
        return _extract_cpio_newc(cpio_data, dest, max_bytes)
    except (ValueError, struct.error) as exc:
        raise ExtractionError(
            f"Failed to extract {archive_path.name}: invalid cpio payload. {exc}"
        ) from exc


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
        if _is_deb_like(package_path):
            bytes_extracted = _extract_deb(package_path, dest_dir, max_bytes)
        elif _is_rpm_like(package_path):
            bytes_extracted = _extract_rpm(package_path, dest_dir, max_bytes)
        elif _is_zip_like(package_path):
            bytes_extracted = _extract_zip(package_path, dest_dir, max_bytes)
        elif _is_tar_like(package_path):
            bytes_extracted = _extract_tar(package_path, dest_dir, max_bytes)
        else:
            raise UnsupportedFormatError(
                f"Unsupported format: {package_path.suffix}. "
                f"Supported: {', '.join(sorted(_ZIP_EXTENSIONS | _TAR_EXTENSIONS | _DEB_EXTENSIONS | _RPM_EXTENSIONS))}"
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
