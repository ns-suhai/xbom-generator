"""CBOM analyzer - detect crypto libraries, algorithms, and certificates."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from xbom.analyzers.base import BaseAnalyzer
from xbom.models.bom_types import BomEntry, BomType, ComponentType

logger = logging.getLogger(__name__)

# Crypto algorithm patterns and their quantum security levels
# Level: NIST post-quantum security levels (0 = broken/weak, 1-5 = quantum safe)
_CRYPTO_PATTERNS: list[tuple[str, str, int]] = [
    # Weak / broken
    (r'\bmd5\b', "MD5", 0),
    (r'\bsha-?1\b', "SHA-1", 0),
    (r'\bdes\b(?!ign|cri|troy)', "DES", 0),
    (r'\brc4\b', "RC4", 0),
    (r'\brsa[_\-]?1024\b', "RSA-1024", 0),
    # Acceptable current
    (r'\bsha-?256\b', "SHA-256", 0),
    (r'\bsha-?384\b', "SHA-384", 0),
    (r'\bsha-?512\b', "SHA-512", 0),
    (r'\baes[_\-]?128\b', "AES-128", 0),
    (r'\baes[_\-]?256\b', "AES-256", 0),
    (r'\brsa[_\-]?2048\b', "RSA-2048", 0),
    (r'\brsa[_\-]?4096\b', "RSA-4096", 0),
    (r'\becdsa\b', "ECDSA", 0),
    (r'\bed25519\b', "Ed25519", 0),
    (r'\bchacha20\b', "ChaCha20", 0),
    # Post-quantum
    (r'\bkyber\b', "CRYSTALS-Kyber", 3),
    (r'\bdilithium\b', "CRYSTALS-Dilithium", 3),
    (r'\bfalcon\b', "FALCON", 1),
    (r'\bsphincsx?\+?\b', "SPHINCS+", 1),
]

# Crypto library imports
_CRYPTO_LIBS = [
    (r'(?:from\s+|import\s+)(?:cryptography|Crypto|hashlib|ssl|OpenSSL)', "Python crypto"),
    (r'(?:require|import)\s+[\'"](?:crypto|tls|node-forge)[\'"]', "Node.js crypto"),
    (r'javax\.crypto|java\.security|BouncyCastle', "Java crypto"),
    (r'openssl|libssl|libcrypto|libsodium|mbedtls', "Native crypto"),
]

# Certificate patterns
_CERT_PATTERN = re.compile(
    r'-----BEGIN\s+(CERTIFICATE|RSA PRIVATE KEY|EC PRIVATE KEY|PRIVATE KEY|PUBLIC KEY)-----'
)


class CbomAnalyzer(BaseAnalyzer):
    """Detect cryptographic algorithms, libraries, and certificates."""

    @property
    def name(self) -> str:
        return "cbom"

    def analyze(
        self,
        extracted_dir: Path,
        classified_files: dict[str, list[Path]],
    ) -> list[BomEntry]:
        entries: list[BomEntry] = []
        seen_algorithms: set[str] = set()

        # Scan scripts, configs, and certificate files
        scannable = (
            classified_files.get("scripts", [])
            + classified_files.get("configs", [])
            + classified_files.get("certificates", [])
            + classified_files.get("data", [])
        )

        for file_path in scannable:
            try:
                content = file_path.read_text(errors="ignore").lower()
            except (OSError, UnicodeDecodeError):
                continue

            # Detect algorithms
            for pattern, algo_name, quantum_level in _CRYPTO_PATTERNS:
                if algo_name in seen_algorithms:
                    continue
                if re.search(pattern, content, re.IGNORECASE):
                    seen_algorithms.add(algo_name)
                    strength = "weak" if quantum_level == 0 and algo_name in {"MD5", "SHA-1", "DES", "RC4", "RSA-1024"} else "acceptable"
                    entries.append(BomEntry(
                        bom_type=BomType.CBOM,
                        component_type=ComponentType.CRYPTO_ASSET,
                        name=algo_name,
                        version=None,
                        metadata={
                            "algorithm": algo_name,
                            "quantum_level": quantum_level,
                            "strength": strength,
                            "source_file": str(file_path.relative_to(extracted_dir)),
                        },
                    ))

            # Detect certificates (read original case content)
            try:
                raw = file_path.read_text(errors="ignore")
            except (OSError, UnicodeDecodeError):
                raw = ""
            for match in _CERT_PATTERN.finditer(raw):
                cert_type = match.group(1)
                cert_name = f"{cert_type} in {file_path.name}"
                if cert_name not in seen_algorithms:
                    seen_algorithms.add(cert_name)
                    entries.append(BomEntry(
                        bom_type=BomType.CBOM,
                        component_type=ComponentType.CRYPTO_ASSET,
                        name=cert_name,
                        version=None,
                        metadata={
                            "type": "certificate" if "CERTIFICATE" in cert_type else "key",
                            "source_file": str(file_path.relative_to(extracted_dir)),
                        },
                    ))

        logger.info("CBOM: found %d crypto assets", len(entries))
        return entries
