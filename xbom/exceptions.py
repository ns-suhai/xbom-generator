"""Custom exceptions for the xBOM generator."""


class XBomError(Exception):
    """Base exception for all xBOM errors."""


class UnsupportedFormatError(XBomError):
    """Raised when the package format is not supported."""


class ExtractionError(XBomError):
    """Raised when archive extraction fails."""


class ResourceLimitError(XBomError):
    """Raised when extraction exceeds size limits (zip bomb protection)."""


class DependencyMissingError(XBomError):
    """Raised when a required external tool is not installed."""


class EnrichmentError(XBomError):
    """Raised when Netskope telemetry enrichment fails."""


class AssemblyError(XBomError):
    """Raised when CycloneDX assembly fails."""
