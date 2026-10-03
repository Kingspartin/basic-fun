"""Typed errors shared across the enrichment layer.

Modules raise these so the dispatcher can react precisely: back off, disable the
module for the scan, or just skip one lookup — never crash the whole scan.
"""
from __future__ import annotations


class EnrichmentError(Exception):
    """Base class for all enrichment errors."""


class RateLimited(EnrichmentError):
    """Provider returned 429. ``retry_after`` is seconds if the header gave one."""

    def __init__(self, message: str = "rate limited", retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class QuotaExceeded(EnrichmentError):
    """The provider (or our own counter) says this key is out of quota.

    The dispatcher disables the module for the rest of the scan and logs it,
    rather than failing the scan.
    """


class UpstreamError(EnrichmentError):
    """A non-retryable upstream failure (4xx other than 429, or 5xx after retries)."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class ConfigurationError(EnrichmentError):
    """Module is misconfigured (e.g. missing required API key)."""


class SuppressedError(EnrichmentError):
    """Raised when a seed entity is on the suppression list; aborts the scan."""
