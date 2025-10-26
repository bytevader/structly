from __future__ import annotations


class StructlyError(Exception):
    """Base class for all structly-specific exceptions."""


class ConfigurationError(StructlyError):
    """Raised when a parser configuration is invalid or cannot be compiled."""


class ParsingError(StructlyError):
    """Raised when parsing fails due to invalid input or runtime issues."""
