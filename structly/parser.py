from __future__ import annotations

from typing import Any, Iterable, Mapping, MutableMapping, Sequence, cast

from pydantic import ValidationError

from .exceptions import ConfigurationError, ParsingError, StructlyError
from .models import StructlyConfig

try:
    from ._structly import Parser as _NativeParser
except ImportError as exc:  # pragma: no cover - exercised during runtime, not tests
    _NativeParser = None  # type: ignore[assignment]
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None


def _coerce_to_structly_config(config: StructlyConfig | Mapping[str, Any]) -> StructlyConfig:
    if isinstance(config, StructlyConfig):
        return config
    if not isinstance(config, Mapping):
        raise ConfigurationError("Configuration must be a mapping or StructlyConfig instance.")

    try:
        return StructlyConfig.from_mapping(config)
    except ValidationError as first_error:
        if "fields" in config:
            raw_fields = config.get("fields")
            if not isinstance(raw_fields, Mapping):
                raise ConfigurationError("Invalid structly configuration") from first_error
            field_items = raw_fields.items()
            cfg_kwargs = {k: v for k, v in config.items() if k != "fields"}
        else:
            field_items = config.items()
            cfg_kwargs = {}

        converted_fields: dict[str, Any] = {}
        for key, value in field_items:
            if key == "version":
                cfg_kwargs["version"] = value
                continue

            if not isinstance(value, Mapping):
                raise ConfigurationError("Invalid structly configuration") from first_error

            raw_spec = dict(value)
            runtime_return = raw_spec.pop("return", None)
            if "return_shape" not in raw_spec and runtime_return is not None:
                raw_spec["return_shape"] = runtime_return

            converted_fields[key] = raw_spec

        if not converted_fields:
            raise ConfigurationError("Invalid structly configuration") from first_error

        merged = {"fields": converted_fields, **cfg_kwargs}
        try:
            return StructlyConfig.from_mapping(merged)
        except ValidationError as exc:
            raise ConfigurationError("Invalid structly configuration") from exc


class StructlyParser:
    """Validates configuration, compiles the native parser, and exposes a Pythonic API."""

    __slots__ = ("config", "_runtime_config", "_native")

    def __init__(self, config: StructlyConfig | Mapping[str, Any]):
        if _NativeParser is None:  # pragma: no cover - exercised only when build is missing
            message = (
                "structly native extension is not available. "
                "Run `make install-rust` (or `maturin develop --release`) before using StructlyParser."
            )
            raise StructlyError(message) from _IMPORT_ERROR

        validated = _coerce_to_structly_config(config)

        runtime_config = validated.to_runtime_dict()

        try:
            native = _NativeParser(runtime_config)
        except ValueError as exc:
            raise ConfigurationError(str(exc)) from exc

        self.config = validated
        self._runtime_config = runtime_config
        self._native = native

    @property
    def runtime_config(self) -> Mapping[str, Any]:
        """Return the runtime configuration passed to the native parser."""
        return self._runtime_config

    @property
    def field_names(self) -> tuple[str, ...]:
        """Ordered tuple of field names as compiled by the parser."""
        names = self._native.field_names()
        if isinstance(names, tuple):
            return cast(tuple[str, ...], names)
        return tuple(str(name) for name in names)

    def parse(self, text: str) -> MutableMapping[str, Any]:
        """Parse a single document."""
        try:
            result = self._native.parse(text)
        except Exception as exc:  # pragma: no cover - defensive
            raise ParsingError(f"Failed to parse document: {exc}") from exc
        if not isinstance(result, MutableMapping):
            result = cast(MutableMapping[str, Any], dict(result))
        return result

    def parse_many(self, texts: Sequence[str] | Iterable[str]) -> list[MutableMapping[str, Any]]:
        """Parse multiple documents in a single call."""
        text_list = list(texts)
        if not all(isinstance(t, str) for t in text_list):
            raise TypeError("All inputs to parse_many must be strings.")
        try:
            results = self._native.parse_many(text_list)
        except Exception as exc:  # pragma: no cover - defensive
            raise ParsingError(f"Failed to parse documents: {exc}") from exc
        return [cast(MutableMapping[str, Any], r) for r in results]

    def parse_tuple(self, text: str) -> tuple[Any, ...]:
        """Parse a single document and return values as an ordered tuple."""
        try:
            result = self._native.parse_tuple(text)
        except Exception as exc:  # pragma: no cover - defensive
            raise ParsingError(f"Failed to parse document: {exc}") from exc
        if isinstance(result, tuple):
            return result
        return tuple(result)

    def iter_field_items(self, text: str) -> tuple[str, ...]:
        """Return an ordered tuple of ``(field_name, value)`` pairs."""
        parsed = self.parse(text)
        return tuple(parsed.items())


def prepare_parser(config: StructlyConfig | Mapping[str, Any]) -> StructlyParser:
    """Compile and return a :class:`StructlyParser`."""
    return StructlyParser(config)


def parse_text(text: str, config: StructlyConfig | Mapping[str, Any]) -> MutableMapping[str, Any]:
    """One-shot helper that compiles the config and parses a single document."""
    return prepare_parser(config).parse(text)


def parse_tuple(text: str, config: StructlyConfig | Mapping[str, Any]) -> tuple[Any, ...]:
    """One-shot helper returning just the field values as a tuple."""
    return prepare_parser(config).parse_tuple(text)


def iter_field_items(text: str, config: StructlyConfig | Mapping[str, Any]) -> tuple[tuple[str, Any], ...]:
    """One-shot helper returning ordered ``(field, value)`` tuples."""
    return prepare_parser(config).iter_field_items(text)
