from __future__ import annotations

import os
from typing import Any, Dict, Iterable, Iterator, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union, cast

from pydantic import ValidationError

from ._structly import Parser as _NativeParser
from .exceptions import ConfigurationError, ParsingError
from .models import StructlyConfig

_VALID_RAYON_POLICIES = {"never", "always", "auto"}


def _apply_rayon_policy(policy: Optional[str]) -> str:
    if policy is None:
        return os.environ.setdefault("STRUCTLY_RAYON", "never")

    normalized = policy.lower()
    if normalized not in _VALID_RAYON_POLICIES:
        raise ValueError(f"Invalid rayon_policy '{policy}'. Expected one of {_VALID_RAYON_POLICIES}.")
    os.environ["STRUCTLY_RAYON"] = normalized
    return normalized


def _coerce_to_structly_config(config: Union[StructlyConfig, Mapping[str, Any]]) -> StructlyConfig:
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

        converted_fields: Dict[str, Any] = {}
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
    """Validates configuration, compiles the native parser, and exposes a Pythonic API.

    Parameters
    ----------
    config:
        Structly configuration or runtime mapping to compile.
    field_layout:
        One of ``"line"`` (default) or ``"inline"``, controlling how field
        values are harvested.
    inline_value_delimiters:
        Optional delimiter set for inline extraction.
    rayon_policy:
        Controls the ``STRUCTLY_RAYON`` environment variable prior to native
        parser initialisation. The default ``None`` sets the variable to
        ``"never"`` if it is unset. Pass ``"always"`` (recommended on multi-CPU
        hosts) or ``"auto"`` to opt into the corresponding Rayon behaviour.
    """

    __slots__ = ("config", "_runtime_config", "_native")

    def __init__(
        self,
        config: Union[StructlyConfig, Mapping[str, Any]],
        *,
        field_layout: str = "line",
        inline_value_delimiters: Optional[str] = None,
        rayon_policy: Optional[str] = "never",
    ):
        _apply_rayon_policy(rayon_policy)
        validated = _coerce_to_structly_config(config)
        runtime_config = validated.to_runtime_dict()

        try:
            native = _NativeParser(
                runtime_config,
                field_layout=field_layout,
                inline_value_delimiters=inline_value_delimiters,
            )
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
    def field_names(self) -> Tuple[str, ...]:
        """Ordered tuple of field names as compiled by the parser."""
        names = self._native.field_names()
        if isinstance(names, Tuple):
            return cast(Tuple[str, ...], names)
        return tuple(str(name) for name in names)

    def parse(self, text: str) -> MutableMapping[str, Any]:
        """Parse a single document."""
        try:
            result = self._native.parse(text)
        except Exception as exc:
            raise ParsingError(f"Failed to parse document: {exc}") from exc
        if not isinstance(result, MutableMapping):
            result = cast(MutableMapping[str, Any], dict(result))
        return result

    def parse_many(self, texts: Union[Sequence[str], Iterable[str]]) -> List[MutableMapping[str, Any]]:
        """Parse multiple documents in a single call."""
        text_list = list(texts)
        if not all(isinstance(t, str) for t in text_list):
            raise TypeError("All inputs to parse_many must be strings.")
        try:
            results = self._native.parse_many(text_list)
        except Exception as exc:
            raise ParsingError(f"Failed to parse documents: {exc}") from exc
        return [cast(MutableMapping[str, Any], r) for r in results]

    def parse_iter(
        self,
        texts: Iterable[str],
        *,
        chunk_size: int = 1,
    ) -> Iterator[MutableMapping[str, Any]]:
        """Yield parsed documents lazily.

        Parameters
        ----------
        texts:
            Iterable of input strings.
        chunk_size:
            Number of documents to process per native batch. ``1`` (default)
            yields one document at a time; larger values trade latency for
            throughput by yielding after each chunk.
        """
        if chunk_size <= 0:
            raise ValueError("chunk_size must be a positive integer")

        buffer: List[str] = []
        for text in texts:
            if not isinstance(text, str):
                raise TypeError("All inputs to parse_iter must be strings.")
            buffer.append(text)
            if len(buffer) >= chunk_size:
                yield from self._parse_chunk(buffer)
                buffer.clear()

        if buffer:
            yield from self._parse_chunk(buffer)

    def parse_chunks(
        self,
        texts: Iterable[str],
        *,
        chunk_size: int = 512,
    ) -> Iterator[List[MutableMapping[str, Any]]]:
        """Yield lists of parsed documents using `chunk_size` per batch."""
        if chunk_size <= 0:
            raise ValueError("chunk_size must be a positive integer")

        buffer: List[str] = []
        for text in texts:
            if not isinstance(text, str):
                raise TypeError("All inputs to parse_chunks must be strings.")
            buffer.append(text)
            if len(buffer) >= chunk_size:
                yield self._parse_chunk(buffer)
                buffer = []

        if buffer:
            yield self._parse_chunk(buffer)

    def _parse_chunk(self, texts: list[str]) -> List[MutableMapping[str, Any]]:
        try:
            results = self._native.parse_many(texts)
        except Exception as exc:
            raise ParsingError(f"Failed to parse documents: {exc}") from exc
        return [cast(MutableMapping[str, Any], r) for r in results]

    def parse_tuple(self, text: str) -> Tuple[Any, ...]:
        """Parse a single document and return values as an ordered tuple."""
        try:
            result = self._native.parse_tuple(text)
        except Exception as exc:
            raise ParsingError(f"Failed to parse document: {exc}") from exc
        if isinstance(result, Tuple):
            return result
        return tuple(result)

    def iter_field_items(self, text: str) -> Tuple[str, ...]:
        """Return an ordered tuple of ``(field_name, value)`` pairs."""
        parsed = self.parse(text)
        return tuple(parsed.items())


def prepare_parser(
    config: Union[StructlyConfig, Mapping[str, Any]],
    *,
    field_layout: str = "line",
    inline_value_delimiters: Optional[str] = None,
    rayon_policy: Optional[str] = None,
) -> StructlyParser:
    """Compile and return a :class:`StructlyParser`.

    See :class:`StructlyParser` for parameter details, including ``rayon_policy``.
    """
    return StructlyParser(
        config,
        field_layout=field_layout,
        inline_value_delimiters=inline_value_delimiters,
        rayon_policy=rayon_policy,
    )


def parse_text(
    text: str,
    config: Union[StructlyConfig, Mapping[str, Any]],
    *,
    field_layout: str = "line",
    inline_value_delimiters: Optional[str] = None,
    rayon_policy: Optional[str] = None,
) -> MutableMapping[str, Any]:
    """One-shot helper that compiles the config and parses a single document."""
    return prepare_parser(
        config,
        field_layout=field_layout,
        inline_value_delimiters=inline_value_delimiters,
        rayon_policy=rayon_policy,
    ).parse(text)


def parse_tuple(
    text: str,
    config: Union[StructlyConfig, Mapping[str, Any]],
    *,
    field_layout: str = "line",
    inline_value_delimiters: Optional[str] = None,
    rayon_policy: Optional[str] = None,
) -> Tuple[Any, ...]:
    """One-shot helper returning just the field values as a tuple."""
    return prepare_parser(
        config,
        field_layout=field_layout,
        inline_value_delimiters=inline_value_delimiters,
        rayon_policy=rayon_policy,
    ).parse_tuple(text)


def iter_field_items(
    text: str,
    config: Union[StructlyConfig, Mapping[str, Any]],
    *,
    field_layout: str = "line",
    inline_value_delimiters: Optional[str] = None,
    rayon_policy: Optional[str] = None,
) -> Tuple[str, ...]:
    """One-shot helper returning ordered ``(field, value)`` tuples."""
    return prepare_parser(
        config,
        field_layout=field_layout,
        inline_value_delimiters=inline_value_delimiters,
        rayon_policy=rayon_policy,
    ).iter_field_items(text)
