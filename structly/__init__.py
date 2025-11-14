from __future__ import annotations

from .exceptions import ConfigurationError, ParsingError, StructlyError
from .models import FieldPattern, FieldPatternType, FieldSpec, Mode, ReturnShape, StructlyConfig
from .parser import StructlyParser
from .parser import iter_field_items as _iter_field_items
from .parser import parse_text as _parse_text
from .parser import parse_tuple as _parse_tuple
from .parser import prepare_parser

prepare = prepare_parser
parse = _parse_text
parse_tuple = _parse_tuple
iter_field_items = _iter_field_items

__all__ = [
    # Exceptions
    "StructlyError",
    "ConfigurationError",
    "ParsingError",
    # Configuration models
    "StructlyConfig",
    "FieldSpec",
    "FieldPattern",
    "FieldPatternType",
    "Mode",
    "ReturnShape",
    # Parser API
    "StructlyParser",
    "prepare",
    "parse",
    "parse_tuple",
    "iter_field_items",
]
