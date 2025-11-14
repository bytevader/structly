from __future__ import annotations

import re
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Tuple, Union

from pydantic import BaseModel, ConfigDict, Field, model_validator


class FieldPatternType(str, Enum):
    """Canonical prefix expected by the Rust core"""

    STARTS_WITH = "sw:"
    REGEX = "r:"


class Mode(str, Enum):
    first = "first"
    all = "all"


class ReturnShape(str, Enum):
    scalar = "scalar"
    list_ = "list"


def _split_prefix(s: str) -> Tuple[Optional[FieldPatternType], str]:
    """
    If a string starts with 'sw:' or 'r:', return (prefix_enum, body).
    Otherwise, return (None, s).
    """
    if s.startswith("sw:"):
        return FieldPatternType.STARTS_WITH, s[3:]
    if s.startswith("r:"):
        return FieldPatternType.REGEX, s[2:]
    return None, s


def _strip_known_prefixes(body: str) -> str:
    """If the body itself contains an accidental 'sw:' or 'r:' prefix, strip it."""
    if body.startswith("sw:") or body.startswith("r:"):
        return body.split(":", 1)[1]
    return body


class FieldPattern(BaseModel):
    pattern_type: FieldPatternType
    pattern: str

    model_config = ConfigDict(extra="forbid", frozen=True)

    @classmethod
    def starts_with(cls, literal: str) -> FieldPattern:
        """Create a starts-with pattern."""
        return cls(pattern_type=FieldPatternType.STARTS_WITH, pattern=literal)

    @classmethod
    def regex(cls, pattern: str) -> FieldPattern:
        """Create a regular-expression pattern."""
        return cls(pattern_type=FieldPatternType.REGEX, pattern=pattern)

    @model_validator(mode="after")
    def _validate_and_compile(self) -> FieldPattern:
        body = _strip_known_prefixes(self.pattern)
        if self.pattern_type == FieldPatternType.REGEX:
            try:
                re.compile(body)
            except re.error as e:
                raise ValueError(f"Invalid regex '{body}': {e}") from e
        if self.pattern_type == FieldPatternType.STARTS_WITH and ("\n" in body or "\r" in body):
            raise ValueError("starts-with patterns must be single-line (no CR/LF).")
        return self

    def runtime_value(self) -> str:
        """Return canonical 'sw:...' or 'r:...' string for the Rust core."""
        body = _strip_known_prefixes(self.pattern)
        return f"{self.pattern_type.value}{body}"

    # Back-compat alias
    compiled = runtime_value


class FieldSpec(BaseModel):
    """
    Specification for a single extracted field (e.g., 'domain', 'created date').
    """

    patterns: Union[List[FieldPattern], List[str]] = Field(
        description="Ordered list of markers. 'sw:' for starts-with literal prefix, 'r:' for regex prefix."
    )
    mode: Mode = Field(default=Mode.first, description="first=stop at first match; all=collect all")
    unique: bool = Field(default=False, description="If true, deduplicate while preserving order")
    return_shape: ReturnShape = Field(
        default=ReturnShape.scalar,
        description="Return shape for this field (scalar|list)",
    )

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="before")
    @classmethod
    def _coerce_string_patterns(cls, data: Any) -> Any:
        """
        Accept both:
          - structured patterns=[FieldPattern(...), ...]
          - string shorthand patterns=["sw:Label:", "r:^Label:\\s*", ...]
        """
        if not isinstance(data, dict) or "patterns" not in data:
            return data
        pats = data["patterns"]
        if pats and isinstance(pats, list) and isinstance(pats[0], str):
            converted: List[Dict[str, Any]] = []
            for s in pats:
                pt, body = _split_prefix(s)
                if pt is None:
                    raise ValueError(
                        f"Pattern '{s}' must start with '{FieldPatternType.STARTS_WITH.value}' "
                        f"or '{FieldPatternType.REGEX.value}'"
                    )
                converted.append({"pattern_type": pt, "pattern": body})
            data = {**data, "patterns": converted}
        return data

    @model_validator(mode="after")
    def _ensure_patterns(self) -> FieldSpec:
        if not self.patterns:
            raise ValueError("At least one pattern is required")
        return self

    def to_runtime_object(self) -> Mapping[str, Any]:
        """
        Convert to the dict shape expected by the Rust core:
        {
          "patterns": ["sw:...", "r:..."],
          "mode": "all" | "first",
          "unique": bool,
          "return": "list" | "scalar"
        }
        """
        return {
            "patterns": [fp.runtime_value() for fp in self.patterns],
            "mode": self.mode.value,
            "unique": self.unique,
            "return": "list" if self.return_shape == ReturnShape.list_ else "scalar",
        }
