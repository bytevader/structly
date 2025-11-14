from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from pydantic import BaseModel, ConfigDict, Field

from structly.models.field_spec import FieldSpec


class StructlyConfig(BaseModel):
    fields: Dict[str, FieldSpec] = Field(default_factory=dict)
    version: Optional[str] = None

    model_config = ConfigDict(extra="forbid", frozen=True)

    @classmethod
    def from_mapping(cls, m: Mapping[str, Any]) -> StructlyConfig:
        """
        Accepts either:
          - {"fields": {name: {patterns:[...], ...}, ...}, "version": "..."}
          - {name: {patterns:[...], ...}, ...} (shorthand)
        """
        if "fields" in m:
            return cls.model_validate(m)
        return cls(fields={k: FieldSpec.model_validate(v) for k, v in m.items()})

    def to_runtime_dict(self) -> Dict[str, Any]:
        return {name: spec.to_runtime_object() for name, spec in self.fields.items()}
