import pytest
from pydantic import ValidationError

from structly import FieldPattern, FieldSpec, Mode, ReturnShape, StructlyConfig


def test_field_pattern_builders():
    sw = FieldPattern.starts_with("Domain:")
    regex = FieldPattern.regex(r"^domain\s+")

    assert sw.runtime_value() == "sw:Domain:"
    assert regex.runtime_value() == "r:^domain\\s+"


def test_field_pattern_strips_duplicate_prefix():
    regex = FieldPattern.regex("r:^domain\\s+")
    starts_with = FieldPattern.starts_with("sw:Registrar:")

    assert regex.runtime_value() == "r:^domain\\s+"
    assert starts_with.runtime_value() == "sw:Registrar:"


def test_field_pattern_rejects_multiline_starts_with():
    with pytest.raises(ValidationError) as excinfo:
        FieldPattern.starts_with("Multi\nLine")
    assert "single-line" in str(excinfo.value)


def test_field_spec_to_runtime_object_scalar_mode_first():
    spec = FieldSpec(
        patterns=[
            FieldPattern.starts_with("Domain:"),
            FieldPattern.regex(r"^domain\s+"),
        ],
        mode=Mode.first,
        unique=False,
        return_shape=ReturnShape.scalar,
    )

    runtime_obj = spec.to_runtime_object()

    assert runtime_obj == {
        "patterns": ["sw:Domain:", "r:^domain\\s+"],
        "mode": "first",
        "unique": False,
        "return": "scalar",
    }


def test_field_spec_to_runtime_object_list_mode_all():
    spec = FieldSpec(
        patterns=[
            FieldPattern.starts_with("Name Server:"),
            FieldPattern.regex(r"^ns\d+\."),
        ],
        mode=Mode.all,
        unique=True,
        return_shape=ReturnShape.list_,
    )

    runtime_obj = spec.to_runtime_object()
    assert runtime_obj == {
        "patterns": ["sw:Name Server:", "r:^ns\\d+\\."],
        "mode": "all",
        "unique": True,
        "return": "list",
    }


def test_field_spec_rejects_empty_patterns():
    with pytest.raises(ValidationError) as excinfo:
        FieldSpec(patterns=[])
    assert "At least one pattern is required" in str(excinfo.value)


def test_field_spec_rejects_unknown_prefix():
    with pytest.raises(ValidationError) as excinfo:
        FieldSpec(patterns=["contains:registrar"])

    message = str(excinfo.value)
    assert "must start with 'sw:' or 'r:'" in message


def test_field_spec_rejects_invalid_regex():
    bad_regex = "r:(?!["  # missing closing bracket

    with pytest.raises(ValidationError) as excinfo:
        FieldSpec(patterns=[bad_regex])

    assert "Invalid regex" in str(excinfo.value)


def test_structly_config_from_mapping_explicit():
    cfg = StructlyConfig.from_mapping(
        {
            "fields": {
                "domain": {"patterns": ["sw:Domain:"], "mode": "first"},
            },
            "version": "2024-04-01",
        }
    )

    assert list(cfg.fields.keys()) == ["domain"]
    assert cfg.version == "2024-04-01"
    assert len(cfg.fields["domain"].patterns) == 1
    assert cfg.fields["domain"].patterns[0].runtime_value() == "sw:Domain:"


def test_structly_config_from_mapping_shorthand():
    cfg = StructlyConfig.from_mapping(
        {
            "domain": {"patterns": ["sw:Domain:"]},
            "created": {"patterns": ["sw:Creation Date:"]},
        }
    )

    assert sorted(cfg.fields.keys()) == ["created", "domain"]
    assert cfg.fields["created"].mode == Mode.first


def test_structly_config_to_runtime_dict():
    cfg = StructlyConfig.from_mapping(
        {
            "fields": {
                "domain": {"patterns": ["sw:Domain:"]},
                "nameservers": {
                    "patterns": ["sw:Name Server:"],
                    "mode": "all",
                    "unique": True,
                    "return_shape": "list",
                },
            }
        }
    )

    runtime_cfg = cfg.to_runtime_dict()

    assert runtime_cfg == {
        "domain": {
            "patterns": ["sw:Domain:"],
            "mode": "first",
            "unique": False,
            "return": "scalar",
        },
        "nameservers": {
            "patterns": ["sw:Name Server:"],
            "mode": "all",
            "unique": True,
            "return": "list",
        },
    }


def test_structly_config_is_immutable():
    cfg = StructlyConfig.from_mapping({"domain": {"patterns": ["sw:Domain:"]}})

    with pytest.raises(ValidationError):
        cfg.fields = {}


def test_structly_config_forbids_extra_fields():
    with pytest.raises(ValidationError):
        StructlyConfig.model_validate({"fields": {}, "version": "v1", "unsupported": True})


def test_field_spec_coerce_string_patterns_noop():
    assert FieldSpec._coerce_string_patterns(None) is None
