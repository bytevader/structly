import os

import pytest

import structly.parser as parser_module
from structly import (
    ConfigurationError,
    FieldPattern,
    FieldSpec,
    Mode,
    ReturnShape,
    StructlyConfig,
    StructlyParser,
    iter_field_items,
    parse,
    parse_tuple,
    prepare,
)
from structly.parser import _coerce_to_structly_config


@pytest.fixture
def sample_config() -> StructlyConfig:
    return StructlyConfig(
        fields={
            "domain": FieldSpec(
                patterns=[FieldPattern.starts_with("Domain:")],
            ),
            "nameservers": FieldSpec(
                patterns=[FieldPattern.starts_with("Name Server:")],
                mode=Mode.all,
                unique=True,
                return_shape=ReturnShape.list_,
            ),
        }
    )


@pytest.fixture
def parser(sample_config: StructlyConfig) -> StructlyParser:
    return StructlyParser(sample_config)


def test_structly_parser_parse(parser: StructlyParser):
    text = "Domain: example.com\nName Server: ns1.example\nName Server: ns2.example\n"

    result = parser.parse(text)

    assert result["domain"] == "example.com"
    assert result["nameservers"] == ["ns1.example", "ns2.example"]
    assert parser.field_names == ("domain", "nameservers")


def test_structly_parser_parse_many(parser: StructlyParser):
    texts = [
        "Domain: example.com\nName Server: ns1.example\n",
        "Domain: example.org\nName Server: ns.a\nName Server: ns.b\n",
    ]

    results = parser.parse_many(texts)

    assert [r["domain"] for r in results] == ["example.com", "example.org"]
    assert results[1]["nameservers"] == ["ns.a", "ns.b"]


def test_structly_parser_iter_field_items(parser: StructlyParser):
    text = "Domain: example.com\nName Server: ns1.example\n"
    items = parser.iter_field_items(text)

    assert items == (("domain", "example.com"), ("nameservers", ["ns1.example"]))


def test_prepare_and_parse_helpers(sample_config: StructlyConfig):
    runtime = sample_config.to_runtime_dict()
    parser = prepare(runtime)
    text = "Domain: example.net\n"
    result = parse(text, runtime)
    tuple_result = parse_tuple(text, runtime)
    items = iter_field_items(text, runtime)

    assert parser.field_names == ("domain", "nameservers")
    assert result["domain"] == "example.net"
    assert tuple_result[0] == "example.net"
    assert items[0] == ("domain", "example.net")


def test_structly_parser_parse_tuple(parser: StructlyParser):
    text = "Domain: example.com\nName Server: ns1.example\n"
    values = parser.parse_tuple(text)

    assert values[0] == "example.com"
    assert values[1] == ["ns1.example"]


def test_structly_parser_runtime_config_property(parser: StructlyParser, sample_config: StructlyConfig):
    assert parser.runtime_config == sample_config.to_runtime_dict()


def test_structly_parser_parse_many_type_error(parser: StructlyParser):
    with pytest.raises(TypeError):
        parser.parse_many(["Domain: ok", 123])  # type: ignore[list-item]


def test_structly_parser_handles_non_native_outputs(monkeypatch, sample_config: StructlyConfig):
    class StubNative:
        def __init__(self, config, **_: object):
            self.config = config

        def field_names(self):
            return ["domain"]

        def parse(self, text):
            return [("domain", "value")]

        def parse_many(self, texts):
            return [{"domain": f"value-{i}"} for i, _ in enumerate(texts)]

        def parse_tuple(self, text):
            return ["value"]

    monkeypatch.setattr(parser_module, "_NativeParser", StubNative)
    parser = StructlyParser(sample_config)

    assert parser.field_names == ("domain",)
    assert parser.parse("anything") == {"domain": "value"}
    assert parser.parse_tuple("anything") == ("value",)


def test_structly_parser_wraps_parse_errors(monkeypatch, sample_config: StructlyConfig):
    class FailingNative:
        def __init__(self, *args, **kwargs):
            pass

        def parse(self, text):
            raise RuntimeError("boom")

        def parse_many(self, texts):
            raise RuntimeError("boom many")

        def parse_tuple(self, text):
            raise RuntimeError("boom tuple")

    monkeypatch.setattr(parser_module, "_NativeParser", lambda *args, **kwargs: FailingNative())
    parser = StructlyParser(sample_config)

    with pytest.raises(parser_module.ParsingError):
        parser.parse("text")

    with pytest.raises(parser_module.ParsingError):
        parser.parse_many(["text"])

    with pytest.raises(parser_module.ParsingError):
        parser._parse_chunk(["text"])

    with pytest.raises(parser_module.ParsingError):
        parser.parse_tuple("text")


def test_structly_parser_wraps_native_value_error(monkeypatch, sample_config: StructlyConfig):
    class FailingNative:
        def __init__(self, config, **_: object):
            raise ValueError("native failure")

    monkeypatch.setattr(parser_module, "_NativeParser", FailingNative)

    with pytest.raises(ConfigurationError) as excinfo:
        StructlyParser(sample_config)

    assert "native failure" in str(excinfo.value)


def test_coerce_to_structly_config_requires_mapping():
    with pytest.raises(ConfigurationError):
        _coerce_to_structly_config(["not", "a", "mapping"])  # type: ignore[arg-type]


def test_coerce_to_structly_config_rejects_non_mapping_fields():
    with pytest.raises(ConfigurationError):
        _coerce_to_structly_config({"fields": "invalid"})  # type: ignore[arg-type]


def test_coerce_to_structly_config_handles_runtime_dict_with_version():
    runtime = {
        "domain": {
            "patterns": ["sw:Domain:"],
            "mode": "first",
            "unique": False,
            "return": "scalar",
        },
        "version": "2024-04-01",
    }

    result = _coerce_to_structly_config(runtime)

    assert result.version == "2024-04-01"
    assert result.fields["domain"].return_shape == ReturnShape.scalar


def test_coerce_to_structly_config_rejects_non_mapping_field_spec():
    with pytest.raises(ConfigurationError):
        _coerce_to_structly_config({"domain": "scalar"})  # type: ignore[arg-type]


def test_coerce_to_structly_config_requires_fields():
    with pytest.raises(ConfigurationError):
        _coerce_to_structly_config({"version": "2024-04-01"})


def test_structly_parser_rejects_invalid_config():
    with pytest.raises(ConfigurationError):
        StructlyParser({"fields": {"domain": {"patterns": []}}})


def test_structly_parser_sets_default_rayon_policy(monkeypatch, sample_config: StructlyConfig):
    monkeypatch.delenv("STRUCTLY_RAYON", raising=False)
    StructlyParser(sample_config)
    assert os.environ["STRUCTLY_RAYON"] == "never"


def test_structly_parser_allows_overriding_rayon_policy(monkeypatch, sample_config: StructlyConfig):
    monkeypatch.delenv("STRUCTLY_RAYON", raising=False)
    StructlyParser(sample_config, rayon_policy="always")
    assert os.environ["STRUCTLY_RAYON"] == "always"
    monkeypatch.setenv("STRUCTLY_RAYON", "never")


def test_structly_parser_rejects_invalid_rayon_policy(sample_config: StructlyConfig):
    with pytest.raises(ValueError):
        StructlyParser(sample_config, rayon_policy="sometimes")


def test_structly_parser_parse_iter(parser: StructlyParser):
    texts = [
        "Domain: example.com\nName Server: ns1.example\n",
        "Domain: example.org\nName Server: ns.a\nName Server: ns.b\n",
        "Domain: example.net\nName Server: ns.x\n",
    ]
    results = list(parser.parse_iter(texts, chunk_size=2))
    assert [r["domain"] for r in results] == ["example.com", "example.org", "example.net"]
    assert results[1]["nameservers"] == ["ns.a", "ns.b"]


def test_structly_parser_parse_chunks(parser: StructlyParser):
    texts = [
        "Domain: example.com\n",
        "Domain: example.org\n",
        "Domain: example.net\n",
    ]
    chunks = list(parser.parse_chunks(texts, chunk_size=2))
    assert len(chunks) == 2
    assert [r["domain"] for r in chunks[0]] == ["example.com", "example.org"]
    assert [r["domain"] for r in chunks[1]] == ["example.net"]


def test_structly_parser_parse_iter_validates_chunk_size(parser: StructlyParser):
    with pytest.raises(ValueError):
        list(parser.parse_iter(["Domain: example.com"], chunk_size=0))


def test_structly_parser_parse_iter_rejects_non_strings(parser: StructlyParser):
    with pytest.raises(TypeError):
        list(parser.parse_iter(["ok", 123]))  # type: ignore[list-item]


def test_structly_parser_parse_chunks_rejects_chunk_size(parser: StructlyParser):
    with pytest.raises(ValueError):
        list(parser.parse_chunks(["Domain: example.com"], chunk_size=0))


def test_structly_parser_parse_chunks_rejects_non_strings(parser: StructlyParser):
    with pytest.raises(TypeError):
        list(parser.parse_chunks(["ok", 123]))  # type: ignore[list-item]
