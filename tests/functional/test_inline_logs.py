from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import pytest

from structly.parser import StructlyParser

FIXTURES = {
    "dns": {
        "path": "tests/data/dns.log",
        "fields": ["client", "query", "type", "response", "rcode"],
    },
    "dhcp": {
        "path": "tests/data/dhcp.log",
        "fields": ["action", "mac", "ip", "lease", "result"],
    },
    "ipam": {
        "path": "tests/data/ipam.log",
        "fields": ["asset_id", "ip", "vlan", "owner", "status"],
    },
    "firewall": {
        "path": "tests/data/firewall.log",
        "fields": ["fw", "src", "dst", "sport", "dport", "proto", "action", "bytes"],
    },
    "router": {
        "path": "tests/data/router.log",
        "fields": ["device", "iface", "status", "flaps", "errors"],
    },
}


def _baseline_parse(line: str, keys: List[str]) -> Dict[str, str | None]:
    tokens = line.strip().split()
    out = {key: None for key in keys}
    for token in tokens:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if key in out and out[key] is None:
            out[key] = value
    return out


@pytest.mark.parametrize("fixture", sorted(FIXTURES))
def test_inline_layout_matches_python_baseline(fixture: str) -> None:
    spec = FIXTURES[fixture]
    path = Path(spec["path"])
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 10_000

    config = {field: {"patterns": [f"sw:{field}="]} for field in spec["fields"]}

    parser = StructlyParser(
        config,
        field_layout="inline",
        inline_value_delimiters=" \t,;|",
    )

    results = parser.parse_many(lines)
    assert len(results) == len(lines)

    # Check a deterministic subset to keep runtime low but still cover the file.
    sample_indexes = [0, 1, 257, 4095, len(lines) - 2, len(lines) - 1]
    for idx in sample_indexes:
        produced = results[idx]
        expected = _baseline_parse(lines[idx], spec["fields"])
        for field in spec["fields"]:
            assert produced[field] == expected[field]
