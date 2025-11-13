from __future__ import annotations

import gc
import os
from pathlib import Path

import psutil
import pytest

from structly.parser import StructlyParser


def _rss_bytes() -> int:
    process = psutil.Process(os.getpid())
    return process.memory_info().rss


@pytest.mark.skipif(psutil is None, reason="psutil is required for RSS-based memory check")
def test_inline_parser_does_not_leak_rss() -> None:
    lines = Path("tests/data/firewall.log").read_text(encoding="utf-8").splitlines()
    parser = StructlyParser(
        {
            "src": {"patterns": ["sw:src="]},
            "dst": {"patterns": ["sw:dst="]},
            "action": {"patterns": ["sw:action="]},
            "bytes": {"patterns": ["sw:bytes="]},
        },
        field_layout="inline",
        inline_value_delimiters=" \t,;|",
    )

    baseline = _rss_bytes()
    iterations = 100
    for i in range(iterations):
        parser.parse_many(lines)
        if i % 5 == 4:
            gc.collect()
    gc.collect()
    post = _rss_bytes()

    # Allow a small cushion for allocator fragmentation and cache warmup.
    allowed_growth = 12 * 1024 * 1024  # 12 MiB
    assert post - baseline <= allowed_growth
