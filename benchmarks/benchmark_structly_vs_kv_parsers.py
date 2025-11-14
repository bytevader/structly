from __future__ import annotations

import argparse
import contextlib
import os
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path
import shutil
import tempfile
from typing import Callable, List, Optional, Sequence, Tuple

from prettytable import PrettyTable

try:
    from colorama import Fore, Style, init as colorama_init
except ImportError:  # pragma: no cover - optional styling dependency
    Fore = Style = None  # type: ignore
    colorama_init = None  # type: ignore

try:
    from structly.parser import StructlyParser
except ImportError as exc:  # pragma: no cover - script level feedback
    print("Structly extension module is not importable. Build the project first.", file=sys.stderr)
    raise SystemExit(2) from exc


DATASET_SPECS = {
    "dns": {
        "path": Path("tests/data/dns.log"),
        "fields": ["client", "query", "type", "response", "rcode"],
    },
    "dhcp": {
        "path": Path("tests/data/dhcp.log"),
        "fields": ["action", "mac", "ip", "lease", "result"],
    },
    "ipam": {
        "path": Path("tests/data/ipam.log"),
        "fields": ["asset_id", "ip", "vlan", "owner", "status"],
    },
    "firewall": {
        "path": Path("tests/data/firewall.log"),
        "fields": ["fw", "src", "dst", "sport", "dport", "proto", "action", "bytes"],
    },
    "router": {
        "path": Path("tests/data/router.log"),
        "fields": ["device", "iface", "status", "flaps", "errors"],
    },
}


def load_dataset(name: str) -> Tuple[List[str], List[str], Path]:
    try:
        spec = DATASET_SPECS[name]
    except KeyError as exc:
        raise ValueError(f"Unknown dataset '{name}'") from exc
    lines = spec["path"].read_text(encoding="utf-8").splitlines()
    fields = spec["fields"]
    return lines, fields, spec["path"]


def structly_runner(
    lines: Sequence[str],
    fields: Sequence[str],
    _path: Path,
) -> Callable[[], int]:
    config = {
        field: {"patterns": [f"sw:{field}="]}
        for field in fields
    }
    parser = StructlyParser(
        config,
        field_layout="inline",
        inline_value_delimiters=" \t,;|",
    )

    def run() -> int:
        results = parser.parse_many(lines)
        # Return the number of populated fields to guard against dead-code elimination.
        return sum(
            sum(1 for value in record.values() if value)
            for record in results
        )

    return run


def logparser3_runner(
    _lines: Sequence[str],
    fields: Sequence[str],
    path: Path,
) -> Optional[Callable[[], int]]:
    try:
        from logparser.Drain import Drain  # type: ignore
        import pandas as pd
    except ImportError:
        return None

    field_set = set(fields)

    def run() -> int:
        outdir = Path(tempfile.mkdtemp(prefix="drain_bench_"))
        parser = Drain.LogParser(
            log_format="<Content>",
            indir=str(path.parent),
            outdir=str(outdir),
            keep_para=False,
        )
        with open(os.devnull, "w") as devnull, contextlib.redirect_stdout(devnull):
            parser.parse(path.name)
        structured = outdir / f"{path.name}_structured.csv"
        populated = 0
        if structured.exists():
            try:
                df = pd.read_csv(structured)
                if "Content" in df.columns:
                    populated = sum(
                        sum(
                            1
                            for field in field_set
                            if f"{field}=" in str(row["Content"])
                        )
                        for _, row in df.iterrows()
                    )
                else:
                    populated = len(df)
            except Exception:
                populated = 0
        shutil.rmtree(outdir, ignore_errors=True)
        return populated

    return run


def pygrok_runner(
    lines: Sequence[str],
    fields: Sequence[str],
    _path: Path,
) -> Optional[Callable[[], int]]:
    try:
        from pygrok import Grok  # type: ignore
    except ImportError:
        return None

    groks = {
        field: Grok(f"{field}=%{{NOTSPACE:{field}}}")
        for field in fields
    }

    def run() -> int:
        populated = 0
        for line in lines:
            for field, grok in groks.items():
                match = grok.match(line)
                if match and match.get(field):
                    populated += 1
        return populated

    return run


def pyparsing_runner(
    lines: Sequence[str],
    fields: Sequence[str],
    _path: Path,
) -> Optional[Callable[[], int]]:
    try:
        from pyparsing import (  # type: ignore
            CharsNotIn,
            Suppress,
            Word,
            alphanums,
        )
    except ImportError:
        return None

    key = Word(alphanums + "_-/:")
    value = CharsNotIn(" \t,;|")
    pair = key("key") + Suppress("=") + value("value")
    field_set = set(fields)

    def run() -> int:
        populated = 0
        for line in lines:
            for tokens, _, _ in pair.scanString(line):
                name = tokens["key"]
                if name in field_set:
                    populated += 1
        return populated

    return run


def regex_runner(
    lines: Sequence[str],
    fields: Sequence[str],
    _path: Path,
) -> Optional[Callable[[], int]]:
    try:
        import regex  # type: ignore
    except ImportError:
        return None

    pattern = regex.compile(r"(?P<key>[\w:/-]+)=(?P<value>[^\s,;|]+)")
    field_set = set(fields)

    def run() -> int:
        populated = 0
        for line in lines:
            for match in pattern.finditer(line):
                if match.group("key") in field_set:
                    populated += 1
        return populated

    return run


def scapy_runner(
    lines: Sequence[str],
    fields: Sequence[str],
    _path: Path,
) -> Optional[Callable[[], int]]:
    try:
        from scapy.packet import Raw  # type: ignore
    except ImportError:
        return None

    field_set = set(fields)

    def run() -> int:
        populated = 0
        for line in lines:
            pkt = Raw(load=line.encode("utf-8", errors="ignore"))
            tokens = pkt.load.decode("utf-8", errors="ignore").split()
            for token in tokens:
                if "=" not in token:
                    continue
                key, value = token.split("=", 1)
                if key in field_set and value:
                    populated += 1
        return populated

    return run


def construct_runner(
    lines: Sequence[str],
    fields: Sequence[str],
    _path: Path,
) -> Optional[Callable[[], int]]:
    try:
        from construct import ExprAdapter, GreedyBytes  # type: ignore
    except ImportError:
        return None

    field_set = set(fields)
    adapter = ExprAdapter(
        GreedyBytes,
        decoder=lambda obj, _ctx: {
            key: value
            for key, value in (
                token.split("=", 1)
                for token in obj.decode("utf-8", errors="ignore").split()
                if "=" in token
            )
        },
        encoder=lambda data, _ctx: " ".join(f"{k}={v}" for k, v in data.items()).encode(
            "utf-8"
        ),
    )

    def run() -> int:
        populated = 0
        for line in lines:
            try:
                mapping = adapter.parse(line.encode("utf-8", errors="ignore"))
            except Exception:
                continue
            populated += sum(1 for field in field_set if mapping.get(field))
        return populated

    return run


@dataclass
class BenchmarkTarget:
    name: str
    factory: Callable[[Sequence[str], Sequence[str], Path], Optional[Callable[[], int]]]


TARGETS = [
    BenchmarkTarget("structly_inline", structly_runner),
    BenchmarkTarget("logparser3_drain", logparser3_runner),
    BenchmarkTarget("pygrok", pygrok_runner),
    BenchmarkTarget("pyparsing", pyparsing_runner),
    BenchmarkTarget("regex", regex_runner),
    BenchmarkTarget("scapy_raw", scapy_runner),
    BenchmarkTarget("construct_adapter", construct_runner),
]


def time_runner(fn: Callable[[], int], repeats: int, warmup: int) -> Tuple[List[float], int]:
    for _ in range(warmup):
        fn()
    samples: List[float] = []
    result = 0
    for _ in range(repeats):
        start = time.perf_counter()
        result = fn()
        samples.append(time.perf_counter() - start)
    return samples, result


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark Structly inline layout against common Python log parsers.")
    parser.add_argument(
        "--dataset",
        choices=sorted(DATASET_SPECS),
        default="firewall",
        help="Synthetic dataset to benchmark (default: firewall).",
    )
    parser.add_argument(
        "--repeats",
        type=int,
        default=5,
        help="Measurement repeats per parser (default: 5).",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=1,
        help="Warmup runs per parser (default: 1).",
    )
    args = parser.parse_args(argv)

    if colorama_init:
        colorama_init(autoreset=True)

    lines, fields, path = load_dataset(args.dataset)
    total_lines = len(lines)
    print(f"Loaded {total_lines:,} lines for dataset '{args.dataset}' with fields {fields}")

    results: List[dict] = []

    for target in TARGETS:
        runner = target.factory(lines, fields, path)
        if runner is None:
            results.append(
                {
                    "name": target.name,
                    "status": "skipped",
                    "reason": "dependency not available",
                }
            )
            continue
        try:
            samples, populated = time_runner(runner, repeats=args.repeats, warmup=args.warmup)
        except Exception as exc:  # pragma: no cover - keep benchmark running
            results.append(
                {
                    "name": target.name,
                    "status": "error",
                    "reason": str(exc),
                }
            )
            continue

        mean = statistics.mean(samples)
        std = statistics.stdev(samples) if len(samples) > 1 else 0.0
        lines_per_sec = total_lines / mean if mean > 0 else float("inf")
        results.append(
            {
                "name": target.name,
                "status": "ok",
                "mean": mean,
                "std": std,
                "lps": lines_per_sec,
                "populated": populated,
            }
        )

    table = PrettyTable()
    table.field_names = ["Parser", "Mean (s)", "Std (s)", "Lines/s", "Populated", "Status"]
    table.align = "r"
    table.align["Parser"] = "l"
    table.align["Status"] = "l"

    ok_results = sorted(
        (r for r in results if r["status"] == "ok"),
        key=lambda r: r["mean"],
    )
    others = [r for r in results if r["status"] != "ok"]
    best_mean = ok_results[0]["mean"] if ok_results else None
    worst_mean = ok_results[-1]["mean"] if len(ok_results) > 1 else None

    ordered_results = ok_results + others

    def colour(text: str, role: Optional[str] = None) -> str:
        if Fore is None or Style is None:
            return text
        if role == "best":
            colour_code = Fore.GREEN
        elif role == "worst":
            colour_code = Fore.RED
        elif role == "mid":
            colour_code = Fore.YELLOW
        else:
            colour_code = Fore.WHITE
        return f"{colour_code}{text}{Style.RESET_ALL}"

    for res in ordered_results:
        status = res["status"]
        if status == "ok":
            role = None
            if best_mean is not None and res["mean"] == best_mean:
                role = "best"
            elif worst_mean is not None and res["mean"] == worst_mean and best_mean != worst_mean:
                role = "worst"
            else:
                role = "mid"
            parser_name = colour(res["name"], role)
            table.add_row(
                [
                    parser_name,
                    f"{res['mean']:.4f}",
                    f"{res['std']:.4f}",
                    f"{res['lps']:,.0f}",
                    f"{res['populated']:,}",
                    colour("ok", role),
                ]
            )
        elif status == "skipped":
            parser_name = colour(res["name"], "mid")
            table.add_row(
                [
                    parser_name,
                    "-",
                    "-",
                    "-",
                    "-",
                    f"skipped ({res['reason']})",
                ]
            )
        else:
            parser_name = colour(res["name"], "worst")
            table.add_row(
                [
                    parser_name,
                    "-",
                    "-",
                    "-",
                    "-",
                    f"error ({res['reason']})",
                ]
            )

    print()
    print(table)

    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
