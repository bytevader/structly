<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/structly.svg">
    <img alt="structly" src="docs/structly.svg">
  </picture>
</p>
<p align="center">
    <em>Structly — Rust-powered parser made for massive telemetry and log workloads.</em>
</p>
<p align="center">
<a href="https://github.com/bytevader/structly/actions/workflows/dev-ci.yml?query=branch%3Adev" target="_blank">
    <img src="https://github.com/bytevader/structly/actions/workflows/dev-ci.yml/badge.svg?branch=dev" alt="Dev CI">
</a>

<a href="https://github.com/bytevader/structly/actions/workflows/main-ci.yml?query=branch%3Amain" target="_blank">
    <img src="https://github.com/bytevader/structly/actions/workflows/main-ci.yml/badge.svg?branch=main" alt="Main CI">
</a>

<a href="https://github.com/bytevader/structly/actions/workflows/main-ci.yml?query=branch%3Amain" target="_blank">
    <img src="https://coverage-badge.samuelcolvin.workers.dev/bytevader/structly.svg?branch=main" alt="Coverage">
</a>
<a href="https://pypi.org/project/structly" target="_blank">
    <img src="https://img.shields.io/pypi/v/structly?color=%2334D058&label=pypi%20package" alt="Package version">
</a>
</p>


---

**Source Code**: <a href="https://github.com/bytevader/structly" target="_blank">https://github.com/bytevader/structly</a>

---
Structly is a high-performance parsing toolkit that combines a Rust core with a Pythonic API.\
True to its name, Structly turns massive amounts of unstructured input into clean, structured outputs without slowing your workflows.

It is built for teams who need to sift through and parse large volumes of operational telemetry—syslog, DNS, DHCP, IPAM, firewall, routing, whois, nuclei, etc. — faster and with less memory overhead than pure-Python pipelines.

Structly’s design maximises throughput without sacrificing the clarity of Python’s API. 
If you need reliable, deterministic log/text parsing at scale, Structly is built to slot into your pipeline—and leave Python-only alternatives far behind.

## Why Structly?

- **Native-speed extraction.** Parsing logic is compiled to Rust and exposed through PyO3, giving Structly microsecond-level latency per record while staying drop-in compatible with Python workflows.
- **Inline log intelligence.** Inline mode recognises `key=value` tokens anywhere on the line, not only at the start, so modern, densely packed logs are handled without regex backtracking.
- **Predictable memory profile.** The parser works on raw byte ranges and chunked batching, preventing the transient allocations often seen in Python log frameworks.
- **Proven advantage over Python stacks.** Benchmarks show Structly parsing synthetic DNS and firewall workloads ~4× faster than libraries such as `pygrok`, `pyparsing`, `regex`, or `logparser3`, while preserving full fidelity of the extracted fields.

## When to Choose Structly Over Python Parsers

| Scenario | Why Structly Wins |
| --- | --- |
| Large batches (10k+ lines per file) | Native code + optional Rayon parallelism keeps throughput >600k lines/s. |
| Dense inline logs (`key=value …`) | Inline mode uses Aho–Corasick plus delimiter scans—no regex backtracking. |
| Multi-field WHOIS records | Rust implementation extracts complex sections in ~0.016s vs ~0.07s for regex. |
| Repeated runs in pipelines | `parse_iter` and `parse_chunks` stream results with predictable memory usage. |
| CPU-bound environments | Rayon policies let you scale across cores or run single-threaded deterministically. |

## Installation

If you are working from this Git repository:

```bash
# Clone the repo and enter it
git clone https://github.com/bytevader/structly.git
cd structly

# Install requirements
pip install -e '.[dev]'
# or
python3 -m pip install -r requirements-dev.txt

# Build the native extension (release mode recommended)
make install-rust

# or, if you manage environments manually:
python3 -m maturin develop --release
```

Structly targets Python 3.9+ with the abi3 wheel and does not require a specific virtual environment layout.

## Core Concepts

### Configuration

```python
from structly import StructlyConfig, FieldSpec, FieldPattern, Mode, StructlyParser

cfg = StructlyConfig.from_mapping({
    "domain": {"patterns": ["sw:Domain:"]},
    "registrar": FieldSpec(
            patterns=[
                FieldPattern.starts_with("Registrar:"),
                FieldPattern.regex(r"^\s*Registrar:\s*(?P<val>.+)$"),
                FieldPattern.regex(r"^\s*(?P<val>.+\[Tag = .+\])$"),
            ],
        ),
    "nameservers": {
        "patterns": ["sw:Name Server:"],
        "mode": Mode.all.value,
        "unique": True,
        "return": "list",
    },
})
parser = StructlyParser(cfg)
```

Patterns accept `sw:` (starts-with) and `r:` (regex) prefixes, returning lists or deduplicating values is built in.\
You can use either just strings for patterns like this:\
`"sw:Domain:"` - but keep in mind that the pattern string should start with `sw:` or `r:`\
Or you can use `FieldPattern` model that is more readable:\
```python
FieldPattern.starts_with("Registrar:"),
FieldPattern.regex(r"^\s*Registrar:\s*(?P<val>.+)$"),
```

### Layouts: `line` vs `inline`

- **Line layout (default).** Extracts values that appear immediately after the prefix at the start of a line—ideal for classic syslog, WHOIS, or structured plaintext.
- **Inline layout.** Use `StructlyParser(..., field_layout="inline", inline_value_delimiters=" \t,;|")` to scan for tokens anywhere on the line. Choose your own delimiter set for unusual formats.

Inline mode retains regex support and deduplication logic while significantly outperforming Python regex loops.

### Rayon Policies

`rayon_policy` controls native parallelism:

- `"never"` (default): deterministic single-thread execution.
- `"always"`: enables Rayon for `parse_many` and chunked paths—best on multi-core hosts.
- `"auto"`: lets the runtime pick (currently equivalent to `"always"`).

This policy is also respected by helper functions (`prepare_parser`, `parse_text`, etc).

### Execution Modes

| Method | When to Use | Notes |
| --- | --- | --- |
| `parse(text)` | Single document | Returns a dict of field→value. |
| `parse_tuple(text)` | Positional accesses | Saves dictionary overhead when order matters. |
| `parse_many(list[str])` | Moderate batches (fits in RAM) | Processes eagerly and returns a list. |
| `parse_iter(iterable, chunk_size)` | Streaming pipelines | Yields one record at a time (or per chunk) without retaining previous results. |
| `parse_chunks(iterable, chunk_size)` | ETL batching | Chunked output for bulk writes (default 512). |

`chunk_size` must be a positive integer; invalid inputs raise immediately, keeping bugs discoverable early.

### Usage

#### WHOIS example

```python
from structly import StructlyConfig, FieldSpec, Mode, StructlyParser

WHOIS_SAMPLE = """\
Domain Name: EXAMPLE-CONTACT.COM
Registry Domain ID: 123456789_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.example-registrar.com
Registrar URL: https://www.example-registrar.com
Updated Date: 2024-03-11T07:12:34Z
Creation Date: 2010-06-18T13:45:21Z
Registry Expiry Date: 2030-06-18T13:45:21Z
Registrar: Example Registrar, Inc.
Registrar IANA ID: 199
Registrant Name: Example Holdings Privacy
Registrant Organization: Example Holdings
Registrant Street: 123 Example Ave
Registrant City: San Francisco
Registrant State/Province: CA
Registrant Postal Code: 94105
Registrant Country: US
Registrant Phone: +1.5555550000
Registrant Email: noc@example-holdings.com
Tech Email: tech@example-holdings.com
Name Server: NS1.EXAMPLE.NET
Name Server: NS2.EXAMPLE.NET
Name Server: NS3.EXAMPLE.NET
DNSSEC: unsigned
Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
Status: clientRenewProhibited https://icann.org/epp#clientRenewProhibited
"""

cfg = StructlyConfig.from_mapping({
    "domain": {"patterns": ["sw:Domain Name:"]},
    "registrar": {"patterns": ["sw:Registrar:"]},
    "created": {"patterns": ["sw:Creation Date:"]},
    "expiry": {"patterns": ["sw:Registry Expiry Date:"]},
    "nameservers": {
        "patterns": ["sw:Name Server:"],
        "mode": Mode.all.value,
        "unique": True,
        "return": "list",
    },
    "statuses": {
        "patterns": ["sw:Status:"] ,
        "mode": Mode.all.value,
        "unique": True,
        "return": "list",
    },
})

parser = StructlyParser(cfg)
result = parser.parse(WHOIS_SAMPLE)

print(result["domain"])
# EXAMPLE-CONTACT.COM
print(result["nameservers"])
# ['NS1.EXAMPLE.NET', 'NS2.EXAMPLE.NET', 'NS3.EXAMPLE.NET']
```

#### Method examples

```python
from structly import StructlyConfig, StructlyParser

cfg = StructlyConfig.from_mapping({
    "ts": {"patterns": ["sw:ts="]},
    "host": {"patterns": ["sw:host="]},
    "status": {"patterns": ["sw:status="]},
})
parser = StructlyParser(
    cfg,
    field_layout="inline",
    inline_value_delimiters=" ",
)

sample_lines = [
    "ts=2025-01-01T00:00:01Z host=api.demo status=ok latency=41ms",
    "ts=2025-01-01T00:00:02Z host=web.demo status=warn latency=88ms",
]

single = parser.parse(sample_lines[0])
# {'ts': '2025-01-01T00:00:01Z', 'host': 'api.demo', 'status': 'ok'}

ordered = parser.parse_tuple(sample_lines[0])
# ('2025-01-01T00:00:01Z', 'api.demo', 'ok')

batch = parser.parse_many(sample_lines)
# [{'ts': ...}, {'ts': ...}]

streamed = list(parser.parse_iter(sample_lines, chunk_size=1))
# parsed docs yielded one at a time

chunked = list(parser.parse_chunks(sample_lines, chunk_size=2))
# [[{'ts': ...}, {'ts': ...}]]
```



## Benchmarks

Benchmarks live in `benchmarks/` and can be run from the repository root:

```bash
# Synthetic log workloads (Structly inline vs Python libraries)
python3 benchmarks/benchmark_structly_vs_kv_parsers.py --dataset firewall

# WHOIS extraction vs pure Python regex pipelines
python3 benchmarks/benchmark_structly_vs_python.py

# Direct comparison to whois-parser
python3 benchmarks/benchmark_structly_vs_whoisparser.py
```

Each script prints a PrettyTable summary; fastest parsers are highlighted in green, slowest in red.\
Check `benchmarks/README.md` for examples.

## Fixtures & Testing

Synthetic datasets (10k lines each) cover DNS, DHCP, IPAM, firewall/netflow, and router logs under `tests/data/`. Tests verify both accuracy and long-run stability:

- `tests/functional/test_inline_logs.py` compares inline extractions to a Python baseline.
- `tests/functional/test_memory_soak.py` guards against RSS leaks on large runs.
- Unit tests cover API validation, streaming methods, and rayon policy handling.

Run the suite after installing dev requirements:

```bash
python3 -m pytest
```
