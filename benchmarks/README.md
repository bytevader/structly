# Structly Benchmarks

This directory contains the scripts used to compare Structly against popular Python parsing stacks. All scripts assume the extension module is built (`make install-rust`) and that the optional Python dependencies listed in `requirements-dev.txt` are installed.

## Scripts

| Script | Description |
| --- | --- |
| `benchmark_structly_vs_kv_parsers.py` | Parses synthetic DNS/DHCP/IPAM/firewall/router logs with Structly inline mode vs. Python libraries (`pygrok`, `pyparsing`, `regex`, `logparser3`, `scapy`, `construct`). |
| `benchmark_structly_vs_python.py` | End-to-end WHOIS extraction: Structly vs. pure-Python strategies (starts-with+regex, regex-only) for per-call and batch performance. |
| `benchmark_structly_vs_whoisparser.py` | Direct comparison between Structly and `whois-parser` on representative WHOIS text. |

## Example Commands

```bash
# Inline log benchmarks (default dataset: firewall)
python3 benchmarks/benchmark_structly_vs_kv_parsers.py --dataset dns

# WHOIS parsing vs pure Python
python3 benchmarks/benchmark_structly_vs_python.py

# Structly vs whois-parser
python3 benchmarks/benchmark_structly_vs_whoisparser.py
```

Run each command from the project root so relative paths resolve correctly.

## Recording Results

```
## benchmark_structly_vs_kv_parsers.py (dataset=firewall)
Loaded 10,000 lines for dataset 'firewall' with fields ['fw', 'src', 'dst', 'sport', 'dport', 'proto', 'action', 'bytes']

+-------------------+----------+---------+---------+-----------+--------+
| Parser            | Mean (s) | Std (s) | Lines/s | Populated | Status |
+-------------------+----------+---------+---------+-----------+--------+
| structly_inline   |   0.0159 |  0.0022 | 630,604 |    80,000 | ok     |
| construct_adapter |   0.0215 |  0.0005 | 465,145 |    80,000 | ok     |
| scapy_raw         |   0.0565 |  0.0006 | 176,959 |    80,000 | ok     |
| pygrok            |   0.0574 |  0.0003 | 174,354 |    80,000 | ok     |
| regex             |   0.0669 |  0.0006 | 149,372 |    80,000 | ok     |
| pyparsing         |   1.0422 |  0.0126 |   9,595 |    80,000 | ok     |
| logparser3_drain  |   2.2320 |  0.0104 |   4,480 |    80,000 | ok     |
+-------------------+----------+---------+---------+-----------+--------+

## benchmark_structly_vs_kv_parsers.py (dataset=dhcp)
Loaded 10,000 lines for dataset 'dhcp' with fields ['action', 'mac', 'ip', 'lease', 'result']

+-------------------+----------+---------+---------+-----------+--------+
| Parser            | Mean (s) | Std (s) | Lines/s | Populated | Status |
+-------------------+----------+---------+---------+-----------+--------+
| structly_inline   |   0.0116 |  0.0012 | 862,746 |    50,000 | ok     |
| construct_adapter |   0.0191 |  0.0031 | 524,302 |    50,000 | ok     |
| pygrok            |   0.0356 |  0.0006 | 280,954 |    50,000 | ok     |
| scapy_raw         |   0.0530 |  0.0005 | 188,739 |    50,000 | ok     |
| regex             |   0.0542 |  0.0005 | 184,646 |    50,000 | ok     |
| logparser3_drain  |   0.4290 |  0.0031 |  23,308 |    50,000 | ok     |
| pyparsing         |   0.8722 |  0.0087 |  11,465 |    50,000 | ok     |
+-------------------+----------+---------+---------+-----------+--------+

## benchmark_structly_vs_kv_parsers.py (dataset=dns)
Loaded 10,000 lines for dataset 'dns' with fields ['client', 'query', 'type', 'response', 'rcode']

+-------------------+----------+---------+---------+-----------+--------+
| Parser            | Mean (s) | Std (s) | Lines/s | Populated | Status |
+-------------------+----------+---------+---------+-----------+--------+
| structly_inline   |   0.0123 |  0.0012 | 815,331 |    50,000 | ok     |
| construct_adapter |   0.0185 |  0.0030 | 539,800 |    50,000 | ok     |
| pygrok            |   0.0369 |  0.0008 | 271,312 |    50,000 | ok     |
| scapy_raw         |   0.0531 |  0.0004 | 188,160 |    50,000 | ok     |
| regex             |   0.0547 |  0.0004 | 182,953 |    50,000 | ok     |
| logparser3_drain  |   0.4546 |  0.0055 |  22,000 |    50,000 | ok     |
| pyparsing         |   0.8817 |  0.0100 |  11,341 |    50,000 | ok     |
+-------------------+----------+---------+---------+-----------+--------+

## benchmark_structly_vs_kv_parsers.py (dataset=ipam)
Loaded 10,000 lines for dataset 'ipam' with fields ['asset_id', 'ip', 'vlan', 'owner', 'status']

+-------------------+----------+---------+---------+-----------+--------+
| Parser            | Mean (s) | Std (s) | Lines/s | Populated | Status |
+-------------------+----------+---------+---------+-----------+--------+
| structly_inline   |   0.0127 |  0.0017 | 787,087 |    50,000 | ok     |
| construct_adapter |   0.0189 |  0.0030 | 528,510 |    50,000 | ok     |
| pygrok            |   0.0363 |  0.0002 | 275,777 |    50,000 | ok     |
| regex             |   0.0383 |  0.0006 | 260,986 |    50,000 | ok     |
| scapy_raw         |   0.0523 |  0.0004 | 191,176 |    50,000 | ok     |
| logparser3_drain  |   0.3315 |  0.0035 |  30,167 |    50,000 | ok     |
| pyparsing         |   0.6085 |  0.0090 |  16,434 |    50,000 | ok     |
+-------------------+----------+---------+---------+-----------+--------+

## benchmark_structly_vs_kv_parsers.py (dataset=router)
Loaded 10,000 lines for dataset 'router' with fields ['device', 'iface', 'status', 'flaps', 'errors']

+-------------------+----------+---------+---------+-----------+--------+
| Parser            | Mean (s) | Std (s) | Lines/s | Populated | Status |
+-------------------+----------+---------+---------+-----------+--------+
| structly_inline   |   0.0105 |  0.0004 | 952,745 |    50,000 | ok     |
| construct_adapter |   0.0191 |  0.0033 | 524,229 |    50,000 | ok     |
| pygrok            |   0.0345 |  0.0003 | 289,554 |    50,000 | ok     |
| scapy_raw         |   0.0523 |  0.0014 | 191,137 |    50,000 | ok     |
| regex             |   0.0534 |  0.0005 | 187,276 |    50,000 | ok     |
| logparser3_drain  |   0.5648 |  0.0060 |  17,706 |    50,000 | ok     |
| pyparsing         |   0.8674 |  0.0057 |  11,529 |    50,000 | ok     |
+-------------------+----------+---------+---------+-----------+--------+

## benchmark_structly_vs_python.py
+------------------------+--------+----------+---------+------------+------------+--------+--------+
| Parser                 |   Runs | Wall (s) | CPU (s) |      RSS Δ |    Py Peak | µs/run | Status |
+------------------------+--------+----------+---------+------------+------------+--------+--------+
| Rust parse_tuple       | 10,000 |   0.1472 |  0.1472 |  0.000 MiB |  0.003 MiB |   14.7 | ok     |
| Rust parse (dict)      | 10,000 |   0.2233 |  0.2233 |  0.219 MiB |  0.003 MiB |   22.3 | ok     |
| Rust parse_many(10000) | 10,000 |   0.2808 |  0.2807 | 31.172 MiB | 33.003 MiB |   28.1 | ok     |
| Py SW→Regex            | 10,000 |   3.2633 |  3.2629 |  0.391 MiB |  0.009 MiB |  326.3 | ok     |
| Py Regex-only          | 10,000 |   3.9162 |  3.9148 |  0.000 MiB |  0.008 MiB |  391.6 | ok     |
+------------------------+--------+----------+---------+------------+------------+--------+--------+

## benchmark_structly_vs_whoisparser.py
+--------------------+------+----------+---------+-----------+-----------+----------+--------+
| Parser             | Runs | Wall (s) | CPU (s) |     RSS Δ |   Py Peak |   µs/run | Status |
+--------------------+------+----------+---------+-----------+-----------+----------+--------+
| Structly parse     |  100 |   0.0022 |  0.0022 | 0.000 MiB | 0.003 MiB |     22.0 | ok     |
| whois-parser parse |  100 |  12.2224 | 12.2188 | 1.438 MiB | 0.322 MiB | 122224.4 | ok     |
+--------------------+------+----------+---------+-----------+-----------+----------+--------+
```

