from __future__ import annotations


import re
import sys
import time
from dataclasses import dataclass
from pprint import pprint
from typing import Any, Dict, List, Optional, Tuple

import resource
import tracemalloc
from prettytable import PrettyTable

try:
    from colorama import Fore, Style, init as colorama_init
except ImportError:  # pragma: no cover - optional styling dependency
    Fore = Style = None  # type: ignore
    colorama_init = None  # type: ignore

from structly import (
    FieldSpec,
    Mode,
    ReturnShape,
    StructlyConfig,
    StructlyParser,
)
tracemalloc.start()
RSS_MULTIPLIER = 1 if sys.platform == "darwin" else 1024

if colorama_init:
    colorama_init(autoreset=True)


@dataclass
class Metrics:
    seconds: float
    cpu_seconds: float
    rss_bytes: int
    py_peak_bytes: int


def _get_usage_snapshot() -> Tuple[float, resource.struct_rusage, Tuple[int, int]]:
    return (
        time.perf_counter(),
        resource.getrusage(resource.RUSAGE_SELF),
        tracemalloc.get_traced_memory(),
    )


def _delta_metrics(start: Tuple[float, resource.struct_rusage, Tuple[int, int]]) -> Metrics:
    t0, r0, (_, py_peak0) = start
    t1 = time.perf_counter()
    r1 = resource.getrusage(resource.RUSAGE_SELF)
    _, py_peak1 = tracemalloc.get_traced_memory()

    wall = t1 - t0
    cpu = (r1.ru_utime + r1.ru_stime) - (r0.ru_utime + r0.ru_stime)
    rss_bytes = int(max(0.0, (r1.ru_maxrss - r0.ru_maxrss)) * RSS_MULTIPLIER)
    py_peak_bytes = max(0, py_peak1 - py_peak0)
    tracemalloc.reset_peak()
    return Metrics(seconds=wall, cpu_seconds=cpu, rss_bytes=rss_bytes, py_peak_bytes=py_peak_bytes)


def _format_bytes(num: int) -> str:
    if num <= 0:
        return "0.000 MiB"
    return f"{num / (1024 * 1024):.3f} MiB"


# -----------------------
# 1) Build config & text
# -----------------------
CFG = StructlyConfig.from_mapping(
    {
        "domain": FieldSpec(patterns=["sw:Domain Name:", "r:^Domain Name:\\s*"]),
        "registrar": FieldSpec(patterns=["sw:Registrar:", "r:^Registrar:\\s*"]),
        "created_date": FieldSpec(patterns=["sw:Created Date:", "sw:Creation Date:", "r:^CreatedDate:\\s*"]),
        "updated_date": FieldSpec(patterns=["sw:Updated Date:", "sw:UpdatedDate:", "r:^UpdatedDate:\\s*"]),
        "expires_date": FieldSpec(
            patterns=[
                "sw:Registrar Registration Expiration Date:",
                "r:^Registrar Registration Expiration Date:\\s*",
            ]
        ),
        "nameservers": FieldSpec(
            patterns=["sw:Name Server:", "r:^Name Server:\\s*"],
            mode=Mode.all,
            unique=True,
            return_shape=ReturnShape.list_,
        ),
        "status": FieldSpec(
            patterns=["sw:Domain Status:", "r:^Domain Status:\\s*"],
            mode=Mode.all,
            unique=True,
            return_shape=ReturnShape.list_,
        ),
        # Registrant section
        "registrant_id": FieldSpec(patterns=["sw:Registry Registrant ID:", "r:^Registry Registrant ID:\\s*"]),
        "registrant_name": FieldSpec(patterns=["sw:Registrant Name:", "r:^Registrant Name:\\s*"]),
        "registrant_org": FieldSpec(patterns=["sw:Registrant Organization:", "r:^Registrant Organization:\\s*"]),
        "registrant_street": FieldSpec(
            patterns=["sw:Registrant Street:", "r:^Registrant Street:\\s*"],
            mode=Mode.all,
            unique=True,
            return_shape=ReturnShape.list_,
        ),
        "registrant_city": FieldSpec(patterns=["sw:Registrant City:", "r:^Registrant City:\\s*"]),
        "registrant_state": FieldSpec(patterns=["sw:Registrant State/Province:", "r:^Registrant State/Province:\\s*"]),
        "registrant_postal": FieldSpec(patterns=["sw:Registrant Postal Code:", "r:^Registrant Postal Code:\\s*"]),
        "registrant_country": FieldSpec(patterns=["sw:Registrant Country:", "r:^Registrant Country:\\s*"]),
        "registrant_phone": FieldSpec(patterns=["sw:Registrant Phone:", "r:^Registrant Phone:\\s*"]),
        "registrant_phone_ext": FieldSpec(patterns=["sw:Registrant Phone Ext:", "r:^Registrant Phone Ext:\\s*"]),
        "registrant_fax": FieldSpec(patterns=["sw:Registrant Fax:", "r:^Registrant Fax:\\s*"]),
        "registrant_fax_ext": FieldSpec(patterns=["sw:Registrant Fax Ext:", "r:^Registrant Fax Ext:\\s*"]),
        "registrant_email": FieldSpec(patterns=["sw:Registrant Email:", "r:^Registrant Email:\\s*"]),
        # Tech section
        "tech_id": FieldSpec(patterns=["sw:Registry Tech ID:", "r:^Registry Tech ID:\\s*"]),
        "tech_name": FieldSpec(patterns=["sw:Tech Name:", "r:^Tech Name:\\s*"]),
        "tech_org": FieldSpec(patterns=["sw:Tech Organization:", "r:^Tech Organization:\\s*"]),
        "tech_street": FieldSpec(
            patterns=["sw:Tech Street:", "r:^Tech Street:\\s*"],
            mode=Mode.all,
            unique=True,
            return_shape=ReturnShape.list_,
        ),
        "tech_city": FieldSpec(patterns=["sw:Tech City:", "r:^Tech City:\\s*"]),
        "tech_state": FieldSpec(patterns=["sw:Tech State/Province:", "r:^Tech State/Province:\\s*"]),
        "tech_postal": FieldSpec(patterns=["sw:Tech Postal Code:", "r:^Tech Postal Code:\\s*"]),
        "tech_country": FieldSpec(patterns=["sw:Tech Country:", "r:^Tech Country:\\s*"]),
        "tech_phone": FieldSpec(patterns=["sw:Tech Phone:", "r:^Tech Phone:\\s*"]),
        "tech_phone_ext": FieldSpec(patterns=["sw:Tech Phone Ext:", "r:^Tech Phone Ext:\\s*"]),
        "tech_fax": FieldSpec(patterns=["sw:Tech Fax:", "r:^Tech Fax:\\s*"]),
        "tech_fax_ext": FieldSpec(patterns=["sw:Tech Fax Ext:", "r:^Tech Fax Ext:\\s*"]),
        "tech_email": FieldSpec(patterns=["sw:Tech Email:", "r:^Tech Email:\\s*"]),
    }
)

PARSER = StructlyParser(CFG)
RUNTIME = PARSER.runtime_config

TEXT = """\
# whois.godaddy.com

Domain Name: DOMAIN.COM
Registry Domain ID: 1234567_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.godaddy.com
Registrar URL: https://www.godaddy.com
Updated Date: 2024-10-12T11:16:10Z
Creation Date: 2001-01-10T13:17:02Z
Registrar Registration Expiration Date: 2030-01-10T13:17:02Z
Registrar: GoDaddy.com, LLC
Registrar IANA ID: 146
Registrar Abuse Contact Email: abuse@godaddy.com
Registrar Abuse Contact Phone: +1.4806242505
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
Domain Status: clientRenewProhibited https://icann.org/epp#clientRenewProhibited
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Registry Registrant ID: Not Available From Registry
Registrant Name: Registration Private
Registrant Organization: Domains By Proxy, LLC
Registrant Street: DomainsByProxy.com
Registrant Street: 100 S. Mill Ave, Suite 1600
Registrant City: Tempe
Registrant State/Province: Arizona
Registrant Postal Code: 85281
Registrant Country: US
Registrant Phone: +1.4806242599
Registrant Phone Ext:
Registrant Fax:
Registrant Fax Ext:
Registrant Email: https://www.godaddy.com/whois/results.aspx?domain=DOMAIN.COM&action=contactDomainOwner
Registry Tech ID: Not Available From Registry
Tech Name: Registration Private
Tech Organization: Domains By Proxy, LLC
Tech Street: DomainsByProxy.com
Tech Street: 100 S. Mill Ave, Suite 1600
Tech City: Tempe
Tech State/Province: Arizona
Tech Postal Code: 85281
Tech Country: US
Tech Phone: +1.4806242599
Tech Phone Ext:
Tech Fax:
Tech Fax Ext:
Tech Email: https://www.godaddy.com/whois/results.aspx?domain=DOMAIN.COM&action=contactDomainOwner
Name Server: NS1.DOMAINDNS.COM
Name Server: NS1.DOMAINDNS.ORG
Name Server: NS1.DOMAINDNS.NET
DNSSEC: signedDelegation
URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/
>>> Last update of WHOIS database: 2025-10-03T12:40:04Z <<<
"""


# ---------------------------------------
# 2) Python baselines (SW→Regex, Regex)
# ---------------------------------------

class PyPlan:
    __slots__ = ("sw", "res", "mode_all", "unique", "return_list")

    def __init__(self, sw: List[str], res: List[re.Pattern], mode_all: bool, unique: bool, return_list: bool):
        self.sw = sw
        self.res = res
        self.mode_all = mode_all
        self.unique = unique
        self.return_list = return_list


def _normalize_field_cfg(field_cfg: Any) -> Tuple[List[str], List[str], bool, bool, bool]:
    if isinstance(field_cfg, list):
        patterns = field_cfg
        mode_all = False
        unique = False
        return_list = False
    else:
        patterns = field_cfg["patterns"]
        mode_all = field_cfg.get("mode", "first") == "all"
        unique = bool(field_cfg.get("unique", False))
        return_list = field_cfg.get("return", "scalar") == "list"

    sw = [p[3:] for p in patterns if isinstance(p, str) and p.startswith("sw:")]
    regexes = [p[2:] for p in patterns if isinstance(p, str) and p.startswith("r:")]
    return sw, regexes, mode_all, unique, return_list


def build_py_plan(runtime_cfg: Dict[str, Any]) -> Dict[str, PyPlan]:
    plan: Dict[str, PyPlan] = {}
    for field, fc in runtime_cfg.items():
        sw, regexes, mode_all, unique, return_list = _normalize_field_cfg(fc)
        res = [re.compile(rx) for rx in regexes]
        plan[field] = PyPlan(sw=sw, res=res, mode_all=mode_all, unique=unique, return_list=return_list)
    return plan


def parse_py_sw_then_regex(text: str, plan: Dict[str, PyPlan]) -> Dict[str, Any]:
    lines = text.splitlines()
    out: Dict[str, Any] = {}
    for field, p in plan.items():
        results: List[str] = []
        seen = set()

        # starts-with pass
        for prefix in p.sw:
            for line in lines:
                if line.startswith(prefix):
                    val = line[len(prefix) :].strip()
                    if not val:
                        continue
                    if p.unique and val in seen:
                        continue
                    if p.unique:
                        seen.add(val)
                    results.append(val)
                    if not p.mode_all:
                        break
            if results and not p.mode_all:
                break

        # regex pass
        if p.res and (p.mode_all or not results):
            for line in lines:
                for rx in p.res:
                    match = rx.match(line)
                    if match:
                        if "val" in match.groupdict():
                            val = match.group("val")
                        elif match.lastindex:
                            val = match.group(match.lastindex)
                        else:
                            val = line[match.end() :]
                        val = val.strip()
                        if not val:
                            continue
                        if p.unique and val in seen:
                            continue
                        if p.unique:
                            seen.add(val)
                        results.append(val)
                        if not p.mode_all:
                            break
                if results and not p.mode_all:
                    break

        out[field] = results if (p.return_list or p.mode_all) else (results[0] if results else None)
    return out


def parse_py_regex_only(text: str, plan: Dict[str, PyPlan]) -> Dict[str, Any]:
    lines = text.splitlines()
    out: Dict[str, Any] = {}
    for field, p in plan.items():
        results: List[str] = []
        seen = set()
        for line in lines:
            for rx in p.res:
                match = rx.match(line)
                if match:
                    if "val" in match.groupdict():
                        val = match.group("val")
                    elif match.lastindex:
                        val = match.group(match.lastindex)
                    else:
                        val = line[match.end() :]
                    val = val.strip()
                    if not val:
                        continue
                    if p.unique and val in seen:
                        continue
                    if p.unique:
                        seen.add(val)
                    results.append(val)
                    if not p.mode_all:
                        break
            if results and not p.mode_all:
                break
        out[field] = results if (p.return_list or p.mode_all) else (results[0] if results else None)
    return out


# ------------------------
# 3) Warmup & correctness
# ------------------------
print("Rust (dict) result:")
rust_out_dict = PARSER.parse(TEXT)
pprint(rust_out_dict)

# Tuple API
names_tuple = PARSER.field_names
vals_tuple = PARSER.parse_tuple(TEXT)
rust_out_from_tuple = dict(zip(names_tuple, vals_tuple))
assert rust_out_from_tuple == rust_out_dict

# Python baselines
py_plan = build_py_plan(RUNTIME)
py_swregex_out = parse_py_sw_then_regex(TEXT, py_plan)
py_regex_only_out = parse_py_regex_only(TEXT, py_plan)

print("\nPython SW→Regex result:")
pprint(py_swregex_out)
print("\nPython Regex-only result:")
pprint(py_regex_only_out)

if rust_out_dict != py_swregex_out:
    print("\nWARNING: mismatch between Structly output and Python SW→Regex baseline")
    for key in sorted(set(rust_out_dict) | set(py_swregex_out)):
        if rust_out_dict.get(key) != py_swregex_out.get(key):
            print(f" - {key}: structly={rust_out_dict.get(key)!r}, python={py_swregex_out.get(key)!r}")


# --------------------------
# 4) Benchmarks (N runs)
# --------------------------
def bench(label: str, fn, args: Tuple[Any, ...], runs: int = 10_000) -> Dict[str, Any]:
    try:
        fn(*args)
    except Exception as exc:  # pragma: no cover - defensive
        return {"label": label, "status": "error", "reason": str(exc)}

    tracemalloc.reset_peak()
    start = _get_usage_snapshot()
    try:
        for _ in range(runs):
            fn(*args)
    except Exception as exc:  # pragma: no cover - defensive
        return {"label": label, "status": "error", "reason": str(exc)}

    metrics = _delta_metrics(start)
    return {
        "label": label,
        "status": "ok",
        "runs": runs,
        "metrics": metrics,
        "per_us": (metrics.seconds / runs) * 1e6 if runs else float("nan"),
    }


N = 10_000
results: List[Dict[str, Any]] = []

print("\n=== Benchmarks (per-call) ===")
results.append(bench("Rust parse (dict)", PARSER.parse, (TEXT,), runs=N))
results.append(bench("Rust parse_tuple", PARSER.parse_tuple, (TEXT,), runs=N))
results.append(bench("Py SW→Regex", parse_py_sw_then_regex, (TEXT, py_plan), runs=N))
results.append(bench("Py Regex-only", parse_py_regex_only, (TEXT, py_plan), runs=N))

print("\n=== Batch benchmark (parse_many) ===")
batch = [TEXT] * N
def bench_batch(label: str, fn, batch_inputs: List[str]) -> Dict[str, Any]:
    try:
        fn(batch_inputs)
    except Exception as exc:  # pragma: no cover - defensive
        return {"label": label, "status": "error", "reason": str(exc)}

    tracemalloc.reset_peak()
    start = _get_usage_snapshot()
    try:
        fn(batch_inputs)
    except Exception as exc:  # pragma: no cover - defensive
        return {"label": label, "status": "error", "reason": str(exc)}
    metrics = _delta_metrics(start)
    return {
        "label": label,
        "status": "ok",
        "runs": len(batch_inputs),
        "metrics": metrics,
        "per_us": (metrics.seconds / len(batch_inputs)) * 1e6 if batch_inputs else float("nan"),
    }

batch_result = bench_batch(f"Rust parse_many({N})", PARSER.parse_many, batch)
results.append(batch_result)

ok_results = sorted(
    (r for r in results if r["status"] == "ok"),
    key=lambda r: r["metrics"].seconds,
)
others = [r for r in results if r["status"] != "ok"]

best_wall = ok_results[0]["metrics"].seconds if ok_results else None
worst_wall = ok_results[-1]["metrics"].seconds if len(ok_results) > 1 else None


def colour(text: str, role: Optional[str] = None) -> str:
    if Fore is None or Style is None:
        return text
    if role == "best":
        c = Fore.GREEN
    elif role == "worst":
        c = Fore.RED
    else:
        c = Fore.YELLOW
    return f"{c}{text}{Style.RESET_ALL}"


table = PrettyTable()
table.field_names = [
    "Parser",
    "Runs",
    "Wall (s)",
    "CPU (s)",
    "RSS Δ",
    "Py Peak",
    "µs/run",
    "Status",
]
table.align = "r"
table.align["Parser"] = "l"
table.align["Status"] = "l"

ordered = ok_results + others
for res in ordered:
    status = res["status"]
    label = res["label"]
    if status == "ok":
        metrics: Metrics = res["metrics"]
        if best_wall is not None and metrics.seconds == best_wall:
            role: str | None = "best"
        elif worst_wall is not None and metrics.seconds == worst_wall and best_wall != worst_wall:
            role = "worst"
        else:
            role = "mid"
        table.add_row(
            [
                colour(label, role),
                f"{res['runs']:,}",
                f"{metrics.seconds:.4f}",
                f"{metrics.cpu_seconds:.4f}",
                _format_bytes(metrics.rss_bytes),
                _format_bytes(metrics.py_peak_bytes),
                f"{res['per_us']:.1f}",
                colour("ok", role),
            ]
        )
    else:
        role = "worst" if status == "error" else "mid"
        table.add_row(
            [
                colour(label, role),
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                f"{status} ({res.get('reason', 'n/a')})",
            ]
        )

print()
print(table)
