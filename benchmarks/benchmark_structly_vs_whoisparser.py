import sys
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple, MutableMapping

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
from whois_parser import WhoisParser, WhoisRecord

RSS_MULTIPLIER = 1 if sys.platform == "darwin" else 1024
tracemalloc.start()


@dataclass
class Metrics:
    seconds: float
    cpu_seconds: float
    rss_bytes: int
    py_peak_bytes: int


def _snapshot() -> Tuple[float, resource.struct_rusage, Tuple[int, int]]:
    return (
        time.perf_counter(),
        resource.getrusage(resource.RUSAGE_SELF),
        tracemalloc.get_traced_memory(),
    )


def _delta(start: Tuple[float, resource.struct_rusage, Tuple[int, int]]) -> Metrics:
    t0, r0, (_, py_peak0) = start
    t1 = time.perf_counter()
    r1 = resource.getrusage(resource.RUSAGE_SELF)
    _, py_peak1 = tracemalloc.get_traced_memory()

    wall = t1 - t0
    cpu = (r1.ru_utime + r1.ru_stime) - (r0.ru_utime + r0.ru_stime)
    rss_bytes = int(max(0.0, (r1.ru_maxrss - r0.ru_maxrss)) * RSS_MULTIPLIER)
    py_peak_bytes = max(0, py_peak1 - py_peak0)
    tracemalloc.reset_peak()
    return Metrics(wall, cpu, rss_bytes, py_peak_bytes)


def _format_bytes(num: int) -> str:
    if num <= 0:
        return "0.000 MiB"
    return f"{num / (1024 * 1024):.3f} MiB"


def benchmark(
    label: str,
    fn: Callable[..., Any],
    *,
    runs: int = 100_000,
    args: Tuple[Any, ...] = (),
    kwargs: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    kwargs = kwargs or {}
    try:
        fn(*args, **kwargs)  # warmup
    except Exception as exc:  # pragma: no cover - defensive
        return {"label": label, "status": "error", "reason": str(exc)}

    tracemalloc.reset_peak()
    start = _snapshot()
    try:
        for _ in range(runs):
            fn(*args, **kwargs)
    except Exception as exc:  # pragma: no cover - defensive
        return {"label": label, "status": "error", "reason": str(exc)}

    metrics = _delta(start)
    per_run_us = (metrics.seconds / runs) * 1e6 if runs else float("nan")
    return {
        "label": label,
        "status": "ok",
        "runs": runs,
        "metrics": metrics,
        "per_us": per_run_us,
    }


WHOIS_SAMPLE = """\
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
            unique=False,
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
            unique=False,
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
PARSER = StructlyParser(CFG, rayon_policy="never")
parser = WhoisParser()

def parse_structly(text: str) -> MutableMapping[str, Any]:
    return PARSER.parse(text)


def parse_whois_parser(text: str) -> WhoisRecord:
    return parser.parse(text, hostname="domain.com")


if __name__ == "__main__":
    if colorama_init:
        colorama_init(autoreset=True)

    runs = 100
    print(f"Benchmarking {runs:,} parses of a WHOIS record")

    structly_result = parse_structly(WHOIS_SAMPLE)
    whois_result = parse_whois_parser(WHOIS_SAMPLE)
    whois_result.raw_text = ""

    results: List[Dict[str, Any]] = []
    for label, fn in [
        ("Structly parse", parse_structly),
        ("whois-parser parse", parse_whois_parser),
    ]:
        results.append(benchmark(label, fn, runs=runs, args=(WHOIS_SAMPLE,)))

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
                role: Optional[str] = "best"
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
        elif status == "error":
            table.add_row(
                [
                    colour(label, "worst"),
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    f"error ({res['reason']})",
                ]
            )
        else:
            table.add_row(
                [
                    colour(label, "mid"),
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    f"skipped ({res['reason']})",
                ]
            )

    print()
    print(table)
