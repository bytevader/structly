from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, MutableMapping

from structly import FieldPattern, FieldSpec, Mode, ReturnShape, StructlyConfig, StructlyParser

NUCLEI_LOG = Path("tests/data/nuclei_scan.txt")

TARGET_TEMPLATES = [
    "cve/2021/CVE-2021-41773",
    "cve/2024/CVE-2024-6387",
    "exposures/configs/git-config",
    "misconfiguration/apache/directory-listing",
    "tech/wordpress/version",
    "wordpress/plugins/contact-form-7/version",
    "cloud/aws/s3-bucket-public-listing",
    "technologies/graphql/introspection",
    "ssl/weak-ciphers",
    "misconfiguration/security-headers",
]

NUCLEI_CONFIG = StructlyConfig(
    fields={
        "timestamp": FieldSpec(patterns=[FieldPattern.regex(r"^\[(?P<val>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]")]),
        "type": FieldSpec(patterns=[FieldPattern.regex(r"^\[[^\]]+\]\s+\[[^\]]+\]\s+\[(?P<val>[^\]]+)\]")]),
        "name": FieldSpec(
            patterns=[
                FieldPattern.regex(r"^\[[^\]]+\](?:\s+\[[^\]]+\]){3,}\s+(?P<val>.+)$"),
            ]
        ),
        "template_id": FieldSpec(
            patterns=[
                FieldPattern.starts_with("template-id:"),
                FieldPattern.starts_with("Template ID:"),
            ]
        ),
        "severity": FieldSpec(
            patterns=[
                FieldPattern.starts_with("severity:"),
                FieldPattern.starts_with("Severity:"),
            ]
        ),
        "host": FieldSpec(
            patterns=[
                FieldPattern.starts_with("host:"),
                FieldPattern.starts_with("Host:"),
            ]
        ),
        "matched_at": FieldSpec(
            patterns=[
                FieldPattern.starts_with("matched-at:"),
                FieldPattern.starts_with("Matched At:"),
            ]
        ),
        "tags": FieldSpec(
            patterns=[
                FieldPattern.starts_with("tags:"),
                FieldPattern.starts_with("Tags:"),
            ]
        ),
        "transport": FieldSpec(
            patterns=[FieldPattern.starts_with("transport:")],
        ),
        "snippet": FieldSpec(
            patterns=[FieldPattern.regex(r"snippet:\s*\"(?P<val>[^\"]+)\"")],
        ),
        "banner": FieldSpec(
            patterns=[FieldPattern.regex(r"banner:\s*\"(?P<val>[^\"]+)\"")],
        ),
        "generator": FieldSpec(
            patterns=[FieldPattern.regex(r"generator:\s*\"(?P<val>[^\"]+)\"")],
        ),
        "plugin_version": FieldSpec(
            patterns=[FieldPattern.regex(r"\bversion:\s*(?P<val>[0-9]+\.[0-9.]+)\b")],
        ),
        "contents": FieldSpec(
            patterns=[FieldPattern.regex(r"^\s*-\s*\"(?P<val>.+)\"$")],
            mode=Mode.all,
            return_shape=ReturnShape.list_,
        ),
        "missing_header": FieldSpec(
            patterns=[FieldPattern.regex(r"^\s*-\s*(?P<val>(?:Content|Strict|X-Frame|Permissions)[^\r\n]*)")],
            mode=Mode.all,
            unique=True,
            return_shape=ReturnShape.list_,
        ),
        "cipher": FieldSpec(
            patterns=[FieldPattern.regex(r"^\s*-\s*(?P<val>TLS_[A-Z0-9_]+)")],
            mode=Mode.all,
            unique=True,
            return_shape=ReturnShape.list_,
        ),
    }
)


def _iter_blocks(text: str):
    block: list[str] = []
    for line in text.splitlines():
        if line.startswith("[202"):
            if block:
                yield "\n".join(block).rstrip()
                block = []
            block.append(line)
        else:
            if block:
                block.append(line)
    if block:
        yield "\n".join(block).rstrip()


def _finding_blocks():
    text = NUCLEI_LOG.read_text(encoding="utf-8")
    return [blk for blk in _iter_blocks(text) if "template-id" in blk.lower()]


def _ensure_severity(result: MutableMapping[str, Any], block: str) -> None:
    if result.get("severity"):
        return
    header = block.splitlines()[0]
    tokens = re.findall(r"\[([^\]]+)\]", header)
    if len(tokens) > 1:
        result["severity"] = tokens[1].lower()


def _parse_findings() -> Dict[str, MutableMapping[str, Any]]:
    parser = StructlyParser(NUCLEI_CONFIG)
    findings: Dict[str, MutableMapping[str, Any]] = {}
    for block in _finding_blocks():
        parsed = parser.parse(block)
        template_id = parsed.get("template_id")
        if not template_id:
            continue
        _ensure_severity(parsed, block)
        findings[template_id] = parsed
    return findings


def test_nuclei_scan_extracts_expected_fields():
    findings = _parse_findings()
    assert set(TARGET_TEMPLATES).issubset(findings.keys())

    apache = findings["cve/2021/CVE-2021-41773"]
    assert apache["timestamp"] == "2025-11-08 09:42:15"
    assert apache["type"] == "http"
    assert apache["name"] == "Apache 2.4.49 Path Traversal"
    assert apache["severity"] == "high"
    assert apache["host"] == "https://demo.example.org"
    assert apache["matched_at"] == "https://demo.example.org/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd"
    assert apache["tags"] == "cve,apache,traversal"
    assert apache["snippet"].startswith("root:x:0:0:root")

    ssh = findings["cve/2024/CVE-2024-6387"]
    assert ssh["timestamp"] == "2025-11-08 09:42:15"
    assert ssh["host"] == "ssh.demo.example.org:22"
    assert ssh["matched_at"] == "ssh://ssh.demo.example.org:22"
    assert ssh["transport"] == "network"
    assert ssh["severity"] == "critical"
    assert ssh["banner"] == "SSH-2.0-OpenSSH_9.2p1 Ubuntu-2ubuntu0.1"

    git_config = findings["exposures/configs/git-config"]
    assert git_config["timestamp"] == "2025-11-08 09:42:14"
    assert git_config["type"] == "http"
    assert git_config["host"] == "https://demo.example.org/.git/config"
    assert git_config["matched_at"] == "https://demo.example.org/.git/config"
    assert git_config["name"] == ".git repository exposed"

    directory_listing = findings["misconfiguration/apache/directory-listing"]
    assert directory_listing["severity"] == "medium"
    assert directory_listing["host"] == "https://demo.example.org/static/"
    assert directory_listing["matched_at"] == "https://demo.example.org/static/"

    wordpress = findings["tech/wordpress/version"]
    assert wordpress["severity"] == "high"
    assert wordpress["generator"] == "WordPress 6.5.5"

    contact_form = findings["wordpress/plugins/contact-form-7/version"]
    assert contact_form["plugin_version"] == "5.7.5"
    assert contact_form["matched_at"] == "https://demo.example.org/wp-content/plugins/contact-form-7/readme.txt"

    s3 = findings["cloud/aws/s3-bucket-public-listing"]
    assert s3["host"] == "assets.demo.example.org"
    assert "backups/2025-10-01.tar.gz" in s3.get("contents", [])

    graphql = findings["technologies/graphql/introspection"]
    assert graphql["host"] == "https://api.demo.example.org/graphql"
    assert graphql["type"] == "http"

    ssl = findings["ssl/weak-ciphers"]
    assert ssl["severity"] == "info"
    assert ssl["cipher"] == ["TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_RC4_128_SHA"]

    headers = findings["misconfiguration/security-headers"]
    assert headers["host"] == "https://demo.example.org"
    assert headers["severity"] == "low"
    assert headers["missing_header"] == [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "Permissions-Policy",
    ]
