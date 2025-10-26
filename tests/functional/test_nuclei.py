import pytest

pytest.importorskip("structly._structly")

from structly import (
    FieldPattern,
    FieldSpec,
    Mode,
    ReturnShape,
    StructlyConfig,
    StructlyParser,
)

NUCLEI_SAMPLE = """\
[2024-04-10 14:22:11] [info] [nuclei] [http] [medium] api.svc.example.net:443 - TLS configuration weakness detected
Template: tls-cipher-weak
Template ID: tls/cipher-weak
Severity: medium
Type: tls
Matched At: https://api.svc.example.net:443
Host: api.svc.example.net
IP: 198.51.100.42
Response Code: 200
Request Method: GET
Info: weak cipher suite offered (TLS_RSA_WITH_3DES_EDE_CBC_SHA)
Info: legacy protocol support detected (TLS 1.0)
CVE: CVE-1999-0001
Fingerprint: TLS_RSA_WITH_3DES_EDE_CBC_SHA
Remediation: Disable deprecated cipher suites and TLS 1.0 support.
Reference: https://cwe.mitre.org/data/definitions/327.html
Reference: https://nvd.nist.gov/vuln/detail/CVE-1999-0001
Tags: tls, compliance, best-practices
Matched Line: TLS_RSA_WITH_3DES_EDE_CBC_SHA
Engine: nuclei-3.2.1
Template Version: 1.4.0
"""

NUCLEI_CONFIG = StructlyConfig(
    fields={
        "timestamp": FieldSpec(
            patterns=[FieldPattern.regex(r"^\[(?P<val>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]")],
        ),
        "target": FieldSpec(
            patterns=[FieldPattern.regex(r"\] \[.*?\] \[.*?\] \[.*?\] \[.*?\] (?P<val>[^ ]+) ")],
        ),
        "finding": FieldSpec(
            patterns=[FieldPattern.regex(r"\] \[.*?\] \[.*?\] \[.*?\] \[.*?\] [^ ]+ - (?P<val>.*)")],
        ),
        "template": FieldSpec(
            patterns=[FieldPattern.starts_with("Template:")],
        ),
        "template_id": FieldSpec(
            patterns=[FieldPattern.starts_with("Template ID:")],
        ),
        "severity": FieldSpec(
            patterns=[FieldPattern.starts_with("Severity:")],
        ),
        "matched_at": FieldSpec(
            patterns=[FieldPattern.starts_with("Matched At:")],
        ),
        "host": FieldSpec(
            patterns=[FieldPattern.starts_with("Host:")],
        ),
        "ip": FieldSpec(
            patterns=[FieldPattern.starts_with("IP:")],
        ),
        "cve": FieldSpec(
            patterns=[FieldPattern.starts_with("CVE:")],
        ),
        "remediation": FieldSpec(
            patterns=[FieldPattern.starts_with("Remediation:")],
        ),
        "fingerprint": FieldSpec(
            patterns=[FieldPattern.starts_with("Fingerprint:")],
        ),
        "tags": FieldSpec(
            patterns=[FieldPattern.starts_with("Tags:")],
        ),
        "references": FieldSpec(
            patterns=[FieldPattern.starts_with("Reference:")],
            mode=Mode.all,
            unique=True,
            return_shape=ReturnShape.list_,
        ),
    }
)


def test_nuclei_finding_parses_to_rich_context():
    parser = StructlyParser(NUCLEI_CONFIG)

    result = parser.parse(NUCLEI_SAMPLE)

    assert result["timestamp"] == "2024-04-10 14:22:11"
    assert result["target"] == "api.svc.example.net:443"
    assert result["finding"] == "TLS configuration weakness detected"
    assert result["template"] == "tls-cipher-weak"
    assert result["template_id"] == "tls/cipher-weak"
    assert result["severity"] == "medium"
    assert result["matched_at"] == "https://api.svc.example.net:443"
    assert result["host"] == "api.svc.example.net"
    assert result["ip"] == "198.51.100.42"
    assert result["cve"] == "CVE-1999-0001"
    assert result["fingerprint"] == "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    assert "Disable deprecated cipher suites" in result["remediation"]
    assert result["tags"] == "tls, compliance, best-practices"
    assert result["references"] == [
        "https://cwe.mitre.org/data/definitions/327.html",
        "https://nvd.nist.gov/vuln/detail/CVE-1999-0001",
    ]
