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

WHOIS_UK_SAMPLE = """\
# whois.nic.uk

    Domain name:
        google.co.uk

    Data validation:
        Nominet was able to match the registrant's name and address against a 3rd party data source on 24-May-2021

    Registrar:
        Markmonitor Inc. [Tag = MARKMONITOR]
        URL: https://www.markmonitor.com

    Relevant dates:
        Registered on: 14-Feb-1999
        Expiry date:  14-Feb-2026
        Last updated:  13-Jan-2025

    Registration status:
        Registered until expiry date.

    Name servers:
        dns101.register.com
        dns101.register.com
        ns2.google.com
        ns3.google.com
        ns4.google.com

    WHOIS lookup made at 11:51:57 26-Oct-2025
"""

WHOIS_CONFIG = StructlyConfig(
    fields={
        "domain": FieldSpec(
            patterns=[FieldPattern.starts_with("Domain Name:")],
        ),
        "registrar": FieldSpec(
            patterns=[FieldPattern.starts_with("Registrar:")],
        ),
        "registrar_url": FieldSpec(
            patterns=[FieldPattern.starts_with("Registrar URL:")],
        ),
        "registrar_id": FieldSpec(
            patterns=[FieldPattern.starts_with("Registrar IANA ID:")],
        ),
        "created": FieldSpec(
            patterns=[FieldPattern.starts_with("Creation Date:")],
        ),
        "updated": FieldSpec(
            patterns=[FieldPattern.starts_with("Updated Date:")],
        ),
        "expiry": FieldSpec(
            patterns=[FieldPattern.starts_with("Registry Expiry Date:")],
        ),
        "registrant_email": FieldSpec(
            patterns=[FieldPattern.regex(r"^Registrant Email:\s+(?P<val>.+)$")],
        ),
        "tech_email": FieldSpec(
            patterns=[FieldPattern.starts_with("Tech Email:")],
        ),
        "name_servers": FieldSpec(
            patterns=[FieldPattern.starts_with("Name Server:")],
            mode=Mode.all,
            unique=True,
            return_shape=ReturnShape.list_,
        ),
        "statuses": FieldSpec(
            patterns=[FieldPattern.starts_with("Status:")],
            mode=Mode.all,
            unique=True,
            return_shape=ReturnShape.list_,
        ),
    }
)


def test_whois_parsing_produces_structured_dict():
    parser = StructlyParser(WHOIS_CONFIG)

    result = parser.parse(WHOIS_SAMPLE)

    assert result["domain"] == "EXAMPLE-CONTACT.COM"
    assert result["registrar"] == "Example Registrar, Inc."
    assert result["registrar_url"] == "https://www.example-registrar.com"
    assert result["registrar_id"] == "199"
    assert result["created"] == "2010-06-18T13:45:21Z"
    assert result["updated"] == "2024-03-11T07:12:34Z"
    assert result["expiry"] == "2030-06-18T13:45:21Z"
    assert result["registrant_email"] == "noc@example-holdings.com"
    assert result["tech_email"] == "tech@example-holdings.com"
    assert result["name_servers"] == [
        "NS1.EXAMPLE.NET",
        "NS2.EXAMPLE.NET",
        "NS3.EXAMPLE.NET",
    ]
    assert result["statuses"] == [
        "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
        "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited",
        "clientRenewProhibited https://icann.org/epp#clientRenewProhibited",
    ]


WHOIS_UK_CONFIG = StructlyConfig(
    fields={
        "domain": FieldSpec(
            patterns=[FieldPattern.regex(r"Domain name:\s*(?P<val>.+)")],
        ),
        "registrar": FieldSpec(
            patterns=[
                FieldPattern.regex(r"^\s*Registrar:\s*(?P<val>.+)$"),
                FieldPattern.regex(r"^\s*(?P<val>.+\[Tag = .+\])$"),
            ],
        ),
        "registrar_url": FieldSpec(
            patterns=[FieldPattern.regex(r"^\s*URL:\s*(?P<val>\S+)")],
        ),
        "registered_on": FieldSpec(
            patterns=[FieldPattern.regex(r"Registered on:\s*(?P<val>\d{2}-[A-Za-z]{3}-\d{4})")],
        ),
        "expiry_date": FieldSpec(
            patterns=[FieldPattern.regex(r"Expiry date:\s*(?P<val>\d{2}-[A-Za-z]{3}-\d{4})")],
        ),
        "last_updated": FieldSpec(
            patterns=[FieldPattern.regex(r"Last updated:\s*(?P<val>\d{2}-[A-Za-z]{3}-\d{4})")],
        ),
        "status": FieldSpec(
            patterns=[FieldPattern.regex(r"Registration status:\s*(?P<val>.+)")],
        ),
        "name_servers": FieldSpec(
            patterns=[
                FieldPattern.regex(r"(?im)^\s*(?:Name Server:)?\s*(?P<val>.*\d+(?:\.[a-z0-9-]+)+)\s*$"),
            ],
            mode=Mode.all,
            unique=True,
            return_shape=ReturnShape.list_,
        ),
        "lookup_time": FieldSpec(
            patterns=[FieldPattern.regex(r"WHOIS lookup made at (?P<val>.*)")],
        ),
    }
)


def test_whois_uk_parsing_handles_indented_fields():
    parser = StructlyParser(WHOIS_UK_CONFIG)
    result = parser.parse(WHOIS_UK_SAMPLE)

    assert result["domain"] == "google.co.uk"
    assert result["registrar"] == "Markmonitor Inc. [Tag = MARKMONITOR]"
    assert result["registrar_url"] == "https://www.markmonitor.com"
    assert result["registered_on"] == "14-Feb-1999"
    assert result["expiry_date"] == "14-Feb-2026"
    assert result["last_updated"] == "13-Jan-2025"
    assert result["status"] == "Registered until expiry date."
    print(result["name_servers"])
    assert result["name_servers"] == [
        "dns101.register.com",
        "ns2.google.com",
        "ns3.google.com",
        "ns4.google.com",
    ]
    assert result["lookup_time"] == "11:51:57 26-Oct-2025"
