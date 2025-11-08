from structly import FieldPattern, FieldSpec, Mode, ReturnShape, StructlyConfig, StructlyParser

SYSLOG_SAMPLE = """\
Apr 12 08:23:45 bastion sshd[1234]: Accepted publickey for deploy from 198.51.100.24 port 51234 ssh2
Apr 12 08:24:02 bastion sshd[1235]: Connection closed by authenticating user devops from 198.51.100.31 port 51235 [preauth]
Apr 12 08:45:19 bastion CRON[2222]: (deploy) CMD (/usr/local/bin/rotate_logs)
Apr 12 08:50:04 bastion systemd[1]: Started daily backup job.
Apr 12 08:55:33 bastion sudo[2345]: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/apt update
Apr 12 08:55:34 bastion sudo[2345]: pam_unix(sudo:session): session opened for user root by deploy(uid=1001)
Apr 12 08:55:37 bastion sudo[2345]: pam_unix(sudo:session): session closed for user root
Apr 12 09:02:10 bastion sshd[3456]: Accepted password for analyst from 198.51.100.42 port 51236 ssh2
Apr 12 09:05:27 bastion sshd[3520]: Received disconnect from 192.0.2.7 port 48912:11: disconnected by user
Apr 12 09:07:43 bastion sshd[3601]: Connection closed by authenticating user analyst from 198.51.100.42 port 51236 [preauth]
Apr 12 09:10:11 bastion sudo[5678]: pam_unix(sudo:session): session opened for user root by deploy(uid=1001)
Apr 12 09:11:18 bastion sudo[5678]: pam_unix(sudo:session): session closed for user root
Apr 12 09:15:02 bastion sshd[9876]: Failed password for invalid user admin from 203.0.113.45 port 41235 ssh2
Apr 12 09:16:45 bastion sshd[9880]: Received disconnect from 203.0.113.45 port 41235:11: Bye Bye [preauth]
Apr 12 09:20:00 bastion sshd[9921]: Accepted publickey for deploy from 198.51.100.24 port 51280 ssh2
Apr 12 09:25:32 bastion sudo[6021]: deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx
Apr 12 09:25:33 bastion sudo[6021]: pam_unix(sudo:session): session opened for user root by deploy(uid=1001)
Apr 12 09:25:45 bastion sudo[6021]: pam_unix(sudo:session): session closed for user root
Apr 12 09:40:12 bastion sshd[6100]: Accepted password for auditor from 198.51.100.55 port 50001 ssh2
Apr 12 09:45:09 bastion sshd[6120]: Failed password for root from 203.0.113.60 port 50022 ssh2
"""

SYSLOG_CONFIG = StructlyConfig(
    fields={
        "timestamp": FieldSpec(
            patterns=[FieldPattern.regex(r"r:^(?P<val>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")],
        ),
        "host": FieldSpec(
            patterns=[FieldPattern.regex(r"r:^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(?P<val>\S+)")],
        ),
        "process": FieldSpec(
            patterns=[FieldPattern.regex(r"r:^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+(?P<val>[a-zA-Z0-9_\-]+)\[")],
        ),
        "message": FieldSpec(
            patterns=[
                FieldPattern.regex(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+\[\d+\]:\s+(?P<val>.*)"),
                FieldPattern.starts_with("Apr"),
            ],
        ),
        "actor": FieldSpec(
            patterns=[
                FieldPattern.regex(r"^.*for\s+(?P<val>invalid user\s+[a-zA-Z0-9_\-]+)\s+from"),
                FieldPattern.regex(r"user\s+(?P<val>[a-zA-Z0-9_\-]+)"),
            ],
            mode=Mode.first,
            unique=False,
        ),
        "source_ip": FieldSpec(
            patterns=[FieldPattern.regex(r"from\s+(?P<val>\d{1,3}(?:\.\d{1,3}){3})")],
            mode=Mode.all,
            unique=True,
            return_shape=ReturnShape.list_,
        ),
    }
)


def test_syslog_parse_many_structures_each_line():
    parser = StructlyParser(SYSLOG_CONFIG)

    lines = [line for line in SYSLOG_SAMPLE.strip().splitlines()]
    results = parser.parse_many(lines)

    assert results[0]["timestamp"] == "Apr 12 08:23:45"
    assert results[0]["process"] == "sshd"
    assert results[0]["source_ip"] == ["198.51.100.24"]

    assert "session opened for user root" in results[10]["message"]
    assert results[10]["actor"] == "root"
    assert results[10]["source_ip"] == []

    assert "Failed password" in results[12]["message"]
    assert results[12]["actor"] == "invalid user admin"
    assert results[12]["source_ip"] == ["203.0.113.45"]
