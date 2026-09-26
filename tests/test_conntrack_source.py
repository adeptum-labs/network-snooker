import subprocess

import pytest

from network_snooker.conntrack_source import (
    ConntrackError,
    Endpoints,
    Flow,
    parse_line,
    parse_output,
    read_flows,
)

SNAT_TCP = (
    "ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.10 dst=93.184.216.34 "
    "sport=51234 dport=443 packets=10 bytes=1200 src=93.184.216.34 dst=203.0.113.5 "
    "sport=443 dport=51234 packets=8 bytes=9000 [ASSURED] mark=0 use=1"
)
ICMP = (
    "ipv4     2 icmp     1 29 src=203.0.113.5 dst=8.8.8.8 type=8 code=0 id=7 packets=1 "
    "bytes=84 src=8.8.8.8 dst=203.0.113.5 type=0 code=0 id=7 packets=1 bytes=84 mark=0 use=1"
)
IPV6 = (
    "ipv6     10 tcp      6 431999 ESTABLISHED src=2001:db8:1::10 dst=2606:4700::1 "
    "sport=40001 dport=443 packets=3 bytes=300 src=2606:4700::1 dst=2001:db8:1::10 "
    "sport=443 dport=40001 packets=2 bytes=2000 [ASSURED] mark=0 use=1"
)
NO_COUNTERS = (
    "ipv4     2 udp      17 29 src=192.168.1.20 dst=192.168.1.1 sport=40000 dport=53 "
    "src=192.168.1.1 dst=192.168.1.20 sport=53 dport=40000 mark=0 use=1"
)
GRE = (
    "ipv4     2 unknown  47 599 src=192.168.1.40 dst=198.51.100.9 "
    "src=198.51.100.9 dst=203.0.113.5 mark=0 use=1"
)


def test_parses_snat_tcp_flow():
    assert parse_line(SNAT_TCP) == Flow(
        protocol="tcp",
        orig=Endpoints("192.168.1.10", "93.184.216.34", 51234, 443),
        reply=Endpoints("93.184.216.34", "203.0.113.5", 443, 51234),
        orig_bytes=1200,
        orig_packets=10,
        reply_bytes=9000,
        reply_packets=8,
    )


def test_parses_ipv6_flow():
    flow = parse_line(IPV6)
    assert flow.orig.src == "2001:db8:1::10"
    assert flow.reply_bytes == 2000


def test_icmp_has_no_ports_and_keeps_id():
    flow = parse_line(ICMP)
    assert flow.orig == Endpoints("203.0.113.5", "8.8.8.8")
    assert flow.ident == 7
    assert flow.key != parse_line(ICMP.replace("id=7", "id=8")).key


def test_missing_counters_parse_as_zero():
    flow = parse_line(NO_COUNTERS)
    assert (flow.orig_bytes, flow.reply_bytes) == (0, 0)


def test_unknown_protocol_without_ports():
    flow = parse_line(GRE)
    assert flow.protocol == "unknown"
    assert flow.reply == Endpoints("198.51.100.9", "203.0.113.5")


def test_garbage_lines_are_skipped():
    assert parse_line("") is None
    assert parse_line("conntrack v1.4.7 (conntrack-tools): 3 flow entries") is None
    assert parse_output(f"{SNAT_TCP}\n\n{IPV6}\n") == [parse_line(SNAT_TCP), parse_line(IPV6)]


def fake_run(returncode=0, stdout="", stderr=""):
    def run(command, **kwargs):
        return subprocess.CompletedProcess(command, returncode, stdout, stderr)

    return run


def test_read_flows_parses_stdout():
    assert read_flows(run=fake_run(stdout=SNAT_TCP)) == [parse_line(SNAT_TCP)]


def test_read_flows_raises_on_failure():
    with pytest.raises(ConntrackError, match="Operation not permitted"):
        read_flows(run=fake_run(returncode=1, stderr="Operation not permitted"))


def test_read_flows_raises_on_timeout():
    def hang(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    with pytest.raises(ConntrackError):
        read_flows(run=hang)
