from __future__ import annotations

import pytest

from iotls_mole.cli import parse_redirect_ports
from iotls_mole.proxy import http_host
from iotls_mole.system import Netfilter, classify_udp


def test_http_host_variants():
    assert http_host(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n") == "example.com"
    assert http_host(b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n") == "example.com"
    assert http_host(b"POST /x HTTP/1.1\r\nhost: a.b.c\r\n\r\n") == "a.b.c"  # case-insensitive
    assert http_host(b"GET / HTTP/1.1\r\nHost: [::1]:443\r\n\r\n") is None  # IPv6 literal skipped
    assert http_host(b"no headers here") is None


def test_parse_redirect_ports():
    assert parse_redirect_ports("80,443,8883") == [80, 443, 8883]
    assert parse_redirect_ports("all") == []          # empty => all TCP
    assert parse_redirect_ports("443, 8443 ,") == [443, 8443]
    with pytest.raises(SystemExit):
        parse_redirect_ports("80,not-a-port")


def test_classify_udp():
    assert classify_udp(53, b"") == "dns"
    assert classify_udp(123, b"") == "ntp"
    assert classify_udp(5684, b"") == "coap-dtls"
    assert classify_udp(443, b"") == "quic-or-dtls"
    assert classify_udp(9999, b"") == "unknown"


def test_netfilter_delete_cmd_drops_insert_index():
    # -I CHAIN <index> ... must become -D CHAIN ... (index stripped)
    rule = ["iptables", "-I", "FORWARD", "1", "-i", "eth0", "-s", "10.0.0.5", "-j", "ACCEPT"]
    assert Netfilter._delete_cmd(rule) == ["iptables", "-D", "FORWARD", "-i", "eth0", "-s", "10.0.0.5", "-j", "ACCEPT"]


def test_netfilter_delete_cmd_append_to_delete():
    rule = ["iptables", "-t", "nat", "-A", "PREROUTING", "-i", "eth0", "-j", "REDIRECT", "--to-ports", "9900"]
    assert Netfilter._delete_cmd(rule) == ["iptables", "-t", "nat", "-D", "PREROUTING", "-i", "eth0", "-j", "REDIRECT", "--to-ports", "9900"]
