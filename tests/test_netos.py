from __future__ import annotations

from iotls_mole import netos


def test_parse_linux_default_route():
    assert netos.parse_linux_default_route("default via 10.0.0.1 dev eth0 proto dhcp\n") == ("10.0.0.1", "eth0")


def test_parse_macos_default_route():
    out = "   route to: default\n  gateway: 10.119.0.1\n  interface: en0\n  flags: <UP,GATEWAY>\n"
    assert netos.parse_macos_default_route(out) == ("10.119.0.1", "en0")


def test_parse_linux_ip_cidr():
    assert netos.parse_linux_ip_cidr("    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0") == "10.0.0.5/24"
    assert netos.parse_linux_ip_cidr("no inet here") is None


def test_parse_macos_ifconfig_cidr_hex_netmask():
    assert netos.parse_macos_ifconfig_cidr("\tinet 10.119.7.100 netmask 0xffffc000 broadcast 10.119.63.255") == "10.119.7.100/18"
    assert netos.parse_macos_ifconfig_cidr("\tinet 192.168.1.5 netmask 0xffffff00 broadcast 192.168.1.255") == "192.168.1.5/24"
    assert netos.parse_macos_ifconfig_cidr("inet6 fe80::1") is None


def test_original_dst_constant_linux():
    assert netos.SO_ORIGINAL_DST == 80


def test_parse_pf_state_macos_real_format():
    # The actual macOS format observed live: `<rdr_target> <- <orig_dst> <- <client>`.
    out = (
        "No ALTQ support in kernel\n"
        "ALL tcp 127.0.0.1:9900 <- 104.20.23.154:443 <- 10.0.0.169:34832       TIME_WAIT:TIME_WAIT\n"
        "ALL tcp 127.0.0.1:9900 <- 188.40.99.226:443 <- 10.0.0.169:36500       ESTABLISHED:ESTABLISHED\n"
    )
    assert netos.parse_pf_state(out, "10.0.0.169", 9900) == ("104.20.23.154", 443)


def test_parse_pf_state_paren_form():
    # Some pf builds render the original dst in parentheses.
    out = "en0 tcp 127.0.0.1:9900 (1.1.1.1:443) <- 10.0.0.169:54321  ESTABLISHED:ESTABLISHED\n"
    assert netos.parse_pf_state(out, "10.0.0.169", 9900) == ("1.1.1.1", 443)


def test_parse_pf_state_no_match():
    out = "ALL tcp 127.0.0.1:9900 <- 8.8.8.8:443 <- 10.0.0.55:51000  ESTABLISHED:ESTABLISHED\n"
    assert netos.parse_pf_state(out, "10.0.0.169", 9900) is None
