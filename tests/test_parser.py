"""Tests for wgtools.parser."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from wgtools.parser import (
    parse_config,
    parse_wg_show,
    _parse_ini_value,
    _parse_int,
)


SAMPLE_CONF = """\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.200.200.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
PresharedKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
AllowedIPs = 0.0.0.0/0
Endpoint = 203.0.113.1:51820
"""


@pytest.fixture
def sample_conf(tmp_path: Path) -> Path:
    conf = tmp_path / "site-vpn.conf"
    conf.write_text(SAMPLE_CONF)
    return conf


class TestParseIniValue:
    def test_extracts_value(self):
        assert _parse_ini_value("Address = 10.0.0.1/32\n", "Address") == "10.0.0.1/32"

    def test_case_insensitive(self):
        assert _parse_ini_value("address = 10.0.0.1/32\n", "Address") == "10.0.0.1/32"

    def test_missing_key_returns_empty(self):
        assert _parse_ini_value("Something = else\n", "Address") == ""

    def test_strips_whitespace(self):
        assert _parse_ini_value("DNS =   1.1.1.1  \n", "DNS") == "1.1.1.1"


class TestParseConfig:
    def test_parses_all_fields(self, sample_conf: Path):
        with patch("wgtools.parser._derive_public_key", return_value="MOCK_PUBKEY"):
            config = parse_config(sample_conf)

        assert config.filename == "site-vpn.conf"
        assert config.username == "site-vpn"
        assert config.interface_ip == "10.200.200.2"
        assert config.public_key == "MOCK_PUBKEY"
        assert config.preshared_key == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        assert config.endpoint == "203.0.113.1:51820"
        assert config.allowed_ips == "0.0.0.0/0"
        assert config.dns == "1.1.1.1"
        assert config.private_key_present is True

    def test_missing_private_key_raises(self, tmp_path: Path):
        conf = tmp_path / "bad.conf"
        conf.write_text("[Interface]\nAddress = 10.0.0.1/32\n[Peer]\n")
        with pytest.raises(ValueError, match="missing PrivateKey"):
            parse_config(conf)

    def test_missing_address_raises(self, tmp_path: Path):
        conf = tmp_path / "bad.conf"
        conf.write_text("[Interface]\nPrivateKey = abc123\n[Peer]\n")
        with pytest.raises(ValueError, match="missing Address"):
            parse_config(conf)

    def test_to_dict(self, sample_conf: Path):
        with patch("wgtools.parser._derive_public_key", return_value="MOCK_PUBKEY"):
            config = parse_config(sample_conf)
        d = config.to_dict()
        assert d["username"] == "site-vpn"
        assert d["interface_ip"] == "10.200.200.2"
        assert d["public_key"] == "MOCK_PUBKEY"
        assert "private_key" not in d  # never expose private key

    def test_no_preshared_key(self, tmp_path: Path):
        conf = tmp_path / "nopsk.conf"
        conf.write_text(
            "[Interface]\nPrivateKey = abc123\nAddress = 10.0.0.1/32\n"
            "[Peer]\nEndpoint = 1.2.3.4:51820\n"
        )
        with patch("wgtools.parser._derive_public_key", return_value="PUB"):
            config = parse_config(conf)
        assert config.preshared_key == ""


# --- wg show <iface> dump parsing -------------------------------------------

# Realistic single-interface `wg show <iface> dump`: line 1 is the interface
# (private_key, public_key, listen_port, fwmark); each later line is one peer.
# Fields are tab-separated.
_IFACE_LINE = "\t".join(["PRIV_KEY_SECRET=", "IFACE_PUB=", "51820", "off"])
_PEER1 = "\t".join(
    [
        "PEER1_PUB=",
        "PEER1_PSK_SECRET=",
        "203.0.113.10:51820",
        "10.200.0.2/32",
        "1719800000",
        "123456",
        "654321",
        "25",
    ]
)
_PEER2 = "\t".join(
    ["PEER2_PUB=", "(none)", "(none)", "10.200.0.3/32", "0", "0", "0", "off"]
)
SAMPLE_DUMP = "\n".join([_IFACE_LINE, _PEER1, _PEER2]) + "\n"


class TestParseInt:
    def test_parses_number(self):
        assert _parse_int("42") == 42

    def test_strips_whitespace(self):
        assert _parse_int("  7 ") == 7

    def test_junk_returns_default(self):
        assert _parse_int("off") == 0
        assert _parse_int("", default=-1) == -1


class TestParseWgShow:
    def test_skips_interface_line_and_parses_peers(self):
        peers = parse_wg_show(SAMPLE_DUMP)
        assert len(peers) == 2
        # The interface's private key must never appear in the output.
        assert all(p.public_key != "IFACE_PUB=" for p in peers)
        assert "PRIV_KEY_SECRET=" not in str([p.to_dict() for p in peers])

    def test_peer_fields_typed(self):
        peer = parse_wg_show(SAMPLE_DUMP)[0]
        assert peer.public_key == "PEER1_PUB="
        assert peer.endpoint == "203.0.113.10:51820"
        assert peer.allowed_ips == "10.200.0.2/32"
        assert peer.latest_handshake == 1719800000
        assert peer.transfer_rx == 123456
        assert peer.transfer_tx == 654321
        assert peer.persistent_keepalive == 25

    def test_never_surfaces_preshared_key(self):
        peer = parse_wg_show(SAMPLE_DUMP)[0]
        d = peer.to_dict()
        assert "preshared_key" not in d
        assert "PEER1_PSK_SECRET=" not in str(d)

    def test_keepalive_off_is_none(self):
        peer2 = parse_wg_show(SAMPLE_DUMP)[1]
        assert peer2.persistent_keepalive is None
        assert peer2.latest_handshake == 0
        assert peer2.transfer_rx == 0

    def test_interface_only_yields_no_peers(self):
        assert parse_wg_show(_IFACE_LINE + "\n") == []

    def test_empty_input_yields_no_peers(self):
        assert parse_wg_show("") == []
        assert parse_wg_show("\n\n") == []

    def test_malformed_peer_line_skipped(self):
        dump = "\n".join([_IFACE_LINE, "TOO\tFEW\tFIELDS", _PEER1]) + "\n"
        peers = parse_wg_show(dump)
        assert len(peers) == 1
        assert peers[0].public_key == "PEER1_PUB="

    def test_malformed_counter_degrades_to_zero(self):
        bad = "\t".join(
            ["PB=", "(none)", "1.2.3.4:1", "10.0.0.9/32", "notanint", "x", "y", "off"]
        )
        dump = "\n".join([_IFACE_LINE, bad]) + "\n"
        peer = parse_wg_show(dump)[0]
        assert peer.latest_handshake == 0
        assert peer.transfer_rx == 0
        assert peer.transfer_tx == 0
