"""Tests for wgtools.parser."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from wgtools.parser import WireGuardClientConfig, parse_config, _parse_ini_value


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
