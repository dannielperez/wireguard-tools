"""WireGuard config file parser.

Parses WireGuard client .conf files and extracts the fields needed
to re-add VPN clients to a server (e.g. a router or Linux WireGuard server):

- Username (from filename)
- Interface IP (from [Interface] Address)
- Public Key (derived from PrivateKey via ``wg pubkey``)
- Pre-Shared Key (from [Peer] PresharedKey)
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class WireGuardClientConfig:
    """Parsed WireGuard client config with server-side fields."""

    filename: str
    username: str
    interface_ip: str
    public_key: str
    preshared_key: str
    private_key_present: bool
    # Original fields for reference
    endpoint: str = ""
    allowed_ips: str = ""
    dns: str = ""

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "username": self.username,
            "interface_ip": self.interface_ip,
            "public_key": self.public_key,
            "preshared_key": self.preshared_key,
            "endpoint": self.endpoint,
            "allowed_ips": self.allowed_ips,
            "dns": self.dns,
        }


def _derive_public_key(private_key: str) -> str:
    """Derive public key from private key using ``wg pubkey``."""
    result = subprocess.run(
        ["wg", "pubkey"],
        input=private_key.strip(),
        capture_output=True,
        text=True,
        timeout=5,
    )
    if result.returncode != 0:
        raise RuntimeError(f"wg pubkey failed: {result.stderr.strip()}")
    return result.stdout.strip()


def _parse_ini_value(text: str, key: str) -> str:
    """Extract a value from INI-style config (case-insensitive key)."""
    m = re.search(rf"^\s*{re.escape(key)}\s*=\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
    return m.group(1).strip() if m else ""


def parse_config(path: Path) -> WireGuardClientConfig:
    """Parse a single WireGuard .conf file.

    Args:
        path: Path to the .conf file.

    Returns:
        WireGuardClientConfig with all server-side fields populated.

    Raises:
        ValueError: If required fields (PrivateKey, Address) are missing.
        RuntimeError: If ``wg pubkey`` fails.
    """
    text = path.read_text()

    # Split into sections
    sections: dict[str, str] = {}
    current_section = ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1].lower()
            sections[current_section] = ""
        elif current_section:
            sections[current_section] += line + "\n"

    iface = sections.get("interface", "")
    peer = sections.get("peer", "")

    # Extract fields
    private_key = _parse_ini_value(iface, "PrivateKey")
    address = _parse_ini_value(iface, "Address")
    dns = _parse_ini_value(iface, "DNS")
    preshared_key = _parse_ini_value(peer, "PresharedKey")
    endpoint = _parse_ini_value(peer, "Endpoint")
    allowed_ips = _parse_ini_value(peer, "AllowedIPs")

    if not private_key:
        raise ValueError(f"{path.name}: missing PrivateKey in [Interface]")
    if not address:
        raise ValueError(f"{path.name}: missing Address in [Interface]")

    # Derive public key from private key
    public_key = _derive_public_key(private_key)

    # Strip CIDR suffix from address for the Interface IP field
    interface_ip = address.split("/")[0]

    # Username from filename (strip .conf extension)
    username = path.stem

    return WireGuardClientConfig(
        filename=path.name,
        username=username,
        interface_ip=interface_ip,
        public_key=public_key,
        preshared_key=preshared_key,
        private_key_present=True,
        endpoint=endpoint,
        allowed_ips=allowed_ips,
        dns=dns,
    )


def parse_configs(directory: Path) -> list[WireGuardClientConfig]:
    """Parse all .conf files in a directory (recursive).

    Args:
        directory: Path to folder containing .conf files (searches subdirectories).

    Returns:
        List of parsed configs, sorted by filename.
    """
    configs = []
    for conf in sorted(directory.rglob("*.conf")):
        configs.append(parse_config(conf))
    return configs
