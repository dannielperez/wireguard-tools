"""WireGuard config file parser.

Parses WireGuard client .conf files and extracts the fields needed
to re-add VPN clients to a server (e.g. a router or Linux WireGuard server):

- Username (from filename)
- Interface IP (from [Interface] Address)
- Public Key (derived from PrivateKey via ``wg pubkey``)
- Pre-Shared Key (from [Peer] PresharedKey)

Also parses the live runtime status of an interface from ``wg show <iface>
dump`` into per-peer transfer counters (:func:`parse_wg_show`), for callers
that need to measure throughput (e.g. a bandwidth-aware hub-assignment sampler).
"""

from __future__ import annotations

import ipaddress
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
    m = re.search(
        rf"^\s*{re.escape(key)}\s*=\s*(.+)$", text, re.MULTILINE | re.IGNORECASE
    )
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


_HOST_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_MAX_HOSTNAME_LENGTH = 253
_MAX_ENDPOINT_PORT = 65535
_UNPARSEABLE_ENDPOINT: tuple[None, None] = (None, None)


def _is_valid_endpoint_host(host: str) -> bool:
    """Return whether ``host`` is an IPv4 address or DNS hostname."""
    try:
        return isinstance(ipaddress.ip_address(host), ipaddress.IPv4Address)
    except ValueError:
        pass

    hostname = host[:-1] if host.endswith(".") else host
    if not hostname or len(hostname) > _MAX_HOSTNAME_LENGTH:
        return False
    # A dotted, all-numeric value is intended as IPv4 and must not fall back to
    # being accepted as a DNS name after strict IP validation fails.
    labels = hostname.split(".")
    if "." in hostname and all(label.isascii() and label.isdigit() for label in labels):
        return False
    return all(_HOST_LABEL_RE.fullmatch(label) for label in hostname.lower().split("."))


def _parse_endpoint_port(value: str) -> int | None:
    """Parse a decimal WireGuard endpoint port in the valid TCP/UDP range."""
    if not value or not value.isascii() or not value.isdigit():
        return None
    port = int(value)
    return port if 1 <= port <= _MAX_ENDPOINT_PORT else None


def _parse_bracketed_endpoint(endpoint: str) -> tuple[str | None, int | None]:
    """Parse a bracketed IPv6 WireGuard endpoint."""
    match = re.fullmatch(r"\[([^][]+)\]:([^:]+)", endpoint)
    if match is None:
        return _UNPARSEABLE_ENDPOINT
    host, port_value = match.groups()
    port = _parse_endpoint_port(port_value)
    if port is None:
        return _UNPARSEABLE_ENDPOINT
    try:
        ipaddress.IPv6Address(host)
    except ValueError:
        return _UNPARSEABLE_ENDPOINT
    return host.lower(), port


def _parse_unbracketed_endpoint(endpoint: str) -> tuple[str | None, int | None]:
    """Parse an IPv4 or DNS endpoint with an optional port."""
    colon_count = endpoint.count(":")
    if colon_count == 1:
        host, port_value = endpoint.rsplit(":", 1)
        port = _parse_endpoint_port(port_value)
        if port is None:
            return _UNPARSEABLE_ENDPOINT
    elif colon_count == 0:
        host, port = endpoint, None
    else:
        return _UNPARSEABLE_ENDPOINT

    if not _is_valid_endpoint_host(host):
        return _UNPARSEABLE_ENDPOINT
    return host.lower(), port


def parse_endpoint(value: str) -> tuple[str | None, int | None]:
    """Parse a WireGuard endpoint into a normalized host and optional port.

    WireGuard renders IPv6 endpoints as ``[host]:port``. Unbracketed values
    containing multiple colons are rejected rather than guessing whether the
    final component is a port. Invalid values degrade to ``(None, None)``.
    """
    endpoint = value.strip()
    if not endpoint or endpoint.lower() == "(none)":
        return _UNPARSEABLE_ENDPOINT

    if endpoint.startswith("["):
        return _parse_bracketed_endpoint(endpoint)
    if "[" in endpoint or "]" in endpoint:
        return _UNPARSEABLE_ENDPOINT
    return _parse_unbracketed_endpoint(endpoint)


@dataclass
class WireGuardPeerTransfer:
    """Per-peer runtime transfer counters parsed from ``wg show <iface> dump``.

    Counters are cumulative byte totals since the interface came up; a caller
    derives throughput by sampling twice and dividing the delta by the interval.
    The peer's preshared key (present in the dump) is intentionally NOT captured
    — this module never surfaces secret material.
    """

    public_key: str
    endpoint: str  # "(none)" when the peer has no known endpoint yet.
    allowed_ips: str
    latest_handshake: int  # epoch seconds; 0 = never handshaked.
    transfer_rx: int  # bytes received from this peer.
    transfer_tx: int  # bytes sent to this peer.
    persistent_keepalive: int | None  # seconds; None when "off".

    @property
    def endpoint_host(self) -> str | None:
        """Normalized endpoint host, or ``None`` when it cannot be parsed."""
        return parse_endpoint(self.endpoint)[0]

    @property
    def endpoint_port(self) -> int | None:
        """Validated endpoint port, or ``None`` when absent or unparseable."""
        return parse_endpoint(self.endpoint)[1]

    def to_dict(self) -> dict:
        return {
            "public_key": self.public_key,
            "endpoint": self.endpoint,
            "endpoint_host": self.endpoint_host,
            "endpoint_port": self.endpoint_port,
            "allowed_ips": self.allowed_ips,
            "latest_handshake": self.latest_handshake,
            "transfer_rx": self.transfer_rx,
            "transfer_tx": self.transfer_tx,
            "persistent_keepalive": self.persistent_keepalive,
        }


def _parse_int(value: str, default: int = 0) -> int:
    """Parse an integer field leniently — junk degrades to ``default``.

    Catches a single exception (``ValueError``): the input is always a string
    field split from the dump, so ``int()`` can only raise ``ValueError``. A
    single exception also avoids the py3.14-vs-3.11 ``except``-tuple
    parenthesization split (this package targets ``>=3.11``).
    """
    try:
        return int(value.strip())
    except ValueError:
        return default


def parse_wg_show(dump: str) -> list[WireGuardPeerTransfer]:
    """Parse ``wg show <iface> dump`` output into per-peer transfer counters.

    The ``dump`` format is tab-separated and stable across wireguard-tools
    releases. The FIRST line describes the interface itself (private_key,
    public_key, listen_port, fwmark) and is skipped — its private key is never
    surfaced. Each subsequent line is one peer::

        public_key  preshared_key  endpoint  allowed_ips  latest_handshake
        transfer_rx  transfer_tx  persistent_keepalive

    Numeric fields parse leniently (a malformed counter degrades to 0) and lines
    with too few fields are skipped, so a caller on a sampling path is never
    broken by unexpected output. Blank lines are ignored, and dump text with no
    peers (interface line only, or empty) yields an empty list.

    Args:
        dump: stdout of ``wg show <iface> dump`` for a SINGLE interface. (The
            ``wg show all dump`` variant prefixes an interface-name column and is
            out of scope — call this per interface.)

    Returns:
        One :class:`WireGuardPeerTransfer` per peer line, in input order.
    """
    lines = [line for line in dump.splitlines() if line.strip()]
    peers: list[WireGuardPeerTransfer] = []
    # lines[0] is the interface itself (carries the private key) — skip it.
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) < 8:
            continue
        public_key, _psk, endpoint, allowed_ips, handshake, rx, tx, keepalive = fields[
            :8
        ]
        keepalive = keepalive.strip()
        peers.append(
            WireGuardPeerTransfer(
                public_key=public_key,
                endpoint=endpoint,
                allowed_ips=allowed_ips,
                latest_handshake=_parse_int(handshake),
                transfer_rx=_parse_int(rx),
                transfer_tx=_parse_int(tx),
                persistent_keepalive=(
                    None if keepalive in ("off", "") else _parse_int(keepalive)
                ),
            ),
        )
    return peers


@dataclass(frozen=True)
class WireGuardRuntimePeer:
    """Secret-free peer projection for application runtime consumers."""

    public_key: str
    endpoint: str
    allowed_ips: str
    latest_handshake: int | None
    transfer_rx: int | None
    transfer_tx: int | None
    persistent_keepalive: int | None

    @property
    def endpoint_host(self) -> str | None:
        """Normalized endpoint host, or ``None`` when it cannot be parsed."""
        return parse_endpoint(self.endpoint)[0]

    @property
    def endpoint_port(self) -> int | None:
        """Validated endpoint port, or ``None`` when absent or unparseable."""
        return parse_endpoint(self.endpoint)[1]


@dataclass(frozen=True)
class WireGuardRuntimeDump:
    """Typed, secret-free projection of a single-interface runtime dump."""

    public_key: str
    listen_port: int | None
    fwmark: str
    peers: tuple[WireGuardRuntimePeer, ...]


def _parse_optional_int(value: str) -> int | None:
    try:
        return int(value.strip())
    except ValueError:
        return None


def parse_wg_dump(dump: str) -> WireGuardRuntimeDump:
    """Parse a complete ``wg show <iface> dump`` without exposing secrets.

    The interface private key and each peer preshared key are deliberately
    skipped. Malformed numeric fields remain unknown (``None``), allowing
    application health consumers to distinguish invalid data from real zero
    counters. The existing :func:`parse_wg_show` parser remains the canonical
    peer-row parser and supplies the non-secret peer fields.
    """
    lines = [line for line in dump.splitlines() if line.strip()]
    if not lines:
        return WireGuardRuntimeDump("", None, "", ())

    interface = lines[0].split("\t")
    interface.extend([""] * (4 - len(interface)))
    peer_rows = [fields for line in lines[1:] if len(fields := line.split("\t")) >= 8]
    peers = tuple(
        WireGuardRuntimePeer(
            public_key=peer.public_key,
            endpoint=peer.endpoint,
            allowed_ips=peer.allowed_ips,
            latest_handshake=_parse_optional_int(fields[4]),
            transfer_rx=_parse_optional_int(fields[5]),
            transfer_tx=_parse_optional_int(fields[6]),
            persistent_keepalive=(
                None
                if fields[7].strip() in {"", "off"}
                else _parse_optional_int(fields[7])
            ),
        )
        for peer, fields in zip(parse_wg_show(dump), peer_rows, strict=True)
    )
    return WireGuardRuntimeDump(
        public_key=interface[1],
        listen_port=_parse_optional_int(interface[2]),
        fwmark=interface[3],
        peers=peers,
    )
