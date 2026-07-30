"""WireGuard config file tools.

Parse client .conf files and extract server-side fields for VPN recovery.
"""

from __future__ import annotations

from .parser import (
    WireGuardClientConfig,
    WireGuardPeerTransfer,
    WireGuardRuntimeDump,
    WireGuardRuntimePeer,
    normalize_host,
    parse_config,
    parse_configs,
    parse_endpoint,
    parse_wg_dump,
    parse_wg_show,
)

__all__ = [
    "WireGuardClientConfig",
    "WireGuardPeerTransfer",
    "WireGuardRuntimeDump",
    "WireGuardRuntimePeer",
    "normalize_host",
    "parse_config",
    "parse_configs",
    "parse_endpoint",
    "parse_wg_dump",
    "parse_wg_show",
]
