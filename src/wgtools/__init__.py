"""WireGuard config file tools.

Parse client .conf files and extract server-side fields for VPN recovery.
"""

from __future__ import annotations

from .parser import WireGuardClientConfig, parse_config, parse_configs

__all__ = ["WireGuardClientConfig", "parse_config", "parse_configs"]
