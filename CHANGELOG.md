# Changelog

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project uses [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-07-01

### Added
- `parse_wg_show` — parse `wg show <iface> dump` output into per-peer
  `WireGuardPeerTransfer` runtime counters (rx/tx bytes, latest handshake,
  endpoint, allowed IPs, persistent keepalive). Skips the interface line (never
  surfaces the private key) and the peer preshared key; parses leniently so a
  sampling caller is never broken by unexpected output. Enables bandwidth-aware
  hub-assignment sampling (Unique AWS transport plane P4.1).
- Unit tests covering interface-line skipping, secret non-exposure, typed peer
  fields, `keepalive off`, empty/interface-only input, and malformed lines.

## [0.1.0] - 2026-05-16

### Added
- `wgtools.parser` module with `WireGuardClientConfig` dataclass and
  `parse_config` / `parse_configs` functions.
- Public-key derivation from `PrivateKey` via the `wg pubkey` userspace tool.
- `wgtools` CLI with `parse` subcommand supporting single files or directories,
  human-readable and JSON output, and `-o/--output` for writing JSON to disk.
- Unit tests covering INI parsing, full-config extraction, and error paths for
  missing `PrivateKey` / `Address`.
