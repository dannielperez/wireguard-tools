# Changelog

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-05-16

### Added
- `wgtools.parser` module with `WireGuardClientConfig` dataclass and
  `parse_config` / `parse_configs` functions.
- Public-key derivation from `PrivateKey` via the `wg pubkey` userspace tool.
- `wgtools` CLI with `parse` subcommand supporting single files or directories,
  human-readable and JSON output, and `-o/--output` for writing JSON to disk.
- Unit tests covering INI parsing, full-config extraction, and error paths for
  missing `PrivateKey` / `Address`.
