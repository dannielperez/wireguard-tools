# wireguard-tools (`wgtools`)

Parse WireGuard client `.conf` files and extract the fields needed to re-add clients on the server side (e.g. a Linux WireGuard server or router gateway).

## Install

```bash
pip install -e .
# requires the `wg` userspace tool on PATH for public-key derivation
```

## Usage

### CLI

```bash
# Single file, human-readable
wgtools parse path/to/client.conf

# Directory, JSON
wgtools parse path/to/configs/ --json

# Directory, JSON written to file
wgtools parse path/to/configs/ -o clients.json
```

### Library

```python
from pathlib import Path
from wgtools.parser import parse_config, parse_configs

config = parse_config(Path("client.conf"))
print(config.username, config.interface_ip, config.public_key)

# Or parse a whole directory:
configs = parse_configs(Path("./configs"))
data = [c.to_dict() for c in configs]
```

## What gets extracted

Per `.conf`:

| Field | Source |
| --- | --- |
| `username` | filename stem |
| `interface_ip` | `[Interface] Address`, CIDR stripped |
| `public_key` | derived from `PrivateKey` via `wg pubkey` |
| `preshared_key` | `[Peer] PresharedKey` |
| `endpoint` | `[Peer] Endpoint` |
| `allowed_ips` | `[Peer] AllowedIPs` |
| `dns` | `[Interface] DNS` |

The private key is never returned in `to_dict()`.

## Requirements

- Python 3.11+
- `wireguard-tools` system package providing `wg` (used only to derive the public key from the private key)

## Development

```bash
pip install -e .
pip install pytest
pytest
```

## License

MIT — see `LICENSE`.
