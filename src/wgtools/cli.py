"""CLI for wireguard-tools."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .parser import parse_config, parse_configs


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="wgtools",
        description="WireGuard config file tools — extract server-side fields from client .conf files",
    )
    sub = parser.add_subparsers(dest="command")

    # parse-configs command
    p_parse = sub.add_parser(
        "parse",
        help="Parse .conf files and output server-side fields",
    )
    p_parse.add_argument(
        "path",
        type=Path,
        help="Path to a .conf file or directory of .conf files",
    )
    p_parse.add_argument(
        "--json", "-j",
        action="store_true",
        dest="as_json",
        help="Output as JSON",
    )
    p_parse.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help="Save JSON output to file",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "parse":
        path: Path = args.path.resolve()

        if path.is_file():
            configs = [parse_config(path)]
        elif path.is_dir():
            configs = parse_configs(path)
        else:
            print(f"Error: {path} is not a file or directory", file=sys.stderr)
            sys.exit(1)

        if not configs:
            print(f"No .conf files found in {path}", file=sys.stderr)
            sys.exit(1)

        if args.as_json or args.output:
            data = [c.to_dict() for c in configs]
            text = json.dumps(data, indent=2)
            if args.output:
                args.output.write_text(text)
                print(f"Saved {len(configs)} config(s) to {args.output}")
            else:
                print(text)
        else:
            # Human-readable table
            for c in configs:
                print(f"{'─' * 60}")
                print(f"  File:           {c.filename}")
                print(f"  Username:       {c.username}")
                print(f"  Interface IP:   {c.interface_ip}")
                print(f"  Public Key:     {c.public_key}")
                print(f"  Pre-Shared Key: {c.preshared_key or '(none)'}")
                print(f"  Endpoint:       {c.endpoint}")
                print(f"  Allowed IPs:    {c.allowed_ips}")
            print(f"{'─' * 60}")
            print(f"\n{len(configs)} config(s) parsed")


if __name__ == "__main__":
    main()
