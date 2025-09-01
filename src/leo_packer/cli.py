"""
CLI for leo-packer (GPLv3).
"""

import argparse
import sys
from .core import pack, unpack


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(
        prog="leo-packer",
        description="Pack and unpack Leo Pack archives"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # -------------------------
    # pack command
    # -------------------------
    p_pack = subparsers.add_parser(
        "pack", help="Pack a directory into an archive"
    )
    p_pack.add_argument("input_dir", help="Directory containing files to pack")
    p_pack.add_argument("output_file", help="Path to output .leopack file")
    p_pack.add_argument(
        "--compress",
        action="store_true",
        help="Enable compression (Deflate) when packing"
    )
    p_pack.add_argument(
        "--password",
        help="Optional password for obfuscation (XOR stream, not cryptographic)"
    )

    # -------------------------
    # unpack command
    # -------------------------
    p_unpack = subparsers.add_parser(
        "unpack", help="Unpack an archive into a directory"
    )
    p_unpack.add_argument("input_file", help="Path to .leopack file to unpack")
    p_unpack.add_argument("output_dir", help="Directory to extract contents into")
    p_unpack.add_argument(
        "--password",
        help="Optional password (required if archive was obfuscated)"
    )

    args = parser.parse_args(argv)

    if args.command == "pack":
        pack(
            args.input_dir,
            args.output_file,
            use_compression=args.compress,
            password=args.password,
        )
    elif args.command == "unpack":
        unpack(
            args.input_file,
            args.output_dir,
            password=args.password,
        )


if __name__ == "__main__":
    main()

