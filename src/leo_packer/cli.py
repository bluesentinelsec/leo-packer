# ==========================================================
# File: src/leo_packer/cli.py
# ==========================================================

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
    p_pack.add_argument(
        "--progress",
        action="store_true",
        help="Show a progress bar"
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
    p_unpack.add_argument(
        "--file",
        action="append",
        help="Specific file(s) to extract (can be repeated). "
             "If omitted, all files are unpacked."
    )
    p_unpack.add_argument(
        "--progress",
        action="store_true",
        help="Show a progress bar"
    )

    # -------------------------
    # list command
    # -------------------------
    p_list = subparsers.add_parser(
        "list", help="List contents of an archive"
    )
    p_list.add_argument("input_file", help="Path to .leopack file")
    p_list.add_argument(
        "--password",
        help="Optional password (required if archive was obfuscated)"
    )

    # -------------------------
    # Parse and dispatch
    # -------------------------
    args = parser.parse_args(argv)

    if args.command == "pack":
        pack(
            args.input_dir,
            args.output_file,
            use_compression=args.compress,
            password=args.password,
            show_progress=args.progress,
        )

    elif args.command == "unpack":
        unpack(
            args.input_file,
            args.output_dir,
            password=args.password,
            files=args.file,
            show_progress=args.progress,
        )

    elif args.command == "list":
        from . import pack_reader
        p = pack_reader.open_pack(args.input_file, password=args.password)
        try:
            for entry in pack_reader.list_entries(p):
                print(f"{entry.name}\t{entry.size_uncompressed} bytes")
        finally:
            pack_reader.close(p)


if __name__ == "__main__":
    main()

