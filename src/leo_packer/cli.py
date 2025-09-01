"""
CLI for leo-packer (GPLv3).
"""

import argparse
from .core import pack, unpack

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="leo-packer",
        description="Pack and unpack Leo Pack archives"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # pack
    p_pack = subparsers.add_parser("pack", help="Pack a directory into an archive")
    p_pack.add_argument("input_dir")
    p_pack.add_argument("output_file")

    # unpack
    p_unpack = subparsers.add_parser("unpack", help="Unpack an archive into a directory")
    p_unpack.add_argument("input_file")
    p_unpack.add_argument("output_dir")

    args = parser.parse_args()

    if args.command == "pack":
        pack(args.input_dir, args.output_file)
    elif args.command == "unpack":
        unpack(args.input_file, args.output_dir)

if __name__ == "__main__":
    main()

