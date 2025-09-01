"""
Core library for Leo Pack operations (LGPLv3).
"""

import os
import struct
from pathlib import Path
from .util import leo_crc32_ieee
from .errors import PackError
from . import pack_reader
from . import compress

_HEADER_SIZE = 0x54
_MAGIC = b"LEOPACK\0"
_VERSION = 1
FLAG_COMPRESSED = 0x1


def pack(input_dir: str, output_file: str, use_compression: bool = False) -> None:
    """Pack a directory into a LeoPack archive."""
    input_dir = Path(input_dir)
    files = [p for p in input_dir.rglob("*") if p.is_file()]

    # Build header placeholder
    header = bytearray(_HEADER_SIZE)
    header[0:8] = _MAGIC
    struct.pack_into("<I", header, 8, _VERSION)
    struct.pack_into("<I", header, 12, 0)  # pack_flags
    struct.pack_into("<Q", header, 40, 0x12345678ABCDEF00)  # salt

    # Data + TOC
    data_chunks = []
    toc_chunks = []
    offset = _HEADER_SIZE

    for f in files:
        data = f.read_bytes()
        stored = data
        flags = 0

        if use_compression:
            comp = compress.compress_deflate(data, level=6)
            if len(comp) < len(data):
                stored = comp
                flags |= FLAG_COMPRESSED

        crc = leo_crc32_ieee(data, len(data), 0)  # CRC always for uncompressed
        data_chunks.append(stored)

        name_bytes = str(f.relative_to(input_dir)).encode("utf-8")
        name_len = len(name_bytes)

        entry_struct = struct.pack(
            "<HHQQQI",
            flags,
            name_len,
            offset,
            len(data),      # size_uncompressed
            len(stored),    # size_stored
            crc,
        )
        toc_chunks.append(struct.pack("<H", name_len) + name_bytes + entry_struct)

        offset += len(stored)

    toc_bytes = b"".join(toc_chunks)

    # Patch header with toc info
    toc_offset = _HEADER_SIZE + sum(len(d) for d in data_chunks)
    struct.pack_into("<Q", header, 16, toc_offset)
    struct.pack_into("<Q", header, 24, len(toc_bytes))
    struct.pack_into("<Q", header, 32, _HEADER_SIZE)  # first data at header end

    # Compute CRC
    tmp = bytearray(header)
    struct.pack_into("<I", tmp, 0x50, 0)
    crc_header = leo_crc32_ieee(tmp, len(header), 0)
    struct.pack_into("<I", header, 0x50, crc_header)

    # Write file
    with open(output_file, "wb") as out:
        out.write(header)
        for d in data_chunks:
            out.write(d)
        out.write(toc_bytes)


def unpack(input_file: str, output_dir: str) -> None:
    """Unpack a LeoPack archive to a directory."""
    os.makedirs(output_dir, exist_ok=True)
    pack = pack_reader.open_pack(input_file)
    try:
        for entry in pack_reader.list_entries(pack):
            data = pack_reader.extract(pack, entry.name)
            out_path = Path(output_dir) / entry.name
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(data)
    finally:
        pack_reader.close(pack)

