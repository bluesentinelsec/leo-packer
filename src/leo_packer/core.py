"""
Core library for Leo Pack operations (LGPLv3).
"""

import os
import struct
from pathlib import Path
from typing import Optional
from .util import leo_crc32_ieee
from .errors import PackError
from . import pack_reader
from . import compress
from . import obfuscate

_HEADER_SIZE = 0x54
_MAGIC = b"LEOPACK\0"
_VERSION = 1

# Entry-level flags (per-file)
FLAG_COMPRESSED = 0x1

# Pack-level flags (header.pack_flags)
PACK_FLAG_OBFUSCATED = 0x1


def _xor_bytes(seed: int, data: bytes) -> bytes:
    """Return XOR'd copy using our LCG stream."""
    if not data or seed == 0:
        return data
    buf = bytearray(data)
    obfuscate.xor_stream_apply(seed, buf)
    return bytes(buf)


def pack(
    input_dir: str,
    output_file: str,
    use_compression: bool = False,
    password: Optional[str] = None,
) -> None:
    """Pack a directory into a LeoPack archive.

    If `password` is provided (non-empty), file data is obfuscated with a
    non-cryptographic XOR stream keyed from (password, pack_salt).
    """
    input_dir = Path(input_dir)
    files = [p for p in input_dir.rglob("*") if p.is_file()]

    pack_flags = 0
    # Use a fixed salt for deterministic tests; you can swap to os.urandom(8) later
    pack_salt = 0x12345678ABCDEF00

    # If obfuscation enabled, derive seed now
    password = password or None
    xor_seed = 0
    if password:
        pack_flags |= PACK_FLAG_OBFUSCATED
        xor_seed = obfuscate.xor_seed_from_password(password, pack_salt)

    # Build header placeholder
    header = bytearray(_HEADER_SIZE)
    header[0:8] = _MAGIC
    struct.pack_into("<I", header, 8, _VERSION)
    struct.pack_into("<I", header, 12, pack_flags)  # pack_flags
    struct.pack_into("<Q", header, 40, pack_salt)   # salt

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

        crc = leo_crc32_ieee(data, len(data), 0)  # CRC over *uncompressed* clear bytes
        data_chunks.append(stored)

        name_bytes = str(f.relative_to(input_dir)).encode("utf-8")
        name_len = len(name_bytes)

        entry_struct = struct.pack(
            "<HHQQQI",
            flags,
            name_len,
            offset,
            len(data),      # size_uncompressed
            len(stored),    # size_stored (post-compression, pre-xor)
            crc,
        )
        toc_chunks.append(struct.pack("<H", name_len) + name_bytes + entry_struct)

        offset += len(stored)

    toc_bytes = b"".join(toc_chunks)

    # Patch header with TOC info
    toc_offset = _HEADER_SIZE + sum(len(d) for d in data_chunks)
    struct.pack_into("<Q", header, 16, toc_offset)      # toc_offset
    struct.pack_into("<Q", header, 24, len(toc_bytes))  # toc_size
    struct.pack_into("<Q", header, 32, _HEADER_SIZE)    # data_offset

    # Compute header CRC
    tmp = bytearray(header)
    struct.pack_into("<I", tmp, 0x50, 0)
    crc_header = leo_crc32_ieee(tmp, len(header), 0)
    struct.pack_into("<I", header, 0x50, crc_header)

    # Write file: header → (optionally XOR'd) data chunks → TOC (left in clear)
    with open(output_file, "wb") as out:
        out.write(header)
        for d in data_chunks:
            if xor_seed:
                out.write(_xor_bytes(xor_seed, d))
            else:
                out.write(d)
        out.write(toc_bytes)


def unpack(input_file: str, output_dir: str, password: Optional[str] = None) -> None:
    """Unpack a LeoPack archive to a directory."""
    os.makedirs(output_dir, exist_ok=True)
    pack = pack_reader.open_pack(input_file, password=password)
    try:
        for entry in pack_reader.list_entries(pack):
            data = pack_reader.extract(pack, entry.name)
            out_path = Path(output_dir) / entry.name
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(data)
    finally:
        pack_reader.close(pack)

