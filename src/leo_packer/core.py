# ==========================================================
# File: src/leo_packer/core.py
# ==========================================================

"""
Core library for Leo Pack operations (LGPLv3).
"""

import os
import struct
from pathlib import Path
from typing import Optional, List
from .util import leo_crc32_ieee
from .errors import PackError
from . import pack_reader
from . import compress
from . import obfuscate

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

_HEADER_SIZE = 0x58  # 88 bytes to match C struct with padding
_MAGIC = b"LEOPACK\0"
_VERSION = 1

# Entry-level flags (per-file)
FLAG_COMPRESSED = 0x1
FLAG_OBFUSCATED = 0x2

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
    """Pack a directory into a LeoPack archive."""
    input_dir = Path(input_dir)
    files = [p for p in input_dir.rglob("*") if p.is_file()]

    pack_flags = 0
    pack_salt = 0x12345678ABCDEF00

    password = password or None
    xor_seed = 0
    if password:
        pack_flags |= PACK_FLAG_OBFUSCATED
        xor_seed = obfuscate.xor_seed_from_password(password, pack_salt)

    header = bytearray(_HEADER_SIZE)
    header[0:8] = _MAGIC
    struct.pack_into("<I", header, 8, _VERSION)
    struct.pack_into("<I", header, 12, pack_flags)
    struct.pack_into("<Q", header, 40, pack_salt)
    # Reserved fields (32 bytes from offset 48-79) are already zero-initialized

    data_chunks = []
    toc_chunks = []
    offset = _HEADER_SIZE

    for f in files:
        print(f"[leo-packer] Packing {f.relative_to(input_dir)}")  # 👈 feedback line
        data = f.read_bytes()
        stored = data
        flags = 0

        if use_compression:
            comp = compress.compress_deflate(data, level=6)
            if len(comp) < len(data):
                stored = comp
                flags |= FLAG_COMPRESSED

        # Set obfuscation flag if password is provided (matches C behavior)
        if password:
            flags |= FLAG_OBFUSCATED

        crc = leo_crc32_ieee(data, len(data), 0)
        data_chunks.append(stored)

        name_bytes = f.relative_to(input_dir).as_posix().encode("utf-8")
        name_len = len(name_bytes)

        entry_struct = struct.pack(
            "<HHIQQQI4x",  # Added 4x for 4 bytes trailing padding to match C struct size (40 bytes)
            flags,
            name_len,
            0,  # 4-byte padding to align offset to 8-byte boundary
            offset,
            len(data),
            len(stored),
            crc,
        )
        toc_chunks.append(struct.pack("<H", name_len) + name_bytes + entry_struct)

        offset += len(stored)

    toc_bytes = b"".join(toc_chunks)

    toc_offset = _HEADER_SIZE + sum(len(d) for d in data_chunks)
    struct.pack_into("<Q", header, 16, toc_offset)
    struct.pack_into("<Q", header, 24, len(toc_bytes))
    struct.pack_into("<Q", header, 32, _HEADER_SIZE)

    # Compute header CRC (C struct has CRC at offset 80, not 0x50)
    tmp = bytearray(header)
    struct.pack_into("<I", tmp, 80, 0)  # Zero CRC field at C struct offset
    crc_header = leo_crc32_ieee(tmp, len(header), 0)
    struct.pack_into("<I", header, 80, crc_header)  # Set CRC at C struct offset

    with open(output_file, "wb") as out:
        out.write(header)
        for d in data_chunks:
            if xor_seed:
                out.write(_xor_bytes(xor_seed, d))
            else:
                out.write(d)
        out.write(toc_bytes)


def unpack(
    input_file: str,
    output_dir: str,
    password: Optional[str] = None,
    files: Optional[List[str]] = None,
) -> None:
    """Unpack a LeoPack archive to a directory."""
    os.makedirs(output_dir, exist_ok=True)
    pack = pack_reader.open_pack(input_file, password=password)
    try:
        entries = pack_reader.list_entries(pack)
        if files:
            entries = [e for e in entries if e.name in files]

        for entry in entries:
            print(f"[leo-packer] Unpacking {entry.name}")  # 👈 feedback line
            data = pack_reader.extract(pack, entry.name)
            out_path = Path(output_dir).joinpath(*entry.name.split("/"))
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(data)
    finally:
        pack_reader.close(pack)

