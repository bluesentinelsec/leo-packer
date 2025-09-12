import os
import struct
from dataclasses import dataclass
from typing import List, Optional, BinaryIO
from . import compress
from . import obfuscate

from .util import crc32_ieee as leo_crc32_ieee
from .errors import LeoPackError as PackError

# Entry-level flags
FLAG_COMPRESSED = 0x1
FLAG_OBFUSCATED = 0x2

# Pack-level flags (header.pack_flags)
PACK_FLAG_OBFUSCATED = 0x1

@dataclass
class Entry:
    name: str
    flags: int
    size_uncompressed: int
    size_stored: int
    offset: int
    crc32_uncompressed: int


@dataclass
class Pack:
    f: BinaryIO
    entries: List[Entry]
    pack_flags: int
    pack_salt: int
    password: Optional[str] = None  # stored to derive XOR stream


_HEADER_SIZE = 0x58  # 88 bytes to match C struct with padding
_MAGIC = b"LEOPACK\0"
_VERSION = 1

def open_pack(path: str, password: Optional[str] = None) -> Pack:
    f = open(path, "rb")

    header = f.read(_HEADER_SIZE)
    if len(header) != _HEADER_SIZE:
        raise PackError("Header truncated")

    magic = header[0:8]
    if magic != _MAGIC:
        raise PackError("Bad magic")

    version, pack_flags, toc_offset, toc_size, data_offset, pack_salt = struct.unpack_from(
        "<I I Q Q Q Q", header, 8
    )

    if version != _VERSION:
        raise PackError("Unsupported version")

    # Validate header CRC (C struct has CRC at offset 80)
    (crc_expect,) = struct.unpack_from("<I", header, 80)
    tmp = bytearray(header)
    struct.pack_into("<I", tmp, 80, 0)
    crc_actual = leo_crc32_ieee(tmp, len(header), 0)
    if crc_expect != crc_actual:
        raise PackError("Bad header CRC")

    # Load TOC (always in clear)
    f.seek(toc_offset)
    toc = f.read(toc_size)
    if len(toc) != toc_size:
        raise PackError("TOC truncated")

    entries: list[Entry] = []
    p = 0
    while p < toc_size:
        (nlen,) = struct.unpack_from("<H", toc, p)
        p += 2
        name = toc[p:p + nlen].decode("utf-8")
        p += nlen
        flags, name_len, padding, offset, size_uncompressed, size_stored, crc32_uncompressed = struct.unpack_from(
            "<HHIQQQI4x", toc, p  # Added 4x for trailing padding
        )
        p += struct.calcsize("<HHIQQQI4x")

        entries.append(Entry(name, flags, size_uncompressed, size_stored, offset, crc32_uncompressed))

    return Pack(f, entries, pack_flags, pack_salt, password=password)


def close(pack: Pack):
    pack.f.close()


def list_entries(pack: Pack) -> List[Entry]:
    return pack.entries


def _xor_bytes(seed: int, data: bytes) -> bytes:
    if seed == 0 or not data:
        return data
    buf = bytearray(data)
    obfuscate.xor_stream_apply(seed, buf)
    return bytes(buf)


def extract(pack: Pack, name: str) -> bytes:
    for e in pack.entries:
        if e.name == name:
            pack.f.seek(e.offset)
            data = pack.f.read(e.size_stored)
            if len(data) != e.size_stored:
                raise PackError("Truncated data")

            # Deobfuscate if this entry is obfuscated (per-entry flag takes precedence)
            needs_deobfuscation = (e.flags & FLAG_OBFUSCATED) or (pack.pack_flags & PACK_FLAG_OBFUSCATED)
            if needs_deobfuscation:
                if not pack.password:
                    raise PackError("Archive is obfuscated and requires a password")
                seed = obfuscate.xor_seed_from_password(pack.password, pack.pack_salt)
                data = _xor_bytes(seed, data)

            # Decompress if needed
            if e.flags & FLAG_COMPRESSED:
                try:
                    data = compress.decompress_deflate(data, expected_size=e.size_uncompressed)
                except Exception as ex:
                    raise PackError(f"Decompression failed for {e.name} (bad password or corrupted data): {ex}") from ex

            crc = leo_crc32_ieee(data, len(data), 0)
            if crc != e.crc32_uncompressed:
                raise PackError("CRC mismatch (bad password or corrupted data)")
            return data
    raise PackError("Entry not found")

