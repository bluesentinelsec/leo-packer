import os
import struct
from dataclasses import dataclass
from typing import List, Optional

from .util import crc32_ieee as leo_crc32_ieee
from .errors import LeoPackError as PackError


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
    f: any
    entries: List[Entry]
    pack_flags: int
    pack_salt: int


_HEADER_SIZE = 0x54
_MAGIC = b"LEOPACK\0"
_VERSION = 1


def open_pack(path: str, password: str | None = None) -> Pack:
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

    # Validate header CRC
    crc_expect, = struct.unpack_from("<I", header, 0x50)
    tmp = bytearray(header)
    struct.pack_into("<I", tmp, 0x50, 0)
    crc_actual = leo_crc32_ieee(tmp, len(header), 0)
    if crc_expect != crc_actual:
        raise PackError("Bad header CRC")

    # Load TOC
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
        flags, name_len, offset, size_uncompressed, size_stored, crc32_uncompressed = struct.unpack_from(
            "<HHQQQI", toc, p
        )
        p += struct.calcsize("<HHQQQI")

        entries.append(Entry(name, flags, size_uncompressed, size_stored, offset, crc32_uncompressed))

    return Pack(f, entries, pack_flags, pack_salt)


def close(pack: Pack):
    pack.f.close()


def list_entries(pack: Pack) -> List[Entry]:
    return pack.entries


def extract(pack: Pack, name: str) -> bytes:
    for e in pack.entries:
        if e.name == name:
            pack.f.seek(e.offset)
            data = pack.f.read(e.size_stored)
            if len(data) != e.size_stored:
                raise PackError("Truncated data")
            crc = leo_crc32_ieee(data, len(data), 0)
            if crc != e.crc32_uncompressed:
                raise PackError("CRC mismatch")
            return data
    raise PackError("Entry not found")

