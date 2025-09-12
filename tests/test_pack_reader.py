# tests/test_pack_reader.py
import io
import os
import struct
import tempfile
import pytest

from leo_packer import pack_reader
from leo_packer.util import leo_crc32_ieee
from leo_packer.errors import PackError


def make_minimal_pack(tmp_path, filename="test.leopack"):
    path = tmp_path / filename

    # Header fields (matching C struct layout)
    magic = b"LEOPACK\0"
    version = 1
    pack_flags = 0
    toc_offset = 0  # to be patched later
    toc_size = 0    # to be patched later
    data_offset = 0  # to be patched later
    pack_salt = 0x12345678ABCDEF00
    reserved = b"\x00" * (8 * 4)

    # Header placeholder (we'll fix CRC and offsets later)
    header = bytearray(0x58)  # 88 bytes to match C struct with padding
    header[0:8] = magic
    struct.pack_into("<I", header, 8, version)
    struct.pack_into("<I", header, 12, pack_flags)
    struct.pack_into("<Q", header, 16, 0)  # toc_offset
    struct.pack_into("<Q", header, 24, 0)  # toc_size
    struct.pack_into("<Q", header, 32, 0)  # data_offset
    struct.pack_into("<Q", header, 40, pack_salt)
    header[48:48 + len(reserved)] = reserved

    # File data section
    data_bytes = b"hello world"
    data_offset = len(header)
    crc = leo_crc32_ieee(data_bytes, len(data_bytes), 0)

    # TOC entry (with proper C struct alignment)
    name = b"hello.txt"
    name_len = len(name)
    entry_struct = struct.pack(
        "<HHIQQQI4x",  # Added I for padding and 4x for trailing padding to match C struct (40 bytes)
        0,                 # flags
        name_len,          # name_len
        0,                 # 4-byte padding to align offset to 8-byte boundary
        data_offset,       # offset
        len(data_bytes),   # size_uncompressed
        len(data_bytes),   # size_stored
        crc                # crc32_uncompressed
    )

    toc_bytes = struct.pack("<H", name_len) + name + entry_struct

    toc_offset = data_offset + len(data_bytes)
    toc_size = len(toc_bytes)

    # Patch header with toc_offset, toc_size, data_offset
    struct.pack_into("<Q", header, 16, toc_offset)
    struct.pack_into("<Q", header, 24, toc_size)
    struct.pack_into("<Q", header, 32, data_offset)

    # Compute header CRC (C struct has CRC at offset 80, not 0x50)
    tmp = bytearray(header)
    struct.pack_into("<I", tmp, 80, 0)  # Zero CRC field at C struct offset
    crc_header = leo_crc32_ieee(tmp, len(header), 0)
    struct.pack_into("<I", header, 80, crc_header)  # Set CRC at C struct offset

    # Write file
    with open(path, "wb") as f:
        f.write(header)
        f.write(data_bytes)
        f.write(toc_bytes)

    return path, data_bytes


def test_open_and_extract(tmp_path):
    path, expected = make_minimal_pack(tmp_path)
    pack = pack_reader.open_pack(str(path))
    try:
        entries = pack_reader.list_entries(pack)
        assert len(entries) == 1
        assert entries[0].name == "hello.txt"
        data = pack_reader.extract(pack, "hello.txt")
        assert data == expected
    finally:
        pack_reader.close(pack)

