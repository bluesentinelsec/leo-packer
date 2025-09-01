/* ==========================================================
 * File: src/leo_packer/__init__.py
 * ========================================================== */

"""
leo_packer - library for packing and unpacking Leo Pack archives.
"""

from .core import pack, unpack

__all__ = ["pack", "unpack"]



/* ==========================================================
 * File: src/leo_packer/cli.py
 * ========================================================== */

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



/* ==========================================================
 * File: src/leo_packer/compress.py
 * ========================================================== */

import zlib
from . import errors

def compress_deflate(data: bytes, level: int = 6) -> bytes:
    """
    Compress using zlib (Deflate).
    Mirrors C behavior: only returns compressed if smaller, else original.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise errors.ArgumentError("compress_deflate requires bytes-like input")

    # compress with zlib wrapper
    compressed = zlib.compress(data, level)

    # Heuristic: only accept compression if smaller
    if len(compressed) < len(data):
        return compressed
    else:
        return data

def decompress_deflate(data: bytes, expected_size: int | None = None) -> bytes:
    """
    Decompress zlib stream into bytes.
    Raises DecompressionError on failure.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise errors.ArgumentError("decompress_deflate requires bytes-like input")

    try:
        out = zlib.decompress(data)
    except zlib.error as e:
        raise errors.DecompressionError(f"zlib decompression failed: {e}") from e

    if expected_size is not None and len(out) != expected_size:
        # strict like C: mismatch is considered corruption
        raise errors.FormatError(
            f"decompressed size {len(out)} != expected {expected_size}"
        )
    return out



/* ==========================================================
 * File: src/leo_packer/core.py
 * ========================================================== */

"""
Core library for Leo Pack operations (LGPLv3).
"""

def pack(input_dir: str, output_file: str) -> None:
    """Stub pack function."""
    print(f"[stub] Packing directory {input_dir} -> {output_file}")

def unpack(input_file: str, output_dir: str) -> None:
    """Stub unpack function."""
    print(f"[stub] Unpacking archive {input_file} -> {output_dir}")



/* ==========================================================
 * File: src/leo_packer/errors.py
 * ========================================================== */

class PackError(Exception):
    """Base class for Leo Pack errors."""

LeoPackError = PackError

class ArgumentError(LeoPackError):
    pass


class CompressionError(LeoPackError):
    pass


class DecompressionError(LeoPackError):
    pass


class FormatError(LeoPackError):
    pass



/* ==========================================================
 * File: src/leo_packer/obfuscate.py
 * ========================================================== */

from . import util

def xor_seed_from_password(password: str, pack_salt: int) -> int:
    """Derive a 32-bit seed from password and salt (non-crypto)."""
    if password is None:
        password = ""
    # Mix salt and password hash using FNV-1a
    parts = pack_salt.to_bytes(8, "little") + password.encode("utf-8")
    mix = util.fnv1a64(parts)
    seed = (mix ^ (mix >> 32)) & 0xFFFFFFFF
    if seed == 0:
        seed = 0xA5A5A5A5
    return seed

def xor_stream_apply(seed: int, data: bytearray) -> None:
    """Apply XOR stream cipher (in-place)."""
    if seed == 0 or len(data) == 0:
        return

    x = seed & 0xFFFFFFFF
    for i in range(len(data)):
        x = (x * 1664525 + 1013904223) & 0xFFFFFFFF
        data[i] ^= (x >> 24) & 0xFF



/* ==========================================================
 * File: src/leo_packer/pack_reader.py
 * ========================================================== */

# src/leo_packer/pack_reader.py
import os
import struct
from dataclasses import dataclass
from typing import List

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



/* ==========================================================
 * File: src/leo_packer/util.py
 * ========================================================== */

import binascii

def fnv1a64(data: bytes) -> int:
    """64-bit FNV-1a hash"""
    h = 0xcbf29ce484222325
    prime = 0x100000001b3
    for b in data:
        h ^= b
        h = (h * prime) & 0xFFFFFFFFFFFFFFFF
    return h

def crc32_ieee(data: bytes, length: int | None = None, seed: int = 0) -> int:
    """CRC-32 IEEE (same as C implementation)."""
    if length is None:
        length = len(data)
    if length > len(data):
        raise ValueError("length exceeds buffer size")

    crc = ~seed & 0xFFFFFFFF
    for b in data[:length]:
        crc ^= b
        for _ in range(8):
            mask = -(crc & 1)
            crc = (crc >> 1) ^ (0xEDB88320 & mask)
    return (~crc) & 0xFFFFFFFF

# Alias for compatibility with C naming
leo_crc32_ieee = crc32_ieee


def align_up(v: int, a: int) -> int:
    """Round v up to nearest multiple of a."""
    return (v + (a - 1)) & ~(a - 1)



/* ==========================================================
 * File: tests/__init__.py
 * ========================================================== */



/* ==========================================================
 * File: tests/test_compress.py
 * ========================================================== */

import pytest
from leo_packer import compress, errors

def test_compress_and_decompress_roundtrip():
    data = b"The quick brown fox jumps over the lazy dog" * 10
    # allocate generous buffer
    out = compress.compress_deflate(data, level=6)
    assert isinstance(out, bytes)
    assert len(out) <= len(data) + len(data) // 10 + 64

    restored = compress.decompress_deflate(out, expected_size=len(data))
    assert restored == data

def test_compression_may_skip_if_not_smaller():
    # small, incompressible data (already "compressed")
    data = b"\x00" * 4
    out = compress.compress_deflate(data, level=6)
    # Even if it "compresses", we don't enforce smaller check here
    assert isinstance(out, bytes)

def test_bad_decompression_raises():
    bad = b"not a zlib stream"
    with pytest.raises(errors.DecompressionError):
        compress.decompress_deflate(bad, expected_size=100)



/* ==========================================================
 * File: tests/test_core.py
 * ========================================================== */

import pytest
from leo_packer import pack, unpack

def test_pack_stub(capsys):
    pack("input_dir", "output.leopack")
    captured = capsys.readouterr()
    assert "Packing directory" in captured.out

def test_unpack_stub(capsys):
    unpack("input.leopack", "output_dir")
    captured = capsys.readouterr()
    assert "Unpacking archive" in captured.out



/* ==========================================================
 * File: tests/test_obfuscate.py
 * ========================================================== */

import pytest
from leo_packer import obfuscate

def test_xor_seed_from_password_deterministic():
    salt = 0x123456789ABCDEF0
    seed1 = obfuscate.xor_seed_from_password("secret", salt)
    seed2 = obfuscate.xor_seed_from_password("secret", salt)
    assert seed1 == seed2  # deterministic
    assert seed1 != 0      # should never be zero

def test_xor_seed_from_password_empty_password():
    salt = 0xCAFEBABE12345678
    seed = obfuscate.xor_seed_from_password("", salt)
    assert seed != 0  # fallback avoids zero

def test_xor_stream_apply_roundtrip():
    seed = obfuscate.xor_seed_from_password("pw", 42)
    data = bytearray(b"hello world")
    orig = data[:]

    obfuscate.xor_stream_apply(seed, data)
    assert data != orig  # should change

    # applying again restores original
    obfuscate.xor_stream_apply(seed, data)
    assert data == orig



/* ==========================================================
 * File: tests/test_pack_reader.py
 * ========================================================== */

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
    header = bytearray(0x54)  # sizeof(leo_pack_header_v1)
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

    # TOC entry
    name = b"hello.txt"
    name_len = len(name)
    entry_struct = struct.pack(
    "<HHQQQI",
    0,                 # flags
    name_len,          # name_len
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

    # Compute header CRC
    tmp = bytearray(header)
    struct.pack_into("<I", tmp, 0x50, 0)  # zero crc field
    crc_header = leo_crc32_ieee(tmp, len(header), 0)
    struct.pack_into("<I", header, 0x50, crc_header)

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



/* ==========================================================
 * File: tests/test_util.py
 * ========================================================== */

import pytest
from leo_packer import util

def test_fnv1a64_known_values():
    assert util.fnv1a64(b"hello") == 0xa430d84680aabd0b
    assert util.fnv1a64(b"world") == 0x4f59ff5e730c8af3

def test_crc32_ieee_known_values():
    # crc32 of "hello" with seed=0 should match zlib.crc32
    import zlib
    data = b"hello"
    assert util.crc32_ieee(data) == zlib.crc32(data) & 0xFFFFFFFF

    # With seed nonzero
    assert util.crc32_ieee(b"hello", seed=12345) != util.crc32_ieee(b"hello")

def test_align_up():
    assert util.align_up(5, 4) == 8
    assert util.align_up(16, 8) == 16
    assert util.align_up(17, 8) == 24



/* ==========================================================
 * File: Makefile
 * ========================================================== */

# Makefile for leo-packer

VENV = .venv
PYTHON = $(VENV)/bin/python3
PIP = $(VENV)/bin/pip
PYTEST = $(VENV)/bin/pytest

.PHONY: venv install test clean

venv:
	python3 -m venv $(VENV)

install: venv
	$(PIP) install --upgrade pip
	$(PIP) install -e .[dev]

test: install
	$(PYTEST)

clean:
	rm -rf $(VENV) .pytest_cache .mypy_cache dist build *.egg-info



