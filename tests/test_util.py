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

