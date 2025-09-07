# tests/test_xor_extension.py
import pytest

import leo_packer.obfuscate as obfuscate

pytestmark = pytest.mark.skipif(
    not getattr(obfuscate, "_has_c_ext", False),
    reason="C extension (_xor) not built"
)


def test_xor_roundtrip_c_extension():
    """XOR should be reversible (applying twice restores original)."""
    seed = 0x12345678
    data = bytearray(b"hello world")

    original = bytes(data)

    obfuscate.xor_stream_apply(seed, data)
    obfuscate.xor_stream_apply(seed, data)  # apply again with same seed

    assert bytes(data) == original


def test_xor_matches_python_fallback(monkeypatch):
    """C extension output should match the pure Python fallback."""
    seed = 0xCAFEBABE
    sample = bytearray(b"The quick brown fox jumps over the lazy dog")

    # Run with C extension
    data1 = bytearray(sample)
    obfuscate.xor_stream_apply(seed, data1)

    # Force use of Python fallback
    monkeypatch.setattr(obfuscate, "_has_c_ext", False)
    data2 = bytearray(sample)
    obfuscate.xor_stream_apply(seed, data2)

    assert data1 == data2

