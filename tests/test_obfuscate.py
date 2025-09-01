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

