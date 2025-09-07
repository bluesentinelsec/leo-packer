# src/leo_packer/obfuscate.py
from . import util

try:
    from . import _xor
    _has_c_ext = True
except ImportError:
    _has_c_ext = False

def xor_seed_from_password(password: str, pack_salt: int) -> int:
    if password is None:
        password = ""
    parts = pack_salt.to_bytes(8, "little") + password.encode("utf-8")
    mix = util.fnv1a64(parts)
    seed = (mix ^ (mix >> 32)) & 0xFFFFFFFF
    if seed == 0:
        seed = 0xA5A5A5A5
    return seed

def xor_stream_apply(seed: int, data: bytearray) -> None:
    """Apply XOR stream cipher (C extension if available, else Python fallback)."""
    if seed == 0 or not data:
        return
    if _has_c_ext:
        _xor.xor_stream_apply(seed, data)
        return

    # Python fallback
    view = memoryview(data)
    x = seed & 0xFFFFFFFF
    n = len(view)
    i = 0
    while i + 4 <= n:
        x = (x * 1664525 + 1013904223) & 0xFFFFFFFF
        view[i]     ^= (x >> 24) & 0xFF
        view[i + 1] ^= (x >> 16) & 0xFF
        view[i + 2] ^= (x >> 8)  & 0xFF
        view[i + 3] ^= x & 0xFF
        i += 4
    while i < n:
        x = (x * 1664525 + 1013904223) & 0xFFFFFFFF
        view[i] ^= (x >> 24) & 0xFF
        i += 1

