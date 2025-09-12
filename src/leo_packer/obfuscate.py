# src/leo_packer/obfuscate.py
import struct
from . import util

try:
    from . import _xor
    _has_c_ext = True
except ImportError:
    _has_c_ext = False

def xor_seed_from_password(password: str, pack_salt: int) -> int:
    if password is None:
        password = ""
    # Match C implementation: hash password first, then combine with salt
    password_hash = util.fnv1a64(password.encode("utf-8"))
    parts = struct.pack("<QQ", pack_salt, password_hash)
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

    # Python fallback - match C implementation: one LCG step per byte, use high byte only
    x = seed & 0xFFFFFFFF
    for i in range(len(data)):
        x = (x * 1664525 + 1013904223) & 0xFFFFFFFF
        data[i] ^= (x >> 24) & 0xFF

