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

