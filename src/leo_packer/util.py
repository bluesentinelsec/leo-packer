import binascii
from typing import Optional

def fnv1a64(data: bytes) -> int:
    """64-bit FNV-1a hash"""
    h = 0xcbf29ce484222325
    prime = 0x100000001b3
    for b in data:
        h ^= b
        h = (h * prime) & 0xFFFFFFFFFFFFFFFF
    return h

def crc32_ieee(data: bytes, length: Optional[int] = None, seed: int = 0) -> int:
    """CRC-32 IEEE (fast C implementation)."""
    if length is None:
        length = len(data)
    # binascii.crc32 supports a 'value' arg to continue from a seed
    crc = binascii.crc32(data[:length], seed) & 0xFFFFFFFF
    return crc

# Alias for compatibility with C naming
leo_crc32_ieee = crc32_ieee


def align_up(v: int, a: int) -> int:
    """Round v up to nearest multiple of a."""
    return (v + (a - 1)) & ~(a - 1)

