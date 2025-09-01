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

