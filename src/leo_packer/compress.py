import zlib
from . import errors
from typing import Optional

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

def decompress_deflate(data: bytes, expected_size: Optional[int] = None) -> bytes:
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

