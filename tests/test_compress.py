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

