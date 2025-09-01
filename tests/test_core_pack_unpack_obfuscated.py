import tempfile
from pathlib import Path

from leo_packer.core import pack
from leo_packer import pack_reader
from leo_packer.errors import PackError


def test_pack_obfuscated_and_read_with_and_without_password(tmp_path):
    # Arrange
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("alpha")
    (src / "b.bin").write_bytes(b"\x00" * 1024)  # compressible

    archive = tmp_path / "arc.leopack"

    # Act: pack with compression + password
    pack(str(src), str(archive), use_compression=True, password="s3cr3t")

    # Can open without password to list entries (TOC is clear)
    p = pack_reader.open_pack(str(archive))
    try:
        entries = pack_reader.list_entries(p)
        names = sorted(e.name for e in entries)
        assert names == ["a.txt", "b.bin"]

        # But extracting without password should fail
        try:
            pack_reader.extract(p, "a.txt")
            assert False, "expected failure extracting without password"
        except PackError:
            pass
    finally:
        pack_reader.close(p)

    # Now open with correct password and extract
    p2 = pack_reader.open_pack(str(archive), password="s3cr3t")
    try:
        a = pack_reader.extract(p2, "a.txt")
        b = pack_reader.extract(p2, "b.bin")
        assert a == b"alpha"
        assert b == b"\x00" * 1024
    finally:
        pack_reader.close(p2)

    # Wrong password should fail on CRC/decompression
    p3 = pack_reader.open_pack(str(archive), password="WRONG")
    try:
        try:
            pack_reader.extract(p3, "a.txt")
            assert False, "expected failure with wrong password"
        except PackError:
            pass
    finally:
        pack_reader.close(p3)

