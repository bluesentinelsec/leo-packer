# tests/test_core_compression.py
import tempfile
from pathlib import Path
from leo_packer import core, pack_reader

def test_pack_and_unpack_with_compression(tmp_path):
    # Create input directory with a compressible file
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    data = b"A" * 1024  # highly compressible
    (input_dir / "file.txt").write_bytes(data)

    # Pack with compression enabled
    archive = tmp_path / "archive.leopack"
    core.pack(str(input_dir), str(archive), use_compression=True)

    # Unpack
    output_dir = tmp_path / "output"
    core.unpack(str(archive), str(output_dir))

    # Verify roundtrip
    out_data = (output_dir / "file.txt").read_bytes()
    assert out_data == data

    # Inspect entry flags (should be compressed)
    pack = pack_reader.open_pack(str(archive))
    try:
        entry = pack_reader.list_entries(pack)[0]
        assert entry.flags & 0x1  # FLAG_COMPRESSED
    finally:
        pack_reader.close(pack)

