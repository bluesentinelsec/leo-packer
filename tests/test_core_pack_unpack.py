import os
import tempfile
import pathlib
import shutil

from leo_packer.core import pack, unpack

def test_pack_and_unpack_roundtrip(tmp_path):
    # Arrange: create an input directory with files
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    (input_dir / "a.txt").write_text("hello")
    (input_dir / "b.txt").write_text("world")

    output_file = tmp_path / "archive.leopack"
    output_dir = tmp_path / "output"

    # Act: pack -> unpack
    pack(str(input_dir), str(output_file))
    unpack(str(output_file), str(output_dir))

    # Assert: files match
    assert (output_dir / "a.txt").read_text() == "hello"
    assert (output_dir / "b.txt").read_text() == "world"

