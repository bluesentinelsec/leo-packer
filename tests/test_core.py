import pytest
from leo_packer import pack, unpack

def test_pack_stub(capsys):
    pack("input_dir", "output.leopack")
    captured = capsys.readouterr()
    assert "Packing directory" in captured.out

def test_unpack_stub(capsys):
    unpack("input.leopack", "output_dir")
    captured = capsys.readouterr()
    assert "Unpacking archive" in captured.out

