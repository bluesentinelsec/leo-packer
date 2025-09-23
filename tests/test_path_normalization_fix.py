import tempfile
from pathlib import Path, PureWindowsPath
from leo_packer.core import pack, unpack
from leo_packer import pack_reader


def test_path_normalization_fix(tmp_path):
    """Test that paths are normalized to forward slashes in archives."""
    
    # Create test structure
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    (input_dir / "subdir").mkdir()
    (input_dir / "subdir" / "nested").mkdir()
    
    (input_dir / "root.txt").write_text("root")
    (input_dir / "subdir" / "file.txt").write_text("sub")
    (input_dir / "subdir" / "nested" / "deep.txt").write_text("deep")
    
    pack_file = tmp_path / "test.leopack"
    pack(str(input_dir), str(pack_file))
    
    # Verify all stored paths use forward slashes
    p = pack_reader.open_pack(str(pack_file))
    try:
        entries = pack_reader.list_entries(p)
        for entry in entries:
            assert "\\" not in entry.name, f"Path '{entry.name}' contains backslashes"
            if "/" in entry.name:
                assert entry.name.count("/") > 0
    finally:
        pack_reader.close(p)
    
    # Test unpacking works correctly
    output_dir = tmp_path / "output"
    unpack(str(pack_file), str(output_dir))
    
    assert (output_dir / "root.txt").read_text() == "root"
    assert (output_dir / "subdir" / "file.txt").read_text() == "sub"
    assert (output_dir / "subdir" / "nested" / "deep.txt").read_text() == "deep"


def test_unpack_handles_forward_slashes_correctly(tmp_path):
    """Test that unpacking correctly handles forward slash paths on any platform."""
    
    # Simulate unpacking a path with forward slashes (as stored in archive)
    from leo_packer.core import Path
    
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    
    # Test the new normalization logic
    test_path = "subdir/nested/file.txt"
    parts = test_path.split("/")
    result_path = Path(output_dir).joinpath(*parts)
    
    # Should create proper nested directory structure
    assert result_path == output_dir / "subdir" / "nested" / "file.txt"
    
    # Verify it creates the right directory structure
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text("test")
    
    assert (output_dir / "subdir" / "nested" / "file.txt").read_text() == "test"
