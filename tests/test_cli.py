import subprocess
import sys
import tempfile
from pathlib import Path


def run_cli(args, cwd=None):
    """Helper to run the CLI and capture output."""
    cmd = [sys.executable, "-m", "leo_packer.cli"] + args
    return subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, check=True
    )


def test_cli_pack_and_unpack_roundtrip(tmp_path):
    # Arrange: create input dir with files
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    (input_dir / "hello.txt").write_text("hello world")
    (input_dir / "data.bin").write_bytes(b"\x01" * 128)

    archive = tmp_path / "archive.leopack"
    output_dir = tmp_path / "output"

    # Act: pack
    run_cli(["pack", str(input_dir), str(archive), "--compress"])

    # Act: unpack
    run_cli(["unpack", str(archive), str(output_dir)])

    # Assert: files restored correctly
    assert (output_dir / "hello.txt").read_text() == "hello world"
    assert (output_dir / "data.bin").read_bytes() == b"\x01" * 128


def test_cli_help_runs():
    result = subprocess.run(
        [sys.executable, "-m", "leo_packer.cli", "--help"],
        capture_output=True,
        text=True,
    )
    assert "leo-packer" in result.stdout
    assert "pack" in result.stdout
    assert "unpack" in result.stdout


def test_cli_password_roundtrip(tmp_path):
    # Arrange
    input_dir = tmp_path / "in"
    input_dir.mkdir()
    (input_dir / "msg.txt").write_text("secret text")
    archive = tmp_path / "p.leopack"
    out_no = tmp_path / "out_no_pw"
    out_ok = tmp_path / "out_ok"

    # Pack with password
    run_cli(["pack", str(input_dir), str(archive), "--compress", "--password", "pw123"])

    # Unpack WITHOUT password should fail
    res = subprocess.run(
        [sys.executable, "-m", "leo_packer.cli", "unpack", str(archive), str(out_no)],
        capture_output=True,
        text=True,
    )
    assert res.returncode != 0

    # Unpack WITH correct password
    run_cli(["unpack", str(archive), str(out_ok), "--password", "pw123"])
    assert (out_ok / "msg.txt").read_text() == "secret text"

def test_cli_list_and_selective_unpack(tmp_path):
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    (input_dir / "a.txt").write_text("aaa")
    (input_dir / "b.txt").write_text("bbb")
    archive = tmp_path / "arc.leopack"

    # Pack
    run_cli(["pack", str(input_dir), str(archive)])

    # List contents
    res = subprocess.run(
        [sys.executable, "-m", "leo_packer.cli", "list", str(archive)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "a.txt" in res.stdout
    assert "b.txt" in res.stdout

    # Selective unpack
    out = tmp_path / "out"
    run_cli(["unpack", str(archive), str(out), "--file", "a.txt"])
    assert (out / "a.txt").read_text() == "aaa"
    assert not (out / "b.txt").exists()
