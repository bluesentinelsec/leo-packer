# leo-packer

**leo-packer** is a lightweight Python library and CLI for packing and unpacking **Leo Pack (`.leopack`) archives**.
It is designed for game engines and tools that need a simple, cross-platform archive format with support for:

* Directory → archive packing
* Optional **Deflate compression** (zlib)
* Optional **XOR-based obfuscation** with a password (not cryptographic)
* **CRC32 checksums** for integrity
* Selective file extraction
* Easy CLI with `pack`, `unpack`, and `list` commands

---

## 1. Introduction

Leo Pack is intended as a simple, self-contained **virtual file system format** for games and apps.
It allows you to bundle all assets into a single file and extract them later.

Unlike `.zip` or `.tar`, `.leopack` has:

* A small binary header with flags and CRCs (modeled after a C implementation).
* Transparent optional compression per file.
* Optional obfuscation to prevent casual inspection.
* A clear and predictable structure, so loaders can be written in C, Go, or other languages.

---

## 2. Installation

Install from PyPI:

```bash
pip install leo-packer
```

For development, clone the repo and install in editable mode:

```bash
git clone https://github.com/bluesentinelsec/leo-packer.git
cd leo-packer
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

---

## 3. CLI Usage

The CLI supports three commands:

### Pack

```bash
leo-packer pack <input_dir> <output.leopack> [--compress] [--password PASSWORD]
```

* Packs a directory into a `.leopack` file.
* `--compress` enables zlib/Deflate per-file compression.
* `--password` applies XOR stream obfuscation.

### Unpack

```bash
leo-packer unpack <archive.leopack> <output_dir> [--password PASSWORD] [--file NAME ...]
```

* Extracts all files by default.
* Use `--file` to extract only specific entries.
* Password is required if the archive was obfuscated.

### List

```bash
leo-packer list <archive.leopack> [--password PASSWORD]
```

* Lists archive contents without extracting.
* Shows file names and uncompressed sizes.

---

## 4. Running Tests

All tests are written in `pytest`.

To run them locally:

```bash
make test
```

This will:

* Install dev dependencies (`pytest`)
* Run the full suite across all modules

Tests include:

* CLI roundtrip
* Compression and decompression
* Obfuscation seed and XOR stream
* Core pack/unpack
* Pack reader integrity and CRCs

GitHub Actions CI runs tests automatically on Linux, macOS, and Windows for Python 3.8 and 3.11.

---

## 5. LeoPack Spec Information

Leo Pack archives use a simple binary format:

### Header (`0x54` bytes)

| Offset | Size | Field        | Notes                                  |
| ------ | ---- | ------------ | -------------------------------------- |
| 0x00   | 8    | Magic        | `"LEOPACK\0"`                          |
| 0x08   | 4    | Version      | Currently `1`                          |
| 0x0C   | 4    | Pack flags   | `0x1 = obfuscated`                     |
| 0x10   | 8    | TOC offset   | Absolute file offset                   |
| 0x18   | 8    | TOC size     | Bytes                                  |
| 0x20   | 8    | Data offset  | Usually `0x54`                         |
| 0x28   | 8    | Pack salt    | Used in password→seed derivation       |
| 0x30   | 16   | Reserved     | Zeroed for now                         |
| 0x50   | 4    | Header CRC32 | CRC32 of header with this field zeroed |

### TOC Entries

Each file is described as:

```
<u16 name_len>
<name bytes>
<flags: u16>
<name_len_dup: u16>
<offset: u64>
<size_uncompressed: u64>
<size_stored: u64>
<crc32_uncompressed: u32>
```

* `flags`: per-file (`0x1 = compressed`)
* `offset`: byte offset in archive where file data starts
* `size_uncompressed`: original size
* `size_stored`: compressed/obfuscated size
* `crc32_uncompressed`: CRC32 over clear, uncompressed data

### Data section

* File data chunks (optionally compressed + obfuscated)
* TOC always left in cleartext

---

## License

- Leo-packer is licensed under **GPLv3**.

---

