# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2] - 2025-09-22

Fixes issue where archives created on Windows with backslashes couldn't be properly unpacked on POSIX systems and vice versa.

Normalize all file paths to forward slashes in archives for cross-platform compatibility

Add --version CLI flag that reads version from package metadata

Bump version to 1.0.2

## [1.0.1] - 2025-09-11

Fix C compatibility: align structs and obfuscation with leo-engine

- Update header size from 84 to 88 bytes to match C struct padding
- Fix TOC entry struct to 40 bytes with proper alignment padding
- Correct header CRC offset from 0x50 to 80 (C struct layout)
- Add per-entry FLAG_OBFUSCATED to match C behavior
- Fix password hashing to hash password first, then combine with salt
- Simplify XOR cipher to 1 LCG step per byte (not 4 bytes per step)
- Update both C extension and Python fallback implementations

Python archives are now fully compatible with C leo-engine.

## [1.0.0] - 2025-09-11

### Added
- Initial release of leo-packer
- Pack and unpack Leo Pack (`.leopack`) archives
- CLI with `pack`, `unpack`, and `list` commands
- Optional Deflate compression support
- Optional XOR-based obfuscation with password protection
- CRC32 integrity checking for all files
- Cross-platform support (Linux, macOS, Windows)
- Python 3.8+ compatibility
- Optional C extension for improved XOR performance with pure Python fallback
- Comprehensive test suite with 19 test cases
- Selective file extraction support
- Complete API documentation and usage examples

### Technical Details
- Binary format with 84-byte header structure
- Table of Contents (TOC) with per-file metadata
- Support for files up to 64-bit sizes
- Transparent compression/decompression
- Password-derived seed generation for obfuscation
- Graceful handling of build environments without C compiler

[1.0.0]: https://github.com/bluesentinelsec/leo-packer/releases/tag/v1.0.0

