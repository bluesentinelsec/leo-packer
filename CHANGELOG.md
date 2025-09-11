# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

