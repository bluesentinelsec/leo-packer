#!/bin/bash

# Script to concatenate Leo pack header files into a single mega file
# Output file clearly separates each input file with a header

# Output file name
OUTPUT_FILE="leo_pack_mega.h"

# List of input header files
FILES=(
src/leo_packer/cli.py
src/leo_packer/compress.py
src/leo_packer/core.py
src/leo_packer/errors.py
src/leo_packer/__init__.py
src/leo_packer/obfuscate.py
src/leo_packer/pack_reader.py
src/leo_packer/util.py

tests/__init__.py
tests/test_cli.py
tests/test_compress.py
tests/test_core_compression.py
tests/test_core_pack_unpack_obfuscated.py
tests/test_core_pack_unpack.py
tests/test_obfuscate.py
tests/test_pack_reader.py
tests/test_util.py

Makefile
)

# Initialize or clear the output file
> "$OUTPUT_FILE"

# Function to append a file with a separator header
append_file() {
    local file="$1"
    if [ ! -f "$file" ]; then
        echo "Error: File $file not found" >&2
        return 1
    fi
    # Add separator and file header
    echo "/* ==========================================================" >> "$OUTPUT_FILE"
    echo " * File: $file" >> "$OUTPUT_FILE"
    echo " * ========================================================== */" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    # Append the file contents
    cat "$file" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
}

# Iterate through the files and append each to the output
for file in "${FILES[@]}"; do
    append_file "$file"
    if [ $? -ne 0 ]; then
        echo "Failed to process $file, continuing with next files" >&2
    fi
done

echo "Mega file created: $OUTPUT_FILE"
