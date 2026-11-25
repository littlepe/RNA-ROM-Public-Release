#!/usr/bin/python3
# Adapted from the vmlinux-to-elf project (MIT).
# Upstream: https://github.com/marin-m/vmlinux-to-elf
"""Decompress an LZ4 Legacy stream.

The ``0x184C2102`` magic is detected first, then the stream is read block by
block in 8MiB steps."""
from lz4.block import decompress
from io import BytesIO



def decompress_lz4_buffer(lz4_buffer: BytesIO):
    """Decompress an LZ4 Legacy buffer.

    Args:
        lz4_buffer: The binary stream, positioned after the ``0x184C2102`` magic.

    Returns:
        bytes: The decompressed data."""
    assert lz4_buffer.read(4) == (0x184C2102).to_bytes(
        4, 'little'
    )

    MAX_LEGACY_BLOCK_SIZE = 8 * 1024 * 1024

    uncompressed_stream = b''

    while True:
        compressed_block_size_raw = lz4_buffer.read(4)
        if len(compressed_block_size_raw) < 4:
            break

        compressed_block_size = int.from_bytes(
            compressed_block_size_raw, 'little'
        )

        compressed_block = lz4_buffer.read(compressed_block_size)
        if (
            len(compressed_block) < compressed_block_size
            or not compressed_block_size
        ):
            break

        uncompressed_block = decompress(
            compressed_block, MAX_LEGACY_BLOCK_SIZE
        )
        uncompressed_stream += uncompressed_block
        # A short block means the end of the stream
        if len(uncompressed_block) < MAX_LEGACY_BLOCK_SIZE:
            break

    return uncompressed_stream
