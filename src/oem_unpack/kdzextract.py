#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Parsing and partition extraction of LG KDZ/DZ firmware.

The directory of the KDZ container, the chunked DZ images and the embedded GPT
are parsed, the partitions are written after a zlib or zstd decompression and
the metadata that is needed to pack them again can be written as well:
    rawprogramN.xml, the .params of a partition and the .dz.params."""

from __future__ import print_function

import hashlib
import io
import os
import zlib
from binascii import crc32, b2a_hex
from collections import OrderedDict
from struct import Struct
from uuid import UUID

import threading

try:
    from . import listing
except ImportError:
    import listing

try:
    from concurrent.futures import ThreadPoolExecutor
except Exception:
    ThreadPoolExecutor = None

_KDZ_TLS = threading.local()


def _extract_threads():
    """Resolve the number of threads used for the extraction.

    Reads RNA_THREADS/DNA_THREADS and falls back to the CPU count.

    Returns:
        int: The thread count."""
    raw = os.getenv("RNA_THREADS") or os.getenv("DNA_THREADS") or os.getenv("WORK_THREADS") or ""
    try:
        count = int(float(raw))
    except (TypeError, ValueError):
        count = 0
    if count <= 0:
        count = max(1, os.cpu_count() or 2)
    return count

try:
    from pyzstd import ZstdDecompressor
except Exception:
    ZstdDecompressor = None

READ_SIZE = 1 << 20
# The DZ header magic: 0x32 0x96 0x18 0x74, it marks a standalone DZ or a payload inside a KDZ.
DZ_FILE_MAGIC = b"\x32\x96\x18\x74"


class DZStruct(object):
    """The base class that packs and unpacks the fixed size DZ and KDZ structs.

    A little endian Struct is built from the _dz_format_dict of the subclass and
    the fields that may be left out are remembered."""

    _dz_length = 512

    def __init__(self, classy):
        """Bind the format table of the subclass and check the size of the struct.

        Args:
            classy: The subclass.

        Raises:
            RuntimeError: When the computed size does not match the declared one."""
        try:
            classy._dzstruct
        except AttributeError:
            classy._dz_struct = Struct(
                "<" + "".join([x[0] for x in classy._dz_format_dict.values()])
            )
            if self._dz_struct.size != self._dz_length:
                raise RuntimeError(
                    "DZ chunk format wrong! (computed={:d}, specified={:d})".format(
                        self._dz_struct.size, self._dz_length
                    )
                )
        try:
            classy._dz_collapsibles
        except AttributeError:
            classy._dz_collapsibles = [
                n for n, (y, p) in classy._dz_format_dict.items() if p
            ]

    def packdict(self, din):
        """Pack a field dictionary into a fixed size binary header.

        Args:
            din: The field dictionary.

        Returns:
            bytes: The header."""
        dout = dict()
        for k in self._dz_format_dict.keys():
            if self._dz_format_dict[k][0][-1] == "s":
                l = int(self._dz_format_dict[k][0][:-1])
                dout[k] = (din[k] if k in din else b"").ljust(l, b"\x00")
            elif k not in din and k in self._dz_collapsibles:
                dout[k] = 0
            else:
                dout[k] = din[k]
        dout["header"] = self._dz_header
        values = [dout[k] for k in self._dz_format_dict.keys()]
        return self._dz_struct.pack(*values)

    def unpackdict(self, buffer):
        """Unpack a field dictionary from a buffer.

        Args:
            buffer: The fixed size header.

        Returns:
            dict: The field dictionary, None when the magic does not match."""
        d = dict(
            zip(self._dz_format_dict.keys(), self._dz_struct.unpack(buffer))
        )
        if d["header"] != self._dz_header:
            return None
        return d


class DZChunk(DZStruct):
    """The 512 byte header of a DZ chunk.

    It describes the slice name, the chunk name, the target sector, the size of
    the compressed data, the MD5 and the CRC32."""

    _dz_area = "chunk"
    # The chunk header magic: 0x30 0x12 0x95 0x78.
    _dz_header = b"\x30\x12\x95\x78"
    # The chunk header layout: header(4s) sliceName(32s) chunkName(64s) targetSize/dataSize
    # md5(16s) targetAddr/trimCount/dev/crc32, the remaining 372 bytes are padding.
    _dz_format_dict = OrderedDict(
        [
            ("header", ("4s", False)),
            ("sliceName", ("32s", True)),
            ("chunkName", ("64s", True)),
            ("targetSize", ("I", False)),
            ("dataSize", ("I", False)),
            ("md5", ("16s", False)),
            ("targetAddr", ("I", False)),
            ("trimCount", ("I", False)),
            ("dev", ("I", False)),
            ("crc32", ("I", False)),
            ("pad", ("372s", True)),
        ]
    )

    def __init__(self):
        "Start the description of the chunk struct."
        super(DZChunk, self).__init__(DZChunk)


class DZFile(DZStruct):
    """The 512 byte header of a DZ file.

    It holds the format version, the device name, the number of chunks, the MD5 of
    the header and the Android version."""

    _dz_area = "file"
    # The file header magic, the same as DZ_FILE_MAGIC.
    _dz_header = b"\x32\x96\x18\x74"
    # The DZ header layout: header/formatMajor/formatMinor, the device and version strings,
    # chunkCount, md5 and a few unknown or reserved fields, 512 bytes in total.
    _dz_format_dict = OrderedDict(
        [
            ("header", ("4s", False)),
            ("formatMajor", ("I", False)),
            ("formatMinor", ("I", False)),
            ("reserved0", ("I", True)),
            ("device", ("32s", True)),
            ("version", ("144s", True)),
            ("chunkCount", ("I", False)),
            ("md5", ("16s", False)),
            ("unknown0", ("I", False)),
            ("reserved1", ("I", True)),
            ("reserved4", ("H", True)),
            ("unknown1", ("16s", False)),
            ("unknown2", ("50s", True)),
            ("buildType", ("20s", True)),
            ("unknown3", ("4s", False)),
            ("androidVer", ("10s", True)),
            ("oldDateCode", ("10s", True)),
            ("reserved5", ("I", False)),
            ("unknown4", ("I", False)),
            ("unknown5", ("I", False)),
            ("unknown6", ("64s", False)),
            ("unknown7", ("32s", False)),
            ("unknown8", ("8s", False)),
            ("pad", ("64s", True)),
        ]
    )

    def __init__(self):
        "Start the description of the DZ file header struct."
        super(DZFile, self).__init__(DZFile)


class KDZFile(DZStruct):
    """A KDZ directory entry: the file name, the length and the offset.

    Every entry is 272 bytes, the container starts with another 8 byte magic
    that is not part of this struct."""

    _dz_length = 272
    # The magic fragments of the KDZ v2 directory (the full container magic is in KDZ_HEADERS).
    _dz_header = b"\x28\x05\x00\x00" b"\x24\x38\x22\x25"
    # The directory entry layout: name(256s) length(Q) offset(Q).
    _dz_format_dict = OrderedDict(
        [
            ("name", ("256s", True)),
            ("length", ("Q", False)),
            ("offset", ("Q", False)),
        ]
    )

    def __init__(self):
        "Start the description of the KDZ directory entry struct."
        super(KDZFile, self).__init__(KDZFile)


class NoGPT(Exception):
    "The GPT could not be parsed or the check failed."

    def __init__(self, errmsg):
        """Store the error message.

        Args:
            errmsg: The text of the error."""
        self.errmsg = errmsg

    def __str__(self):
        """Return the text of the exception.

        Returns:
            str: The text of the error."""
        return self.errmsg


class GPTSlice(object):
    "One entry of the GPT partition table (an EFI partition entry)."

    # The GPT entry layout: type/uuid(16s) startLBA/endLBA/flags(Q) name(72s UTF-16LE).
    _gpt_slice_fmt = OrderedDict(
        [
            ("type", ("16s")),
            ("uuid", ("16s")),
            ("startLBA", ("Q")),
            ("endLBA", ("Q")),
            ("flags", ("Q")),
            ("name", ("72s")),
        ]
    )
    _gpt_struct = Struct("<" + "".join([x for x in _gpt_slice_fmt.values()]))

    def __init__(self, buf):
        """Parse a partition entry from a 128 byte buffer.

        Args:
            buf: The bytes of the GPT entry."""
        data = dict(
            zip(self._gpt_slice_fmt.keys(), self._gpt_struct.unpack(buf))
        )
        self.type = UUID(bytes=data["type"])
        self.uuid = UUID(bytes=data["uuid"])
        self.startLBA = data["startLBA"]
        self.endLBA = data["endLBA"]
        self.flags = data["flags"]
        self.name = data["name"].decode("utf16").rstrip("\x00")


class GPT(object):
    "Parse the primary and the backup GPT header and the partition entries."

    # The GPT header signature "EFI PART".
    _gpt_header = b"EFI PART"
    _gpt_size = 0x5C
    # The GPT header layout: header/revision/headerSize/crc32/reserved,
    # myLBA/altLBA/dataStartLBA/dataEndLBA、uuid、entryStart/Count/Size/Crc32。
    _gpt_head_fmt = OrderedDict(
        [
            ("header", ("8s")),
            ("revision", ("I")),
            ("headerSize", ("I")),
            ("crc32", ("I")),
            ("reserved", ("I")),
            ("myLBA", ("Q")),
            ("altLBA", ("Q")),
            ("dataStartLBA", ("Q")),
            ("dataEndLBA", ("Q")),
            ("uuid", ("16s")),
            ("entryStart", ("Q")),
            ("entryCount", ("I")),
            ("entrySize", ("I")),
            ("entryCrc32", ("I")),
        ]
    )
    _gpt_struct = Struct("<" + "".join([x for x in _gpt_head_fmt.values()]))

    def tryParseHeader(self, buf):
        """Try to parse a GPT header and check its CRC.

        Args:
            buf: The header buffer.

        Returns:
            dict: The header fields, None when the signature or the CRC does not
            match.

        Raises:
            NoGPT: When the buffer is smaller than a GPT header."""
        if len(buf) < self._gpt_size:
            raise NoGPT("Failed to locate GPT")
        data = dict(
            zip(
                self._gpt_head_fmt.keys(),
                self._gpt_struct.unpack(buf[0 : self._gpt_size]),
            )
        )
        if data["header"] != self._gpt_header:
            return None
        tmp = data["crc32"]
        data["crc32"] = 0
        crc = crc32(
            self._gpt_struct.pack(*[data[k] for k in self._gpt_head_fmt.keys()])
        )
        data["crc32"] = tmp
        crc = crc32(buf[self._gpt_size : data["headerSize"]], crc)
        crc &= 0xFFFFFFFF
        if crc != data["crc32"]:
            return None
        return data

    def __init__(self, buf, type=None, lbaMinShift=9, lbaMaxShift=16):
        """Detect the LBA size in a buffer and load the GPT.

    The sector sizes 2^shift are tried one after another, a valid GPT header is
    looked for in the first sector or at the end of the image and the partition
    entries are read and their CRC checked.

    Args:
        buf: The image data.
        type: Kept for the callers.
        lbaMinShift: The first shift of the sector size.
        lbaMaxShift: The last shift of the sector size.

    Raises:
        NoGPT: When no valid GPT is found, the version is wrong or the partition
            table CRC fails."""
        if self._gpt_struct.size != self._gpt_size:
            raise NoGPT("GPT format string wrong!")
        shiftLBA = lbaMinShift
        shiftLBA -= 1
        data = None
        while shiftLBA < lbaMaxShift:
            shiftLBA += 1
            lbaSize = 1 << shiftLBA
            hbuf = buf[lbaSize : lbaSize << 1]
            data = self.tryParseHeader(hbuf)
            if data:
                break
            hbuf = buf[-lbaSize:]
            data = self.tryParseHeader(hbuf)
            if data:
                break
        else:
            raise NoGPT("Failed to locate GPT")

        self.shiftLBA = shiftLBA
        self.revision = data["revision"]
        self.headerSize = data["headerSize"]
        self.reserved = data["reserved"]
        self.myLBA = data["myLBA"]
        self.altLBA = data["altLBA"]
        self.dataStartLBA = data["dataStartLBA"]
        self.dataEndLBA = data["dataEndLBA"]
        self.uuid = UUID(bytes=data["uuid"])
        self.entryStart = data["entryStart"]
        self.entryCount = data["entryCount"]
        self.entrySize = data["entrySize"]
        self.entryCrc32 = data["entryCrc32"]

        if self.revision >> 16 != 1:
            raise NoGPT("Error: GPT major version isn't 1")
        if (self.myLBA != 1) and (self.altLBA != 1):
            raise NoGPT("Error: No GPT at LBA 1 ?!")
        if self.entrySize & (self.entrySize - 1):
            raise NoGPT("Error: entry size is not a power of 2")

        if self.myLBA == 1:
            sliceAddr = self.entryStart << self.shiftLBA
        else:
            sliceAddr = (self.entryStart - self.myLBA - 1) << self.shiftLBA

        self.slices = []
        crc = 0
        for i in range(self.entryCount):
            sbuf = buf[sliceAddr : sliceAddr + self.entrySize]
            crc = crc32(sbuf, crc)
            self.slices.append(GPTSlice(sbuf))
            sliceAddr += self.entrySize
        crc &= 0xFFFFFFFF
        if crc != self.entryCrc32:
            raise NoGPT("Error: bad slice entry CRC")

        last = 0
        self.ordered = True
        for slice in self.slices:
            if slice.type == UUID(int=0):
                continue
            if slice.startLBA <= last:
                self.ordered = False
                break
            last = slice.endLBA


class DzError(Exception):
    "The DZ or KDZ could not be parsed or decompressed."

    pass


class LimitedReader(object):
    "A wrapper around a file that limits how many bytes can still be read."

    def __init__(self, fp, remaining):
        """Bind the underlying stream and the number of bytes that are left.

        Args:
            fp: The file object below.
            remaining: The number of bytes that can still be read."""
        self._fp = fp
        self._remaining = remaining

    def readable(self):
        """State that the object can be read.

        Returns:
            bool: Always True."""
        return True

    def read(self, n=-1):
        """Read at most n bytes.

    The read never goes past the quota that is left.

        Args:
            n: The number of bytes, a negative value reads the rest.

        Returns:
            bytes: The data that was read."""
        if self._remaining <= 0:
            return b""
        if n is None or n < 0:
            n = self._remaining
        n = min(n, self._remaining)
        data = self._fp.read(n)
        self._remaining -= len(data)
        return data


class WindowIO(object):
    "Map a continuous range of a file to a stream that can be read on its own."

    def __init__(self, path, start=0, length=None):
        """Open a file and limit the window to a start and a length.

        Args:
            path: The file path.
            start: The start offset of the window.
            length: The length of the window, to the end of the file by default."""
        self._fp = open(path, "rb")
        self._start = int(start or 0)
        if length is None:
            self._fp.seek(0, os.SEEK_END)
            self._length = self._fp.tell() - self._start
        else:
            self._length = int(length)
        self._pos = 0

    def seek(self, offset, whence=os.SEEK_SET):
        """Move the read pointer inside the window.

        Args:
            offset: The offset.
            whence: The base position.

        Returns:
            int: The new position.

        Raises:
            ValueError: When whence is not valid."""
        if whence == os.SEEK_SET or whence == io.SEEK_SET:
            self._pos = offset
        elif whence == os.SEEK_CUR or whence == io.SEEK_CUR:
            self._pos += offset
        elif whence == os.SEEK_END or whence == io.SEEK_END:
            self._pos = self._length + offset
        else:
            raise ValueError("bad whence")
        if self._pos < 0:
            self._pos = 0
        return self._pos

    def tell(self):
        """Return the current offset inside the window.

        Returns:
            int: The position."""
        return self._pos

    def read(self, n=-1):
        """Read data from the current position of the window.

        Args:
            n: The number of bytes, a negative value reads to the end of the
                window.

        Returns:
            bytes: The data that was read."""
        if self._pos >= self._length:
            return b""
        self._fp.seek(self._start + self._pos)
        if n is None or n < 0:
            n = self._length - self._pos
        n = min(n, self._length - self._pos)
        data = self._fp.read(n)
        self._pos += len(data)
        return data

    def close(self):
        "Close the file below."
        self._fp.close()

    def __enter__(self):
        """Support the with statement.

    Returns:
        WindowIO: The object itself."""
        return self

    def __exit__(self, *args):
        """Close the file when the with block ends.

        Args:
            args: The exception information.

        Returns:
            bool: Always False, the exception is not swallowed."""
        self.close()
        return False


def _is_zlib(header):
    """Tell from the first byte whether the data is zlib compressed.

    Args:
        header: The header of the data.

    Returns:
        bool: True when the first byte is 0x78."""
    return len(header) >= 1 and header[0:1] == b"\x78"


def _iter_decompressed(fp, offset, size):
    """Decompress the payload of a DZ chunk block by block.

    Zlib is tried first, the newer zstd DZ files need pyzstd.

    Args:
        fp: The data stream.
        offset: The offset of the payload.
        size: The length of the payload.

    Yields:
        bytes: The decompressed blocks.

    Raises:
        DzError: When zstd is needed but pyzstd is not available."""
    fp.seek(offset, io.SEEK_SET)
    magic = fp.read(2)
    fp.seek(offset, io.SEEK_SET)
    if _is_zlib(magic):
        obj = zlib.decompressobj()
        left = size
        while left > 0:
            piece = fp.read(min(READ_SIZE, left))
            if not piece:
                break
            left -= len(piece)
            out = obj.decompress(piece)
            if out:
                yield out
        tail = obj.flush()
        if tail:
            yield tail
        return
    if ZstdDecompressor is None:
        raise DzError("pyzstd is needed to decompress the newer LG DZ (zstandard)")
    dctx = ZstdDecompressor()
    limited = LimitedReader(fp, size)
    reader = None
    if hasattr(dctx, "stream_reader"):
        try:
            reader = dctx.stream_reader(limited)
        except Exception:
            reader = None
    if reader is not None:
        while True:
            block = reader.read(READ_SIZE)
            if not block:
                break
            yield block
        return
    zdata = limited.read(size)
    buf = dctx.decompress(zdata)
    if buf:
        yield buf


def _decompress_all(fp, offset, size):
    """Decompress the whole payload of a DZ chunk.

    Args:
        fp: The data stream.
        offset: The offset of the payload.
        size: The length of the payload.

    Returns:
        bytes: The decompressed data."""
    return b"".join(_iter_decompressed(fp, offset, size))


def _bname(value):
    """Turn bytes or a plain value into a readable name.

    Args:
        value: The value of the name.

    Returns:
        str: The name without the trailing NUL."""
    if isinstance(value, bytes):
        return value.rstrip(b"\x00").decode("utf-8", "replace")
    return str(value or "")


def _hex(value):
    """Turn bytes into a hex string.

    Args:
        value: The bytes or a plain value.

    Returns:
        str: The hex text."""
    if isinstance(value, bytes):
        return b2a_hex(value).decode("ascii")
    return str(value or "")


class UNDZUtils(object):
    "The tool that reads the DZ header and trims the fields that may be left out."

    def loadHeader(self, file):
        """Read and unpack the fixed size header of the current struct.

        Args:
            file: The data stream.

        Returns:
            dict: The header fields.

        Raises:
            DzError: When the header is truncated, the magic is wrong or a field
                is off."""
        buffer = file.read(self._dz_length)
        if len(buffer) < self._dz_length:
            raise DzError("truncated DZ {} header".format(self._dz_area))
        dz_item = self.unpackdict(buffer)
        if dz_item is None:
            raise DzError("bad DZ {} header".format(self._dz_area))
        dz_item["buffer"] = buffer
        for key in self._dz_collapsibles:
            val = dz_item[key]
            if isinstance(val, (bytes, str)):
                dz_item[key] = val.rstrip(b"\x00") if isinstance(val, bytes) else val.rstrip("\x00")
            elif isinstance(val, int):
                pass
            else:
                raise DzError("internal header error")
        return dz_item


class UNDZChunk(DZChunk, UNDZUtils):
    "One chunk of an opened DZ."

    def __init__(self, dzfile, file):
        """Read the chunk header at the current position and note the offset of
        the data.

        Args:
            dzfile: The UNDZFile it belongs to.
            file: The data stream."""
        super(UNDZChunk, self).__init__()
        self.dz = dzfile
        dz_item = self.loadHeader(file)
        self.messages = []
        self.dataOffset = file.tell()
        dzfile.md5Headers.update(dz_item["buffer"])
        self.sliceName = dz_item["sliceName"]
        self.chunkName = dz_item["chunkName"]
        self.targetAddr = dz_item["targetAddr"]
        self.targetSize = dz_item["targetSize"]
        self.dataSize = dz_item["dataSize"]
        self.md5 = dz_item["md5"]
        self.trimCount = dz_item["trimCount"]
        self.crc32 = dz_item["crc32"]
        self.dev = dz_item["dev"]

    def getSliceName(self):
        """Return the name of the slice it belongs to.

        Returns:
            str: The partition name."""
        return _bname(self.sliceName)

    def getChunkName(self):
        """Return the name of the chunk.

        With several devices the name gets an A/B/... prefix.

        Returns:
            str: The chunk name."""
        name = _bname(self.chunkName)
        if self.dev > 0:
            name = chr(ord("A") + self.dev) + "." + name
        return name

    def getTargetStart(self):
        """Return the first byte offset of the write target.

        Returns:
            int: The start offset."""
        return self.targetAddr << self.dz.shiftLBA

    def getTargetEnd(self):
        """Return the last byte offset of the write target.

        Returns:
            int: The end offset."""
        return (self.targetAddr << self.dz.shiftLBA) + self.targetSize

    def getDev(self):
        """Return the device number.

        Returns:
            int: The device number."""
        return self.dev

    def getNext(self):
        """Return the offset of the next chunk header.

        Returns:
            int: The offset in the file."""
        return self.dataOffset + self.dataSize

    def extract(self):
        """Decompress this chunk into memory and check its MD5.

        Returns:
            bytes: The decompressed data."""
        buf = _decompress_all(self.dz.dzfile, self.dataOffset, self.dataSize)
        md5 = hashlib.md5(buf)
        if md5.digest() != self.md5:
            self.messages.append(
                "[!] MD5 mismatch for {} ({})".format(self.getChunkName(), md5.hexdigest())
            )
        return buf

    def extract_into(self, outfile):
        """Decompress this chunk in a stream and write it to the output file that
        was positioned already.

    The output is extended by the trimCount first, then the data is written
    while it is decompressed and the MD5 is checked.

    Args:
        outfile: The output file object that was positioned already."""
        current = outfile.seek(0, io.SEEK_CUR)
        outfile.truncate(current + (self.trimCount << self.dz.shiftLBA))
        md5 = hashlib.md5()
        for block in _iter_decompressed(self.dz.dzfile, self.dataOffset, self.dataSize):
            md5.update(block)
            outfile.write(block)
        if md5.digest() != self.md5:
            self.messages.append(
                "[!] MD5 mismatch for {} ({})".format(self.getChunkName(), md5.hexdigest())
            )


class UNDZSlice(object):
    "A logical slice (a partition) that is built from DZ chunks."

    def __init__(self, dzfile, index, name, start=0x7FFFFFFFFFFFFFFF, end=0):
        """Create a slice, with an optional range.

        Args:
            dzfile: The UNDZFile it belongs to.
            index: The number of the slice.
            name: The name of the slice.
            start: The first byte, not set by default.
            end: The last byte, not set by default."""
        self.dz = dzfile
        self.index = index
        self.name = name
        self.chunks = []
        self.start = start
        self.end = end

    def addChunk(self, chunk):
        """Attach a chunk to this slice.

        Args:
            chunk: The UNDZChunk instance."""
        self.chunks.append(chunk)

    def getStart(self):
        """Return the first byte of the slice.

        When the range is not set it is derived from the target addresses of the
        chunks.

        Returns:
            int: The first byte."""
        if self.chunks and (self.start >= self.end or self.start == 0x7FFFFFFFFFFFFFFF):
            return min(c.getTargetStart() for c in self.chunks)
        return self.start

    def getEnd(self):
        """Return the last byte of the slice.

        When the range is not set it is derived from the target addresses of the
        chunks.

        Returns:
            int: The last byte."""
        if self.chunks and (self.start >= self.end or self.start == 0x7FFFFFFFFFFFFFFF):
            return max(c.getTargetEnd() for c in self.chunks)
        return self.end

    def getLength(self):
        """Return the length of the slice in bytes.

    Returns:
        int: The length, 0 for an invalid range."""
        end = self.getEnd()
        start = self.getStart()
        length = end - start
        return length if length > 0 else 0

    def extract_to(self, path, params=False):
        """Write the partition image at its target offset.

        Args:
            path: The path of the image to write.
            params: Also write the <partition>.img.params when true."""
        start = self.getStart()
        end = self.getEnd()
        with io.open(path, "wb") as handle:
            for chunk in self.chunks:
                cur = chunk.getTargetStart()
                if cur < start:
                    buf = chunk.extract()
                    handle.seek(0, io.SEEK_SET)
                    handle.truncate(0)
                    handle.write(buf[cur - start :])
                else:
                    handle.seek(cur - start, io.SEEK_SET)
                    chunk.extract_into(handle)
            length = end - start
            if length > 0:
                handle.truncate(length)
        if params:
            self.write_params(path + ".params")

    def write_params(self, path):
        """Write the parameters that are needed to pack the partition again.

    They let image2chunks and mkdz rebuild the DZ.

    Args:
        path: The path of the parameter file."""
        start = self.getStart()
        end = self.getEnd()
        lines = [
            "startLBA={}".format(start >> self.dz.shiftLBA),
            "startAddr={}".format(start),
            "endLBA={}".format(end >> self.dz.shiftLBA),
            "endAddr={}".format(end),
        ]
        if self.chunks:
            last = self.chunks[-1]
            lines.append("lastWipe={}".format(
                (last.getTargetStart() >> self.dz.shiftLBA) + last.trimCount))
            lines.append("dev={}".format(self.chunks[0].getDev()))
            lines.append("blockSize={}".format(1 << self.dz.shiftLBA))
            lines.append("blockShift={}".format(self.dz.shiftLBA))
        else:
            lines.append("phantom=1")
        with io.open(path, "wt") as handle:
            handle.write("\n".join(lines) + "\n")


class UNDZFile(DZFile, UNDZUtils):
    "Open a DZ image, load every chunk and merge the slices with the GPT."

    def __init__(self, source):
        """Open a path or a stream and parse the DZ.

    Args:
        source: The path of a file or an open stream.

    Raises:
        DzError: When the DZ header or the format is not valid."""
        super(UNDZFile, self).__init__()
        self.slices = []
        self.sliceIdx = {}
        self.chunks = []
        self.messages = []
        self.md5Headers = hashlib.md5()
        self.shiftLBA = 9
        if hasattr(source, "read") and hasattr(source, "seek"):
            self.dzfile = source
        else:
            self.dzfile = WindowIO(source)
        self.own_file = True
        self.open()
        self.loadChunks()
        self._check_headers()

    def close(self):
        "Close the underlying stream that this object opened."
        if self.own_file and self.dzfile is not None:
            try:
                self.dzfile.close()
            except Exception:
                pass
            self.dzfile = None

    def open(self):
        """Read the DZ file header and note the number of chunks and the device
        information.

        Raises:
            DzError: When the format version is too new."""
        self.dzfile.seek(0, io.SEEK_END)
        self.length = self.dzfile.tell()
        self.dzfile.seek(0, io.SEEK_SET)
        dz_file = self.loadHeader(self.dzfile)
        if dz_file["formatMajor"] > 2:
            raise DzError("DZ format version too high")
        self.header_item = dz_file
        self.chunkCount = dz_file["chunkCount"]
        self.md5 = dz_file["md5"]
        self.device = _bname(dz_file.get("device"))
        self.android_version = _bname(dz_file.get("androidVer"))

    def loadChunks(self):
        """Walk the chunk headers and build the slices.

            The slices are sorted by their target address afterwards."""
        while True:
            try:
                chunk = UNDZChunk(self, self.dzfile)
            except DzError:
                break
            except Exception:
                break
            self.chunks.append(chunk)
            nxt = chunk.getNext()
            if nxt >= int(self.length):
                break
            self.dzfile.seek(nxt, io.SEEK_SET)
        self.chunks.sort(key=lambda c: (c.getTargetStart() + (c.getDev() << 48)))
        self._build_slices()

    def _build_slices(self):
        """Build the partition slices with the GPT of the first block and attach the
            chunks to them."""
        if not self.chunks:
            return
        try:
            table = GPT(self.chunks[0].extract())
            self.shiftLBA = table.shiftLBA
            nxt = table.dataStartLBA
            first = UNDZSlice(self, 0, self.chunks[0].getSliceName(), 0, nxt << self.shiftLBA)
            self.slices.append(first)
            self.sliceIdx[first.name] = first
            entries = [s for s in table.slices if s.type != UUID(int=0)]
            index = 1
            for entry in entries:
                item = UNDZSlice(
                    self,
                    index,
                    entry.name,
                    entry.startLBA << self.shiftLBA,
                    (entry.endLBA + 1) << self.shiftLBA,
                )
                self.slices.append(item)
                self.sliceIdx[item.name] = item
                index += 1
            last = UNDZSlice(
                self,
                index,
                self.chunks[-1].getSliceName(),
                table.dataEndLBA << self.shiftLBA,
                (table.altLBA + 1) << self.shiftLBA,
            )
            self.slices.append(last)
            self.sliceIdx[last.name] = last
        except NoGPT:
            pass
        for chunk in self.chunks:
            self._add_chunk(chunk)

    def _add_chunk(self, chunk):
        """Add a chunk to the slice with the same name, or to a new one.

    Args:
        chunk: The UNDZChunk instance."""
        name = chunk.getSliceName()
        if name in self.sliceIdx:
            self.sliceIdx[name].addChunk(chunk)
            return
        index = (self.slices[-1].index or 0) + 1 if self.slices else 0
        item = UNDZSlice(self, index, name)
        self.slices.append(item)
        self.sliceIdx[name] = item
        item.addChunk(chunk)

    def _check_headers(self):
        """Check the number of chunks against the MD5 of the file header.

            A mismatch is appended to the messages."""
        if self.chunks and len(self.chunks) != self.chunkCount:
            self.messages.append(
                "[!] chunk count {} != header {}".format(len(self.chunks), self.chunkCount)
            )
        if self.md5Headers.digest() != self.md5:
            self.messages.append("[!] DZ chunk header MD5 mismatch")

    def usable_slices(self):
        """Return the slices that can be extracted.

            The empty slices, the unallocated areas and the duplicated names are skipped.

        Returns:
            list: The UNDZSlice instances."""
        seen = set()
        out = []
        for item in self.slices:
            name = item.name or ""
            if not item.chunks:
                continue
            if name.startswith("_unallocated_"):
                continue
            key = name.casefold()
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
        return out

    def write_dz_params(self, dirpath, stem=""):
        """Write the .dz.params with the fields of the header that are needed to
        rebuild the DZ.

        Args:
            dirpath: The output directory.
            stem: The prefix of the file name.

        Returns:
            str: The path of the file."""
        item = self.header_item
        lines = [
            "format_major={}".format(item["formatMajor"]),
            "format_minor={}".format(item["formatMinor"]),
            "device={}".format(_bname(item["device"])),
            "factoryversion={}".format(_bname(item["version"])),
            "blockShift={}".format(self.shiftLBA),
            "blockSize={}".format(1 << self.shiftLBA),
            "unknown0={}".format(item["unknown0"]),
            "build_type={}".format(_bname(item["buildType"])),
            "old_date_code={}".format(_bname(item["oldDateCode"])),
            "android_version={}".format(_bname(item["androidVer"])),
            "unknown1={}".format(_hex(item["unknown1"])),
            "unknown2={}".format(_bname(item["unknown2"])),
            "unknown3={}".format(_hex(item["unknown3"])),
            "unknown4={}".format(item["unknown4"]),
            "unknown5={}".format(item["unknown5"]),
        ]
        path = os.path.join(dirpath, stem + ".dz.params")
        with io.open(path, "wt") as handle:
            handle.write("\n".join(lines) + "\n")
        return path

    def write_rawprogram(self, dirpath, stem="", wanted=None):
        """Write the rawprogramN.xml, the firehose table of Qualcomm, by physical
            partition.

            When wanted is not empty only the program nodes of the chosen partitions are
            written.

            Args:
                dirpath: The output directory.
                stem: The prefix of the file name.
                wanted: The names of the partitions that are wanted.

            Returns:
                list: The paths of the files that were written."""
        devices = {}
        for chunk in self.chunks:
            if wanted and chunk.getSliceName().casefold() not in wanted:
                continue
            devices.setdefault(chunk.getDev(), []).append(chunk)
        paths = []
        for dev in sorted(devices):
            lines = ['<?xml version="1.0" ?>', "<data>"]
            for chunk in devices[dev]:
                size_kb = chunk.targetSize >> 10
                start = chunk.getTargetStart()
                lines.append(
                    '\t<program SECTOR_SIZE_IN_BYTES="{}" file_sector_offset="0"'
                    ' filename="{}" label="{}" num_partition_sectors="{}"'
                    ' physical_partition_number="{}" size_in_KB="{}" sparse="false"'
                    ' start_byte_hex="0x{:X}" start_sector="{}"/>'.format(
                        1 << self.shiftLBA, chunk.getChunkName(), chunk.getSliceName(),
                        size_kb >> 2, dev, size_kb, start, start >> self.shiftLBA))
            lines.append("</data>")
            name = "{}rawprogram{}.xml".format(stem + "." if stem else "", dev)
            path = os.path.join(dirpath, name)
            with io.open(path, "wt") as handle:
                handle.write("\n".join(lines) + "\n")
            paths.append(path)
        return paths

# The 8 byte container magic of a KDZ and its version: v0/v1/v2.
KDZ_HEADERS = {
    b"\x28\x05\x00\x00\x34\x31\x25\x80": 0,
    b"\x18\x05\x00\x00\x32\x79\x44\x50": 1,
    KDZFile._dz_header: 2,
}

# The partitions that are skipped during the automatic extraction (userdata, cache, the GPT backup, ...).
SKIP_AUTO = frozenset(
    (
        "userdata",
        "cache",
        "grow",
        "metadata",
        "primarygpt",
        "backupgpt",
        "msf_fota",
        "mpt",
        "fota",
    )
)


def _read_magic(path, n=8):
    """Read the first bytes of a file.

    Args:
        path: The path of the file.
        n: The number of bytes to read.

    Returns:
        bytes: The header, an empty string when it cannot be read."""
    try:
        with open(path, "rb") as fh:
            return fh.read(n)
    except OSError:
        return b""


def is_kdz_file(path):
    """Check whether the path is a KDZ or a standalone DZ.

    Args:
        path: The path of the file.

    Returns:
        bool: True when the magic or the extension matches."""
    if not path or not os.path.isfile(path):
        return False
    name = os.path.basename(path).lower()
    magic = _read_magic(path, 8)
    if magic[:8] in KDZ_HEADERS:
        return True
    if magic[:4] == DZ_FILE_MAGIC:
        return True
    return name.endswith(".kdz") or name.endswith(".dz")


def is_dz_file(path):
    """Check whether the path is a standalone DZ file.

    Args:
        path: The path of the file.

    Returns:
        bool: True when the magic or the extension matches."""
    if not path or not os.path.isfile(path):
        return False
    if _read_magic(path, 4)[:4] == DZ_FILE_MAGIC:
        return True
    return os.path.basename(path).lower().endswith(".dz")


def format_size(size):
    """Format a byte count with a unit.

    Args:
        size: The number of bytes.

    Returns:
        str: The readable text."""
    try:
        size = int(size)
    except (TypeError, ValueError):
        size = 0
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return "{} B".format(size)
            return "{:.1f} {}".format(value, unit)
        value /= 1024
    return "{} B".format(size)


def parse_kdz(path):
    """Parse the directory of a KDZ.

    An entry ends with 0x03 and the list ends with 0x00, any other byte makes the
    scan go back and continue.

    Args:
        path: The path of the KDZ.

    Returns:
        list: The file entries.

    Raises:
        DzError: When this is not a supported KDZ file."""
    header = KDZFile()
    entries = []
    with open(path, "rb") as infile:
        infile.seek(0, os.SEEK_END)
        total = infile.tell()
        infile.seek(0, os.SEEK_SET)
        magic = infile.read(8)
        if magic not in KDZ_HEADERS:
            raise DzError("This is not a supported KDZ file")
        last = False
        cont = True
        data_start = 1 << 63
        while cont:
            buf = infile.read(header._dz_length)
            if len(buf) < header._dz_length:
                break
            item = dict(
                zip(header._dz_format_dict.keys(), header._dz_struct.unpack(buf))
            )
            for key in header._dz_collapsibles:
                if isinstance(item[key], (bytes, str)):
                    item[key] = (
                        item[key].rstrip(b"\x00")
                        if isinstance(item[key], bytes)
                        else item[key].rstrip("\x00")
                    )
            raw_name = item["name"]
            if isinstance(raw_name, bytes):
                raw_name = raw_name.split(b"\x00", 1)[0]
            name = _bname(raw_name)
            length = int(item["length"])
            offset = int(item["offset"])
            if offset < data_start:
                data_start = offset
            if name and length > 0 and 0 <= offset < total:
                entries.append({"name": name, "length": length, "offset": offset})
            cont = not last
            nxt = infile.read(1)
            if nxt == b"\x03":
                last = True
            elif nxt == b"\x00":
                cont = False
            elif nxt:
                infile.seek(-1, os.SEEK_CUR)
            else:
                cont = False
    return entries


def _payload_is_dz(path, offset):
    """Check whether an offset of a KDZ holds a DZ payload.

    Args:
        path: The path of the KDZ.
        offset: The offset.

    Returns:
        bool: True when the DZ magic is there."""
    with open(path, "rb") as fh:
        fh.seek(int(offset))
        return fh.read(4) == DZ_FILE_MAGIC


def kdz_dz_payloads(path):
    """List the DZ payloads of a file that can be decompressed.

    Args:
        path: The path of the KDZ or of the standalone DZ.

    Returns:
        list: The payload entries."""
    magic = _read_magic(path, 8)
    if magic[:8] in KDZ_HEADERS:
        out = []
        for entry in parse_kdz(path):
            if _payload_is_dz(path, entry["offset"]):
                item = dict(entry)
                item["standalone"] = False
                out.append(item)
        return out
    if magic[:4] == DZ_FILE_MAGIC:
        return [
            {
                "name": os.path.basename(path),
                "length": os.path.getsize(path),
                "offset": 0,
                "standalone": True,
            }
        ]
    return []


def open_dz(path, entry=None):
    """Open a standalone DZ or the DZ inside the window of a KDZ.

    Args:
        path: The path of the file.
        entry: A payload entry returned by kdz_dz_payloads.

    Returns:
        UNDZFile: The parser."""
    if entry is None or entry.get("standalone"):
        return UNDZFile(path)
    return UNDZFile(WindowIO(path, entry["offset"], entry["length"]))


def list_slices(path):
    """List the partitions of a KDZ or DZ that can be extracted.

    Args:
        path: The path of the file.

    Returns:
        list: The (display name, partition name, length) triples.

    Raises:
        DzError: When there is no DZ firmware that can be decompressed."""
    payloads = kdz_dz_payloads(path)
    if not payloads:
        raise DzError("The KDZ holds no DZ firmware that can be decompressed")
    rows = []
    multi = len(payloads) > 1
    for entry in payloads:
        dzfile = open_dz(path, entry)
        try:
            for item in dzfile.usable_slices():
                name = item.name
                if multi:
                    stem = os.path.splitext(entry["name"])[0]
                    display = "{}:{}".format(stem, name)
                else:
                    display = name
                rows.append((display, name, item.getLength()))
        finally:
            dzfile.close()
    return rows


def print_slices(slices):
    """Print the partitions of a KDZ or DZ in the shared table.

    Args:
        slices: The (display name, partition name, length) triples."""
    listing.print_partitions(
        [
            {
                "name": display,
                "size": length,
                "note": partition if partition != display else "",
            }
            for display, partition, length in slices
        ],
        title="Partitions",
    )


def _write_slice(item, dest, images, params):
    """Write the image of one partition and its parameter file.

    Args:
        item: The UNDZSlice instance.
        dest: The output path.
        images: Write the image.
        params: Write the parameter file."""
    if images:
        item.extract_to(dest, params)
    elif params:
        item.write_params(dest + ".params")


def extract_slices(path, outdir, wanted=None, log=None, params=0, rawprogram=0, dz_params=0, images=1):
    """Extract the wanted partitions, or the ones that can be extracted, into
        the output directory.

        With params, rawprogram or dz_params the metadata that is needed to pack
        them again is written as well: the .img.params of a partition, the
        rawprogramN.xml and the .dz.params. When images is 0 only the metadata is
        written and no partition image is exported.

    Args:
        path: The path of the KDZ or DZ.
        outdir: The output directory.
        wanted: The names of the partitions that are wanted.
        log: The callback that logs.
        params: Write the parameters of the partitions.
        rawprogram: Write the rawprogramN.xml.
        dz_params: Write the .dz.params.
        images: Export the partition images.

    Returns:
        list: The images that were written.

    Raises:
        DzError: When no output was asked for, there is no DZ or the wanted
            partitions are not there."""
    def echo(msg):
        """Write one line through the log callback.

    Args:
        msg: The text."""
        if log:
            log(msg)

    if not images and not (params or rawprogram or dz_params):
        raise DzError("Nothing was selected for the output")
    payloads = kdz_dz_payloads(path)
    if not payloads:
        raise DzError("The KDZ holds no DZ firmware that can be decompressed")
    multi = len(payloads) > 1
    names = set()
    for raw in wanted or []:
        text = (raw or "").strip()
        if ":" in text and not text.lower().endswith(".img"):
            text = text.split(":", 1)[-1]
        if text.lower().endswith(".img"):
            text = text[:-4]
        if text:
            names.add(text.casefold())
    os.makedirs(outdir, exist_ok=True)
    extracted = []
    used = set()
    wrote_meta = False
    for entry in payloads:
        stem = os.path.splitext(os.path.basename(entry["name"]))[0] if multi else ""
        echo("> Parsing the DZ: {}".format(entry["name"]))
        dzfile = open_dz(path, entry)
        try:
            for warn in dzfile.messages:
                echo(warn)
            if dz_params:
                meta = dzfile.write_dz_params(outdir, stem)
                echo("> Wrote the DZ parameters: {}".format(os.path.basename(meta)))
                wrote_meta = True
            if rawprogram:
                metas = dzfile.write_rawprogram(outdir, stem, names)
                if metas:
                    echo("> Wrote {} rawprogram files".format(len(metas)))
                    wrote_meta = True
            if not images and not params:
                continue
            slices = dzfile.usable_slices()
            if names:
                slices = [item for item in slices if item.name.casefold() in names]
                if not slices:
                    continue
            jobs = []
            for item in slices:
                if not names and item.name.casefold() in SKIP_AUTO:
                    echo("> Skipped the partition: {}".format(item.name))
                    continue
                dest_name = item.name + ".img"
                dest = os.path.join(outdir, dest_name)
                if dest in used:
                    dest = os.path.join(outdir, "{}_{}.img".format(stem, item.name))
                used.add(dest)
                jobs.append((item, item.name, dest, format_size(item.getLength())))
                extracted.append(dest)
            threads = _extract_threads()
            if threads > 1 and len(jobs) > 1 and ThreadPoolExecutor is not None:
                def work(job):
                    """Write one partition with the standalone parser.

    Args:
        job: (slice, name, output path, size text)."""
                    _item, sname, dest, size = job
                    echo("> Wrote the partition: {} ({})".format(sname, size))
                    sub = getattr(_KDZ_TLS, "dz", None)
                    if sub is None or getattr(_KDZ_TLS, "entry", None) is not entry:
                        if sub is not None:
                            sub.close()
                        sub = open_dz(path, entry)
                        _KDZ_TLS.dz = sub
                        _KDZ_TLS.entry = entry
                    for candidate in sub.usable_slices():
                        if candidate.name == sname:
                            _write_slice(candidate, dest, images, params)
                            break
                with ThreadPoolExecutor(max_workers=min(threads, len(jobs))) as pool:
                    list(pool.map(work, jobs))
            else:
                for item, sname, dest, size in jobs:
                    echo("> Wrote the partition: {} ({})".format(sname, size))
                    _write_slice(item, dest, images, params)
        finally:
            dzfile.close()
    if names and not extracted and not wrote_meta:
        raise DzError("The partition was not found")
    return extracted

