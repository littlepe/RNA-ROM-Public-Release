"""Unpack Unisoc PAC firmware.

The PAC header and the file table are parsed, the CRC is checked, the
partitions are extracted and a flash.cfg is written; a PAC inside a ZIP is
supported as well."""
import struct
import os
import sys
import zlib

try:
    from . import listing
except ImportError:
    import listing
from pathlib import Path

PAC_MAGIC = 0xFFFAFFFA
ZIP_MAGIC = 0x04034B50
SIZEOF_PAC_HEADER = 2124
SIZEOF_FILE_T = 2580

try:
    from concurrent.futures import ThreadPoolExecutor
except Exception:
    ThreadPoolExecutor = None


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

CRC16_TABLE = [
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
    0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
    0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
    0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
    0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
    0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
    0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
    0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
    0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
    0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
    0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
    0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
    0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
    0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
    0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
    0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
    0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
    0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
    0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
    0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
    0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
    0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
    0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
    0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
    0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
    0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
    0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
    0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
    0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
]


def crc16(data, crc=0):
    """Compute the CRC16 that the PAC uses.

    Args:
        data: The bytes to compute over.
        crc: The start value.

    Returns:
        int: The CRC16."""
    for byte in data:
        crc = ((crc >> 8) ^ CRC16_TABLE[(crc ^ byte) & 0xFF]) & 0xFFFF
    return crc & 0xFFFF


def unicode_to_mbcs(data):
    """Decode a padded UTF-16LE field into a string without the NUL bytes.

    Args:
        data: The fixed size UTF-16LE bytes.

    Returns:
        str: The decoded string."""
    return data.decode('utf-16-le', errors='ignore').rstrip('\x00')


def unpack_dword(data):
    """Read a little endian 32 bit integer.

    Args:
        data: Four bytes.

    Returns:
        int: The value."""
    return struct.unpack('<I', data)[0]


def unpack_word(data):
    """Read a little endian 16 bit integer.

    Args:
        data: Two bytes.

    Returns:
        int: The value."""
    return struct.unpack('<H', data)[0]


class PacHeader:
    """The header of a PAC file.

    Attributes:
        version: The version string.
        total_size: The size of the file.
        product_name, product_alias, product_version: The product details.
        file_count, file_offset: The count and the offset of the file table.
        magic, crc1, crc2: The magic and the checksums."""
    def __init__(self):
        "Start with empty header fields."
        self.version = ""
        self.hi_size = 0
        self.lo_size = 0
        self.total_size = 0
        self.product_name = ""
        self.product_version = ""
        self.file_count = 0
        self.file_offset = 0
        self.mode = 0
        self.flash_type = 0
        self.nand_strategy = 0
        self.is_nv_backup = 0
        self.nand_page_type = 0
        self.product_alias = ""
        self.oma_dm_product_flag = 0
        self.is_oma_dm = 0
        self.is_preload = 0
        self.magic = 0
        self.crc1 = 0
        self.crc2 = 0

    def parse(self, data):
        """Fill the fields from the 2124 byte header buffer.

        Args:
            data: The bytes of the PAC header."""
        self.version = unicode_to_mbcs(data[0:44])
        self.hi_size = unpack_dword(data[44:48])
        self.lo_size = unpack_dword(data[48:52])
        self.total_size = self.hi_size * 0x100000000 + self.lo_size
        self.product_name = unicode_to_mbcs(data[52:564])
        self.product_version = unicode_to_mbcs(data[564:1076])
        self.file_count = unpack_dword(data[1076:1080])
        self.file_offset = unpack_dword(data[1080:1084])
        self.mode = unpack_dword(data[1084:1088])
        self.flash_type = unpack_dword(data[1088:1092])
        self.nand_strategy = unpack_dword(data[1092:1096])
        self.is_nv_backup = unpack_dword(data[1096:1100])
        self.nand_page_type = unpack_dword(data[1100:1104])
        self.product_alias = unicode_to_mbcs(data[1104:1304])
        self.oma_dm_product_flag = unpack_dword(data[1304:1308])
        self.is_oma_dm = unpack_dword(data[1308:1312])
        self.is_preload = unpack_dword(data[1312:1316])
        self.magic = unpack_dword(data[2116:2120])
        self.crc1 = unpack_word(data[2120:2122])
        self.crc2 = unpack_word(data[2122:2124])

    def print_info(self):
        "Print the product information to stdout."
        print("\n---------------------ProductInfo---------------------")
        print(f"Version={self.version}")
        print(f"Size={self.total_size}")
        print(f"PrdName={self.product_name}")
        print(f"PrdVersion={self.product_version}")
        print(f"FileCount={self.file_count}")
        print(f"FileOffset={self.file_offset}")
        print(f"Mode={self.mode}")
        print(f"NandFlash={self.flash_type}")
        print(f"NandStrategy={self.nand_strategy}")
        print(f"IsNvBackup={self.is_nv_backup}")
        print(f"NandPageType={self.nand_page_type}")
        print(f"PrdAlias={self.product_alias}")
        print(f"OmaDmProductFlag={self.oma_dm_product_flag}")
        print(f"IsOmaDM={self.is_oma_dm}")
        print(f"IsPreload={self.is_preload}")
        print(f"Magic=0x{self.magic:X}")
        print(f"CRC1={self.crc1}")
        print(f"CRC2={self.crc2}")

    def to_config(self):
        """Build the [Setting] section of the flash.cfg.

    Returns:
        str: The text of the configuration."""
        cfg = "\n[Setting]\n"
        cfg += f"PacVer={self.version}\n"
        cfg += f"PAC_PRODUCT={self.product_name}\n"
        cfg += f"ProductAlias={self.product_alias}\n"
        cfg += f"ProductVer={self.product_version}\n"
        cfg += f"Mode={self.mode}\n"
        cfg += f"FlashType={self.flash_type}\n"
        cfg += f"NandStrategy={self.nand_strategy}\n"
        cfg += f"NandPageType={self.nand_page_type}\n"
        cfg += f"NvBackup={self.is_nv_backup}\n"
        cfg += f"OmaDmProductFlag={self.oma_dm_product_flag}\n"
        cfg += f"OmaDM={self.is_oma_dm}\n"
        cfg += f"IsPreload={self.is_preload}\n"
        return cfg


class FileInfo:
    """The description of one file or partition of a PAC.

    Attributes:
        file_id, file_name, file_version: The id and the name.
        file_size, data_offset: The size and the offset of the data.
        file_flag, check_flag, can_omit_flag: The write and check flags."""
    def __init__(self):
        "Start with an empty file table entry."
        self.size = 0
        self.file_id = ""
        self.file_name = ""
        self.file_version = ""
        self.hi_file_size = 0
        self.hi_data_offset = 0
        self.lo_file_size = 0
        self.file_flag = 0
        self.check_flag = 0
        self.lo_data_offset = 0
        self.can_omit_flag = 0
        self.addr_num = 0
        self.file_size = 0
        self.data_offset = 0

    def parse(self, data):
        """Parse a 2580 byte file table entry.

    Args:
        data: The bytes of the entry."""
        self.size = unpack_dword(data[0:4])
        self.file_id = unicode_to_mbcs(data[4:516])
        self.file_name = unicode_to_mbcs(data[516:1028])
        self.file_version = unicode_to_mbcs(data[1028:1532])
        self.hi_file_size = unpack_dword(data[1532:1536])
        self.hi_data_offset = unpack_dword(data[1536:1540])
        self.lo_file_size = unpack_dword(data[1540:1544])
        self.file_flag = unpack_dword(data[1544:1548])
        self.check_flag = unpack_dword(data[1548:1552])
        self.lo_data_offset = unpack_dword(data[1552:1556])
        self.can_omit_flag = unpack_dword(data[1556:1560])
        self.addr_num = unpack_dword(data[1560:1564])
        self.file_size = self.hi_file_size * 0x100000000 + self.lo_file_size
        self.data_offset = self.hi_data_offset * 0x100000000 + self.lo_data_offset

    def print_info(self, index):
        """Print a file table entry for the debug output.

    Args:
        index: The number of the entry, starting at 0."""
        print(f"\n---------------------{index + 1}---------------------")
        print(f"Size={self.size}")
        print(f"FileID={self.file_id}")
        print(f"FileName={self.file_name}")
        print(f"FileSize={self.file_size}")
        print(f"FileFlag={self.file_flag}")
        print(f"CheckFlag={self.check_flag}")
        print(f"DataOffset={self.data_offset}")
        print(f"CanOmitFlag={self.can_omit_flag}")


class PacExtractor:
    """The PAC unpacker.

    Attributes:
        pac_file: The path of the PAC file.
        output_dir: The output directory.
        check_crc: Check the CRC.
        debug: Print the entries of the file table.
        header: The parsed PAC header.
        files: The list of FileInfo."""
    def __init__(self, pac_file, output_dir=None, check_crc=True, debug=False):
        """Remember the paths and the options.

        Args:
            pac_file: The path of the PAC file.
            output_dir: The output directory, the ImageFiles next to the PAC by
                default.
            check_crc: Check the CRC.
            debug: Print the entries of the file table."""
        self.pac_file = pac_file
        self.check_crc = check_crc
        self.debug = debug
        self.header = PacHeader()
        self.files = []

        if output_dir is None:
            output_dir = os.path.join(os.path.dirname(pac_file), "ImageFiles")
        self.output_dir = output_dir

    def extract(self):
        """Check and extract a PAC, or unpack it as a ZIP.

        Raises:
            ValueError: When the file is too small, the magic does not match or the
                CRC check fails."""
        import time
        start = time.time()

        pac_size = os.path.getsize(self.pac_file)
        if pac_size < SIZEOF_PAC_HEADER:
            raise ValueError("PAC file size is too small, maybe it has been destructed!")

        os.makedirs(self.output_dir, exist_ok=True)

        with open(self.pac_file, 'rb') as f:
            header_data = f.read(SIZEOF_PAC_HEADER)

            first_magic = struct.unpack('<I', header_data[:4])[0]
            if first_magic == ZIP_MAGIC:
                self._extract_zip()
                return

            print("\nsprd pac.")
            self.header.parse(header_data)

            if self.header.magic != PAC_MAGIC and self.header.magic != 0xFFFFFFFA:
                raise ValueError("Not a valid PAC file (magic=0x{:08X})".format(self.header.magic))

            self.header.print_info()

            if self.header.total_size != pac_size:
                print("Warning: PAC file size mismatch (expected={}, actual={})".format(
                    self.header.total_size, pac_size))

            if self.check_crc:
                self._check_crc(f, header_data, pac_size)

            f.seek(SIZEOF_PAC_HEADER)
            file_info_data = f.read(SIZEOF_FILE_T * self.header.file_count)

            self.files = []
            for i in range(self.header.file_count):
                info = FileInfo()
                info.parse(file_info_data[i * SIZEOF_FILE_T:(i + 1) * SIZEOF_FILE_T])
                self.files.append(info)
                if self.debug:
                    info.print_info(i)

            listing.print_partitions(
                [
                    {
                        "name": info.file_name,
                        "size": info.file_size,
                        "offset": info.data_offset,
                        "note": info.file_id,
                    }
                    for info in self.files
                ],
                title="Files",
            )

            product_cfg = self.header.to_config()
            image_cfg = "\n[FlashParam]\n"

            jobs = []
            for i, info in enumerate(self.files):
                if info.file_size == 0:
                    if info.file_flag == 1:
                        image_cfg += f"{info.file_id}=0@\n"
                    else:
                        image_cfg += f"{info.file_id}=1@\n"
                    continue

                output_file = self._get_unique_filename(info.file_name)
                output_path = os.path.join(self.output_dir, output_file)
                jobs.append((info, output_file, output_path))

                if info.file_id:
                    image_cfg += f"{info.file_id}=1@{output_file}\n"
                else:
                    product_cfg += f"PAC_CONFILE={output_file}\n"

            def work(job):
                """Extract a single file table entry.

    Args:
        job: (file info, output name, output path)."""
                info, output_file, output_path = job
                with open(self.pac_file, 'rb') as fh:
                    fh.seek(info.data_offset)
                    remaining = info.file_size
                    with open(output_path, 'wb') as out:
                        while remaining > 0:
                            data = fh.read(min(remaining, 64 * 1024))
                            if not data:
                                break
                            out.write(data)
                            remaining -= len(data)
                print(f"Extracted: {output_file} ({self._human_size(info.file_size)})")

            threads = _extract_threads()
            if threads > 1 and len(jobs) > 1 and ThreadPoolExecutor is not None:
                with ThreadPoolExecutor(max_workers=min(threads, len(jobs))) as pool:
                    list(pool.map(work, jobs))
            else:
                for job in jobs:
                    work(job)

            cfg_path = os.path.join(self.output_dir, "flash.cfg")
            with open(cfg_path, 'w', encoding='utf-8') as cfg:
                cfg.write(product_cfg)
                cfg.write(image_cfg)

        elapsed = time.time() - start
        print(f"\n---------------------------")
        print(f"Extract complete!")
        print(f"Output: {self.output_dir}")
        print(f"Time: {elapsed:.1f}s")
        print(f"---------------------------")

    def _extract_zip(self):
        """Unpack a PAC that is wrapped in a ZIP straight into the output
            directory."""
        import zipfile
        print("\nzip pac.")
        with zipfile.ZipFile(self.pac_file, 'r') as zf:
            zf.extractall(self.output_dir)
        print(f"Extracted to: {self.output_dir}")

    def _check_crc(self, f, header_data, pac_size):
        """Check the CRC1 of the PAC header and the CRC2 of the data area.

    Args:
        f: The opened PAC file.
        header_data: The bytes of the header.
        pac_size: The size of the PAC file.

    Raises:
        ValueError: When CRC1 or CRC2 does not match."""
        print("\nCheck crc first part...")
        if self.header.magic == PAC_MAGIC:
            crc1 = crc16(header_data[:2120])
            if crc1 != self.header.crc1:
                print(f"CalcHeaderCRC1={crc1}")
                print(f"PacCRC1={self.header.crc1}")
                raise ValueError("CRC1 Error! PAC file may be damaged!")

        print("\nCheck crc second part...")
        f.seek(SIZEOF_PAC_HEADER)
        remaining = pac_size - SIZEOF_PAC_HEADER
        crc2 = 0
        while remaining > 0:
            chunk_size = min(remaining, 64 * 1024)
            data = f.read(chunk_size)
            crc2 = crc16(data, crc2)
            remaining -= len(data)

        if crc2 != self.header.crc2:
            print(f"CalcDataCRC2={crc2}")
            print(f"PacCRC2={self.header.crc2}")
            raise ValueError("CRC2 Error! PAC file may be damaged!")

        f.seek(SIZEOF_PAC_HEADER)
        print("CRC check passed!")

    def _get_unique_filename(self, name):
        """Build a name for the output file that does not collide.

    Args:
        name: The wanted file name.

    Returns:
        str: A free file name, ``(n)`` is added when there is a clash."""
        output_path = os.path.join(self.output_dir, name)
        if not os.path.exists(output_path):
            return name

        base, ext = os.path.splitext(name)
        n = 1
        while True:
            new_name = f"{base}({n}){ext}"
            new_path = os.path.join(self.output_dir, new_name)
            if not os.path.exists(new_path):
                return new_name
            n += 1

    @staticmethod
    def _human_size(size):
        """Format a byte count as readable text.

    Args:
        size: The number of bytes.

    Returns:
        str: Text such as 1.5M."""
        if size >= 1073741824:
            return f"{size / 1073741824:.1f}G"
        elif size >= 1048576:
            return f"{size / 1048576:.1f}M"
        elif size >= 1024:
            return f"{size / 1024:.1f}K"
        return f"{size}B"


def main():
    "The command line entry point: pac_extract <pac-file> [output-dir] [-S] [-D]."
    if len(sys.argv) < 2:
        print("Usage: pac_extract <pac-file> [output-dir] [-S] [-D]")
        print("  -S: Skip CRC check")
        print("  -D: Debug mode")
        sys.exit(1)

    pac_file = sys.argv[1]
    output_dir = None
    check_crc = True
    debug = False

    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == '-S':
            check_crc = False
        elif arg == '-D':
            debug = True
        elif output_dir is None:
            output_dir = arg
        i += 1

    if not os.path.isfile(pac_file):
        print(f"Error: File not found: {pac_file}")
        sys.exit(1)

    extractor = PacExtractor(pac_file, output_dir, check_crc, debug)
    extractor.extract()


if __name__ == '__main__':
    main()
