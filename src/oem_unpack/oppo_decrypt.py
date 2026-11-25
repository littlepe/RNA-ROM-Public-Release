#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unpack the encrypted firmware of OPPO, Realme and OnePlus (ozip, ofp, ops).

The encrypted packages of the vendor are recognised and decrypted and the
partition and image files are written. The entry points are
ozip_extract_whole, qc_extract, mtk_extract and ops_extract."""

from __future__ import print_function

import argparse
import hashlib
import io
import os
import re
import shutil
import struct
import sys
import zipfile
from binascii import hexlify, unhexlify

try:
    from .log import debug, debug_exc, file_info
    from .log import out as echo
except Exception:
    def debug(msg):
        """A placeholder for the debug output.

        Args:
            msg: The text."""
        pass

    def debug_exc(prefix="exception: "):
        """A placeholder for the exception output.

        Args:
            prefix: The prefix."""
        pass

    def file_info(path):
        """A placeholder for the file information.

        Args:
            path: The path.

        Returns:
            str: The path, unchanged."""
        return str(path)

    def echo(msg):
        """Write one line to the console.

        Args:
            msg: The text."""
        print(str(msg))

_AES_IMPORT_ERROR = ""
try:
    # The built in stand in (cryptography based) is preferred, it avoids the native library of the Termux pycryptodome
    from . import rna_aes as AES
except Exception:
    try:
        import rna_aes as AES
    except Exception as _aes_e1:
        try:
            from Crypto.Cipher import AES
        except Exception as _aes_e2:
            try:
                from Cryptodome.Cipher import AES
            except Exception as _aes_e3:
                AES = None
                _AES_IMPORT_ERROR = "rna_aes: {} | Crypto: {} | Cryptodome: {}".format(
                    _aes_e1, _aes_e2, _aes_e3
                )

CHUNK = 4 * 1024 * 1024
QC_DECRYPT_CHUNK = 0x40000
# The fixed password of the outer zip of a Qualcomm OFP; the plain ozip magic is used to try the keys.
QC_ZIP_PASSWORD = b"flash@realme$50E7F7D847732396F1582CD62DD385ED7ABB0897"
OZIP_MAGICS = (b"\x50\x4B\x03\x04", b"\x41\x56\x42\x30", b"\x41\x4E\x44\x52")
REC_MAX_BLOB = 256 * 1024 * 1024
REC_MAX_LAYERS = 64

try:
    from concurrent.futures import ThreadPoolExecutor
except Exception:
    ThreadPoolExecutor = None

import threading


def _log_tr(text):
    """The output is English, the translation is the identity."""
    return text

_IO_LOCK = threading.Lock()


def _cap_by_mem(count):
    """Lower the thread count so that a single thread stays inside the memory
    budget, this avoids an OOM.

    Args:
        count: The wanted number of threads.

    Returns:
        int: The thread count that the available memory allows."""
    raw = os.getenv("RNA_THREAD_MEM") or os.getenv("DNA_THREAD_MEM") or os.getenv("WORK_THREAD_MEM") or ""
    try:
        per = int(float(raw))
    except (TypeError, ValueError):
        per = 0
    if per <= 0:
        return count
    avail = 0
    try:
        with open("/proc/meminfo", "r") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    avail = int(line.split()[1]) // 1024
                    break
    except Exception:
        avail = 0
    if avail <= 0:
        return count
    return max(1, min(count, avail // per))


def worker_threads():
    """Resolve the number of threads used for the decryption.

    Reads RNA_THREADS/DNA_THREADS and falls back to the CPU count, the result is
    then lowered to what the memory allows.

    Returns:
        int: The thread count."""
    raw = os.getenv("RNA_THREADS") or os.getenv("DNA_THREADS") or os.getenv("WORK_THREADS") or ""
    try:
        count = int(float(raw))
    except (TypeError, ValueError):
        count = 0
    if count <= 0:
        count = max(1, os.cpu_count() or 2)
    return _cap_by_mem(count)


def _run_jobs(jobs, worker, threads):
    """Run a list of tasks in parallel.

    Args:
        jobs: The arguments of the tasks.
        worker: The function that handles one task.
        threads: The number of threads, a single thread or a single task runs them
            one after the other."""
    if threads <= 1 or len(jobs) <= 1 or ThreadPoolExecutor is None:
        for job in jobs:
            worker(job)
        return
    with ThreadPoolExecutor(max_workers=min(threads, len(jobs))) as pool:
        for _ in pool.map(worker, jobs):
            pass


def _pread(fd, size, offset):
    """Read from a file descriptor at an offset.

    Args:
        fd: The file descriptor.
        size: The number of bytes to read.
        offset: The offset.

    Returns:
        bytes: The data that was read."""
    if hasattr(os, "pread"):
        return os.pread(fd, size, offset)
    with _IO_LOCK:
        os.lseek(fd, offset, os.SEEK_SET)
        return os.read(fd, size)


def _pwrite(fd, data, offset):
    """Write to a file descriptor at an offset.

    Args:
        fd: The file descriptor.
        data: The data to write.
        offset: The offset.

    Returns:
        int: The number of bytes that were written."""
    if hasattr(os, "pwrite"):
        return os.pwrite(fd, data, offset)
    with _IO_LOCK:
        os.lseek(fd, offset, os.SEEK_SET)
        return os.write(fd, data)

# The built in ozip AES-128 key table (hex), the first 16 bytes are decrypted with ECB until the magic matches.
OZIP_KEYS = [
    "D6EECF0AE5ACD4E0E9FE522DE7CE381E",
    "D6ECCF0AE5ACD4E0E92E522DE7C1381E",
    "D6DCCF0AD5ACD4E0292E522DB7C1381E",
    "D7DCCE1AD4AFDCE2393E5161CBDC4321",
    "D7DBCE2AD4ADDCE1393E5521CBDC4321",
    "D7DBCE1AD4AFDCE1393E5121CBDC4321",
    "D4D2CD61D4AFDCE13B5E01221BD14D20",
    "261CC7131D7C1481294E532DB752381E",
    "1CA21E12271335AE33AB81B2A7B14622",
    "D4D2CE11D4AFDCE13B3E0121CBD14D20",
    "1C4C1EA3A12531AE491B21BB31613C11",
    "1C4C1EA3A12531AE4A1B21BB31C13C21",
    "1C4A11A3A12513AE441B23BB31513121",
    "1C4A11A3A12589AE441A23BB31517733",
    "1C4A11A3A22513AE541B53BB31513121",
    "2442CE821A4F352E33AE81B22BC1462E",
    "14C2CD6214CFDC2733AE81B22BC1462C",
    "1E38C1B72D522E29E0D4ACD50ACFDCD6",
    "12341EAAC4C123CE193556A1BBCC232D",
    "2143DCCB21513E39E1DCAFD41ACEDBD7",
    "2D23CCBBA1563519CE23C1C4AA1E3412",
    "172B3E14E46F3CE13E2B5121CBDC4321",
    "ACAA1E12A71431CE4A1B21BBA1C1C6A2",
    "ACAC1E13A72531AE4A1B22BB31C1CC22",
    "1C4411A3A12533AE441B21BB31613C11",
    "1C4416A8A42717AE441523B336513121",
    "55EEAA33112133AE441B23BB31513121",
    "ACAC1E13A12531AE4A1B21BB31C13C21",
    "ACAC1E13A72431AE4A1B22BBA1C1C6A2",
    "12CAC11211AAC3AEA2658690122C1E81",
    "1CA21E12271435AE331B81BBA7C14612",
    "D1DACF24351CE428A9CE32ED87323216",
    "A1CC75115CAECB890E4A563CA1AC67C8",
    "2132321EA2CA86621A11241ABA512722",
    "22A21E821743E5EE33AE81B227B1462E",
]

# The Qualcomm OFP key sets: [version tag, obfuscation mask, user key, IV], the nibbles are rotated to undo the obfuscation.
QC_KEYSETS = [
    ["V1.5.13",
     "67657963787565E837D226B69A495D21",
     "F6C50203515A2CE7D8C3E1F938B7E94C",
     "42F2D5399137E2B2813CD8ECDF2F4D72"],
    ["V1.4.17/1.4.27",
     "27827963787265EF89D126B69A495A21",
     "82C50203285A2CE7D8C3E198383CE94C",
     "422DD5399181E223813CD8ECDF2E4D72"],
    ["V1.6.17",
     "E11AA7BB558A436A8375FD15DDD4651F",
     "77DDF6A0696841F6B74782C097835169",
     "A739742384A44E8BA45207AD5C3700EA"],
    ["V1.6.6/1.6.9/1.6.17/1.6.24/1.6.26/1.7.6",
     "3C2D518D9BF2E4279DC758CD535147C3",
     "87C74A29709AC1BF2382276C4E8DF232",
     "598D92E967265E9BCABE2469FE4A915E"],
    ["V1.7.2",
     "8FB8FB261930260BE945B841AEFA9FD4",
     "E529E82B28F5A2F8831D860AE39E425D",
     "8A09DA60ED36F125D64709973372C1CF"],
    ["V2.0.3",
     "E8AE288C0192C54BF10C5707E9C4705B",
     "D64FC385DCD52A3C9B5FBA8650F92EDA",
     "79051FD8D8B6297E2E4559E997F63B7F"],
]

# The MediaTek OFP key table: a triple holds the obfuscated key, the AES key and the IV, a pair the plain key and the IV.
MTK_KEYTABLES = [
    ["67657963787565E837D226B69A495D21",
     "F6C50203515A2CE7D8C3E1F938B7E94C",
     "42F2D5399137E2B2813CD8ECDF2F4D72"],
    ["9E4F32639D21357D37D226B69A495D21",
     "A3D8D358E42F5A9E931DD3917D9A3218",
     "386935399137416B67416BECF22F519A"],
    ["892D57E92A4D8A975E3C216B7C9DE189",
     "D26DF2D9913785B145D18C7219B89F26",
     "516989E4A1BFC78B365C6BC57D944391"],
    ["27827963787265EF89D126B69A495A21",
     "82C50203285A2CE7D8C3E198383CE94C",
     "422DD5399181E223813CD8ECDF2E4D72"],
    ["3C4A618D9BF2E4279DC758CD535147C3",
     "87B13D29709AC1BF2382276C4E8DF232",
     "59B7A8E967265E9BCABE2469FE4A915E"],
    ["1C3288822BF824259DC852C1733127D3",
     "E7918D22799181CF2312176C9E2DF298",
     "3247F889A7B6DECBCA3E28693E4AAAFE"],
    ["1E4F32239D65A57D37D2266D9A775D43",
     "A332D3C3E42F5A3E931DD991729A321D",
     "3F2A35399A373377674155ECF28FD19A"],
    ["122D57E92A518AFF5E3C786B7C34E189",
     "DD6DF2D9543785674522717219989FB0",
     "12698965A132C76136CC88C5DD94EE91"],
    ["ab3f76d7989207f2",
     "2bf515b3a9737835"],
]

# The OPS stream cipher: the S-Box, the round keys and the MBox of each version, the same as the MSM download tool.
OPS_SBOX = bytes.fromhex(
    "c66363a5c66363a5f87c7c84f87c7c84ee777799ee777799f67b7b8df67b7b8d"
    "fff2f20dfff2f20dd66b6bbdd66b6bbdde6f6fb1de6f6fb191c5c55491c5c554"
    "60303050603030500201010302010103ce6767a9ce6767a9562b2b7d562b2b7d"
    "e7fefe19e7fefe19b5d7d762b5d7d7624dababe64dababe6ec76769aec76769a"
    "8fcaca458fcaca451f82829d1f82829d89c9c94089c9c940fa7d7d87fa7d7d87"
    "effafa15effafa15b25959ebb25959eb8e4747c98e4747c9fbf0f00bfbf0f00b"
    "41adadec41adadecb3d4d467b3d4d4675fa2a2fd5fa2a2fd45afafea45afafea"
    "239c9cbf239c9cbf53a4a4f753a4a4f7e4727296e47272969bc0c05b9bc0c05b"
    "75b7b7c275b7b7c2e1fdfd1ce1fdfd1c3d9393ae3d9393ae4c26266a4c26266a"
    "6c36365a6c36365a7e3f3f417e3f3f41f5f7f702f5f7f70283cccc4f83cccc4f"
    "6834345c6834345c51a5a5f451a5a5f4d1e5e534d1e5e534f9f1f108f9f1f108"
    "e2717193e2717193abd8d873abd8d87362313153623131532a15153f2a15153f"
    "0804040c0804040c95c7c75295c7c75246232365462323659dc3c35e9dc3c35e"
    "3018182830181828379696a1379696a10a05050f0a05050f2f9a9ab52f9a9ab5"
    "0e0707090e07070924121236241212361b80809b1b80809bdfe2e23ddfe2e23d"
    "cdebeb26cdebeb264e2727694e2727697fb2b2cd7fb2b2cdea75759fea75759f"
    "1209091b1209091b1d83839e1d83839e582c2c74582c2c74341a1a2e341a1a2e"
    "361b1b2d361b1b2ddc6e6eb2dc6e6eb2b45a5aeeb45a5aee5ba0a0fb5ba0a0fb"
    "a45252f6a45252f6763b3b4d763b3b4db7d6d661b7d6d6617db3b3ce7db3b3ce"
    "5229297b5229297bdde3e33edde3e33e5e2f2f715e2f2f711384849713848497"
    "a65353f5a65353f5b9d1d168b9d1d1680000000000000000c1eded2cc1eded2c"
    "4020206040202060e3fcfc1fe3fcfc1f79b1b1c879b1b1c8b65b5bedb65b5bed"
    "d46a6abed46a6abe8dcbcb468dcbcb4667bebed967bebed97239394b7239394b"
    "944a4ade944a4ade984c4cd4984c4cd4b05858e8b05858e885cfcf4a85cfcf4a"
    "bbd0d06bbbd0d06bc5efef2ac5efef2a4faaaae54faaaae5edfbfb16edfbfb16"
    "864343c5864343c59a4d4dd79a4d4dd766333355663333551185859411858594"
    "8a4545cf8a4545cfe9f9f910e9f9f9100402020604020206fe7f7f81fe7f7f81"
    "a05050f0a05050f0783c3c44783c3c44259f9fba259f9fba4ba8a8e34ba8a8e3"
    "a25151f3a25151f35da3a3fe5da3a3fe804040c0804040c0058f8f8a058f8f8a"
    "3f9292ad3f9292ad219d9dbc219d9dbc7038384870383848f1f5f504f1f5f504"
    "63bcbcdf63bcbcdf77b6b6c177b6b6c1afdada75afdada754221216342212163"
    "2010103020101030e5ffff1ae5ffff1afdf3f30efdf3f30ebfd2d26dbfd2d26d"
    "81cdcd4c81cdcd4c180c0c14180c0c142613133526131335c3ecec2fc3ecec2f"
    "be5f5fe1be5f5fe1359797a2359797a2884444cc884444cc2e1717392e171739"
    "93c4c45793c4c45755a7a7f255a7a7f2fc7e7e82fc7e7e827a3d3d477a3d3d47"
    "c86464acc86464acba5d5de7ba5d5de73219192b3219192be6737395e6737395"
    "c06060a0c06060a019818198198181989e4f4fd19e4f4fd1a3dcdc7fa3dcdc7f"
    "4422226644222266542a2a7e542a2a7e3b9090ab3b9090ab0b8888830b888883"
    "8c4646ca8c4646cac7eeee29c7eeee296bb8b8d36bb8b8d32814143c2814143c"
    "a7dede79a7dede79bc5e5ee2bc5e5ee2160b0b1d160b0b1daddbdb76addbdb76"
    "dbe0e03bdbe0e03b6432325664323256743a3a4e743a3a4e140a0a1e140a0a1e"
    "924949db924949db0c06060a0c06060a4824246c4824246cb85c5ce4b85c5ce4"
    "9fc2c25d9fc2c25dbdd3d36ebdd3d36e43acacef43acacefc46262a6c46262a6"
    "399191a8399191a8319595a4319595a4d3e4e437d3e4e437f279798bf279798b"
    "d5e7e732d5e7e7328bc8c8438bc8c8436e3737596e373759da6d6db7da6d6db7"
    "018d8d8c018d8d8cb1d5d564b1d5d5649c4e4ed29c4e4ed249a9a9e049a9a9e0"
    "d86c6cb4d86c6cb4ac5656faac5656faf3f4f407f3f4f407cfeaea25cfeaea25"
    "ca6565afca6565aff47a7a8ef47a7a8e47aeaee947aeaee91008081810080818"
    "6fbabad56fbabad5f0787888f07878884a25256f4a25256f5c2e2e725c2e2e72"
    "381c1c24381c1c2457a6a6f157a6a6f173b4b4c773b4b4c797c6c65197c6c651"
    "cbe8e823cbe8e823a1dddd7ca1dddd7ce874749ce874749c3e1f1f213e1f1f21"
    "964b4bdd964b4bdd61bdbddc61bdbddc0d8b8b860d8b8b860f8a8a850f8a8a85"
    "e0707090e07070907c3e3e427c3e3e4271b5b5c471b5b5c4cc6666aacc6666aa"
    "904848d8904848d80603030506030305f7f6f601f7f6f6011c0e0e121c0e0e12"
    "c26161a3c26161a36a35355f6a35355fae5757f9ae5757f969b9b9d069b9b9d0"
    "178686911786869199c1c15899c1c1583a1d1d273a1d1d27279e9eb9279e9eb9"
    "d9e1e138d9e1e138ebf8f813ebf8f8132b9898b32b9898b32211113322111133"
    "d26969bbd26969bba9d9d970a9d9d970078e8e89078e8e89339494a7339494a7"
    "2d9b9bb62d9b9bb63c1e1e223c1e1e221587879215878792c9e9e920c9e9e920"
    "87cece4987cece49aa5555ffaa5555ff5028287850282878a5dfdf7aa5dfdf7a"
    "038c8c8f038c8c8f59a1a1f859a1a1f809898980098989801a0d0d171a0d0d17"
    "65bfbfda65bfbfdad7e6e631d7e6e631844242c6844242c6d06868b8d06868b8"
    "824141c3824141c3299999b0299999b05a2d2d775a2d2d771e0f0f111e0f0f11"
    "7bb0b0cb7bb0b0cba85454fca85454fc6dbbbbd66dbbbbd62c16163a2c16163a")

OPS_KEY = struct.unpack("<4I", bytes.fromhex("d1b5e39e5eea049d671dd5abd2afcbaf"))
OPS_MBOX = {
    5: [0x60, 0x8a, 0x3f, 0x2d, 0x68, 0x6b, 0xd4, 0x23, 0x51, 0x0c,
        0xd0, 0x95, 0xbb, 0x40, 0xe9, 0x76, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0a, 0x00],
    6: [0xAA, 0x69, 0x82, 0x9E, 0x5D, 0xDE, 0xB1, 0x3D, 0x30, 0xBB,
        0x81, 0xA3, 0x46, 0x65, 0xa3, 0xe1, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0a, 0x00],
    4: [0xC4, 0x5D, 0x05, 0x71, 0x99, 0xDD, 0xBB, 0xEE, 0x29, 0xA1,
        0x6D, 0xC7, 0xAD, 0xBF, 0xA4, 0x3F, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0a, 0x00],
}


def echo(msg):
    """Write one line to the console.

    Args:
        msg: The text to print."""
    print(str(_log_tr(msg)))


def _pro_dir():
    """Return the current project directory.

    Returns:
        str: The project directory when it exists, an empty string otherwise."""
    for key in ("WORK_PRO", "RNA_PRO", "DNA_PRO"):
        val = os.getenv(key)
        if val and os.path.isdir(val):
            return val
    return ""


def resolve_input(path):
    """Resolve an input path.

    The out directory of the project and the working directory are searched as a
    fallback.

    Args:
        path: The raw path.

    Returns:
        str: The absolute path, the input when it is not found."""
    path = (path or "").strip().strip('"')
    if not path:
        return path
    if os.path.isfile(path):
        return os.path.abspath(path)
    name = os.path.basename(path)
    roots = []
    pro = _pro_dir()
    if pro:
        roots.append(os.path.join(pro, "out"))
        roots.append(pro)
    for key in ("WORK_DRO", "RNA_DRO", "DNA_DRO"):
        val = os.getenv(key)
        if val:
            roots.append(val)
    roots.append(os.getcwd())
    for root in roots:
        cand = os.path.join(root, name)
        if os.path.isfile(cand):
            return os.path.abspath(cand)
    return path


def aes_cfb(data, key, iv):
    """Decrypt data with AES-128-CFB.

    Args:
        data: The ciphertext.
        key: The 16 byte key.
        iv: The 16 byte IV.

    Returns:
        bytes: The plaintext."""
    return AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).decrypt(data)


def _nibble_swap(ch):
    """Swap the nibbles of a byte.

    Args:
        ch: The input byte.

    Returns:
        int: The byte with the nibbles swapped."""
    return ((ch & 0xF) << 4) + ((ch & 0xF0) >> 4)


def _rol8(x, n=4):
    """Rotate an 8 bit value to the left.

    Args:
        x: The input byte.
        n: The number of bits.

    Returns:
        int: The result."""
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _deobfuscate(data, mask):
    """Undo the obfuscation, an xor with the mask and a rotate of the nibbles by
    four bits.

    Args:
        data: The bytes to undo.
        mask: A mask of the same length.

    Returns:
        bytearray: The bytes without the obfuscation."""
    return bytearray(_rol8(data[i] ^ mask[i]) for i in range(len(data)))


def ozip_keytest(data, extra_keys=None):
    """Try the candidate keys and see whether the plain ozip magic comes out.

    Args:
        data: The 16 bytes of cipher text at 0x1050.
        extra_keys: The extra keys that are tried first.

    Returns:
        bytes: The key that matched, None when there is none."""
    for key in list(extra_keys or []):
        try:
            if AES.new(key, AES.MODE_ECB).decrypt(data)[:4] in OZIP_MAGICS:
                return key
        except ValueError:
            continue
    for key in OZIP_KEYS:
        raw = unhexlify(key)
        if AES.new(raw, AES.MODE_ECB).decrypt(data)[:4] in OZIP_MAGICS:
            return raw
    return None


def parse_key_text(text):
    """Read the user input as a 16 byte AES key.

    Args:
        text: A 32 or 64 digit hex string, 16 characters or any other string.

    Returns:
        bytes: The key, None when it cannot be read."""
    text = (text or "").strip().strip('"').strip("'")
    if not text:
        return None
    if re.fullmatch(r"[0-9a-fA-F]{32}", text):
        return unhexlify(text)
    if re.fullmatch(r"[0-9a-fA-F]{64}", text):
        return unhexlify(text)[:16]
    try:
        data = text.encode("utf-8")
    except Exception:
        return None
    if len(data) == 16:
        return data
    if len(data) > 16:
        return hashlib.md5(data).digest()
    return None


def custom_key_file():
    """Find the file with the custom keys.

    Returns:
        str: The path of the file, an empty string when it is not there."""
    for key in ("OPPO_KEYS", "RNA_OPPO_KEYS", "DNA_OPPO_KEYS"):
        val = os.getenv(key)
        if val:
            return val
    pro = _pro_dir()
    if pro:
        cand = os.path.join(pro, "oppo_keys.txt")
        if os.path.isfile(cand):
            return cand
    local = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oppo_keys.txt")
    if os.path.isfile(local):
        return local
    return ""


def load_custom_keys():
    """Load the AES-128 keys from the file with the custom keys.

    Returns:
        list: The keys, without duplicates."""
    keys = []
    path = custom_key_file()
    if not path:
        return keys
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                key = parse_key_text(line.split("#", 1)[0].strip())
                if key and key not in keys:
                    keys.append(key)
    except OSError as exc:
        debug("read custom keys failed: {}".format(exc))
    if keys:
        debug("custom keys from {}: {}".format(path, [k.hex().upper() for k in keys]))
    return keys


def ozip_resolve_key(ct16, rec=None, custom_key=""):
    """Find the AES key of an ozip.

    The key of the user is tried first, then the file with the custom keys, then the
    built in table and finally the recovery image.

    Args:
        ct16: The 16 bytes of cipher text at 0x1050.
        rec: The path of the recovery image.
        custom_key: The key text of the user.

    Returns:
        bytes: The key that matched, None when it fails."""
    extra = []
    user_key = parse_key_text(custom_key)
    if user_key:
        extra.append(user_key)
        echo("> Using the given key: {}".format(user_key.hex().upper()))
    for key in load_custom_keys():
        if key not in extra:
            extra.append(key)
    key = ozip_keytest(ct16, extra)
    if key:
        return key
    if rec:
        rec_path = resolve_input(rec)
        if rec_path and os.path.isfile(rec_path):
            echo("> None of the built in keys matched, extracting from the recovery image: {}".format(os.path.basename(rec_path)))
            keys = rec_extract_keys(rec_path, ct16)
            for key in keys:
                if key:
                    return key
    echo("> Unknown AES key; use --custom_key to give one or --rec to extract it from a recovery image")
    return None


def ozip_find_key(src, rec=None, custom_key=""):
    """Read the cipher text of an ozip and find its key.

    Args:
        src: The path of the ozip.
        rec: The path of the recovery image.
        custom_key: The key text of the user.

    Returns:
        bytes: The key that matched, None when it fails."""
    # The ozip header: from 0x1050 there are 16 AES-ECB encrypted bytes that have to decrypt to PK/AVB0/ANDR.
    with open(src, "rb") as f:
        f.seek(0x1050)
        data = f.read(16)
    return ozip_resolve_key(data, rec, custom_key)


def ozip_oracle_probe(src):
    """Read the 16 bytes that verify the key, they sit at 0x1050 of an ozip.

    Args:
        src: The path of the ozip.

    Returns:
        bytes: The cipher text, an empty string when it cannot be read."""
    try:
        with open(src, "rb") as f:
            f.seek(0x1050)
            return f.read(16)
    except OSError:
        return b""


def _scan_oracle_blob(blob, ciphertext):
    """Brute force the AES keys of a binary blob, the ones that decrypt the
    magic are the right ones.

    Args:
        blob: The data to scan.
        ciphertext: The cipher text that verifies the key.

    Returns:
        bytes: The key that matched, None when there is none."""
    n = len(blob) - 16
    i = 0
    last_report = 0
    while i <= n:
        if i - last_report >= (16 * 1024 * 1024):
            echo("> Scanning the recovery image ... {}%".format(i * 100 // max(n, 1)))
            last_report = i
        k = blob[i:i + 16]
        i += 1
        if k[0] == k[1] == k[2] == k[3] == k[4]:
            continue
        try:
            if AES.new(k, AES.MODE_ECB).decrypt(ciphertext)[:4] in OZIP_MAGICS:
                return k
        except ValueError:
            continue
    return None


_AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")

_AES_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _aes128_expand(key16):
    """Expand an AES-128 key into the 176 bytes of round keys.

    Args:
        key16: The 16 byte key.

    Returns:
        bytes: The round keys."""
    words = [int.from_bytes(key16[i:i + 4], "little") for i in range(0, 16, 4)]
    out = bytearray(key16)
    for i in range(4, 44):
        t = words[i - 1]
        if i % 4 == 0:
            t = ((t << 8) & 0xFFFFFFFF) | (t >> 24)
            t = (_AES_SBOX[(t >> 24) & 0xFF] << 24) | (_AES_SBOX[(t >> 16) & 0xFF] << 16) | \
                (_AES_SBOX[(t >> 8) & 0xFF] << 8) | _AES_SBOX[t & 0xFF]
            t ^= _AES_RCON[i // 4 - 1] << 24
        w = words[i - 4] ^ t
        words.append(w)
        out += w.to_bytes(4, "little")
    return bytes(out)


def _findaes_schedule(region):
    """Scan a binary region for the table of an expanded AES-128 key.

    Args:
        region: The data to scan.

    Returns:
        list: The candidate keys that were found."""
    n = len(region)
    if n < 176:
        return []
    found = []
    sb = _AES_SBOX
    i = 0
    limit = n - 176
    while i <= limit:
        k0 = region[i:i + 16]
        t = int.from_bytes(k0[12:16], "little")
        t = ((t << 8) & 0xFFFFFFFF) | (t >> 24)
        t = (sb[(t >> 24) & 0xFF] << 24) | (sb[(t >> 16) & 0xFF] << 16) | \
            (sb[(t >> 8) & 0xFF] << 8) | sb[t & 0xFF]
        t ^= 0x01000000
        w4 = int.from_bytes(k0[0:4], "little") ^ t
        if int.from_bytes(region[i + 16:i + 20], "little") != w4:
            i += 1
            continue
        full = _aes128_expand(k0)
        if region[i:i + 176] == full:
            found.append(k0)
            i += 176
            continue
        i += 1
    return found


def rec_extract_keys(rec_path, oracle_ct16=None):
    """Extract the candidate ozip AES-128 keys from a recovery image.

        Raw ELF and shared objects, the Android boot image, the compressed ramdisk
        formats, the newc cpio and the zip archives are supported. With an oracle the
        cipher text is decrypted with ECB until the magic matches, otherwise the table
        of an expanded AES-128 key is scanned.

    Args:
        rec_path: The path of the recovery image.
        oracle_ct16: The cipher text that verifies the key.

    Returns:
        list: The candidate keys."""
    if AES is None:
        return []
    try:
        with open(rec_path, "rb") as f:
            base = f.read(REC_MAX_BLOB + 1)
    except OSError as exc:
        debug("rec read failed: {}".format(exc))
        return []
    if len(base) > REC_MAX_BLOB:
        echo("> Warning: the recovery image is larger than {}MB, only the first {}MB are scanned".format(
            REC_MAX_BLOB // (1024 * 1024), REC_MAX_BLOB // (1024 * 1024)))
    keys = []
    seen = set()
    for key in OZIP_KEYS:
        seen.add(unhexlify(key))
    if oracle_ct16 and len(oracle_ct16) >= 16:
        for label, blob in _iter_rec_blobs(base):
            echo("> Scanned: {} ({}KB)".format(label, len(blob) // 1024))
            key = _scan_oracle_blob(blob, oracle_ct16)
            if key and key not in seen:
                seen.add(key)
                keys.append(key)
                echo("> A key was extracted from {}: {}".format(label, key.hex().upper()))
            if keys:
                break
    for label, blob in _iter_rec_blobs(base):
        for key in _findaes_schedule(blob):
            if key not in seen:
                seen.add(key)
                keys.append(key)
                echo("> A candidate key was found (key schedule): {} <{}>".format(key.hex().upper(), label))
    return keys


def _parse_android_bootimg(data):
    """Parse an Android boot image and locate the ramdisk.

    Args:
        data: The image data.

    Returns:
        list: The (name, offset, size) triples, None when it is not a boot image."""
    if data[:8] != b"ANDROID!":
        return None
    try:
        header_version = struct.unpack("<I", data[40:44])[0]
        if header_version in (3, 4):
            ramdisk_size = struct.unpack("<I", data[16:20])[0]
            return [("ramdisk", 0x1000, ramdisk_size)]
        kernel_size, ramdisk_size = struct.unpack("<II", data[8:16])
        page_size = struct.unpack("<I", data[36:40])[0]
        if page_size == 0 or page_size > 0x100000:
            page_size = 0x800
        pages = lambda n: ((n + page_size - 1) // page_size) if n else 0
        off = page_size * (1 + pages(kernel_size))
        return [("ramdisk", off, ramdisk_size)]
    except struct.error:
        return None


def _try_decompress_blob(data):
    """Try to decompress a block, the magic decides how.

    Args:
        data: The compressed data.

    Returns:
        bytes: The decompressed data, None when the format is unknown or the
            decompression fails."""
    if data[:2] == b"\x1f\x8b":
        import gzip
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as g:
                return g.read()
        except Exception:
            return None
    if data[:4] == b"\x04\x22\x4d\x18":
        try:
            import lz4.frame as lz4f
            with lz4f.open(io.BytesIO(data)) as f:
                return f.read()
        except Exception:
            return None
    if data[:4] == (0x184C2102).to_bytes(4, "little"):
        try:
            from .lz4_legacy import decompress_lz4_buffer
            return decompress_lz4_buffer(io.BytesIO(data))
        except Exception:
            return None
    if data[:6] == b"\xfd7zXZ\x00":
        try:
            import lzma
            return lzma.LZMADecompressor().decompress(data)
        except Exception:
            return None
    if data[:4] == b"\x28\xb5\x2f\xfd":
        try:
            import zstandard
            return zstandard.ZstdDecompressor().decompress(data, max_output_size=REC_MAX_BLOB)
        except Exception:
            return None
    if data[:3] == b"BZh":
        try:
            import bz2
            return bz2.decompress(data)
        except Exception:
            return None
    if data[:4] == b"\x89LZO":
        try:
            from minilzo import decompress as lzo_decompress
        except Exception:
            return None
        header = struct.unpack(">BBI", data[9:17])
        out = bytearray(header[2])
        try:
            pos = data.find(b"\x11\x00\x00", 32)
            if pos < 0:
                return None
            lzo_decompress(data[pos:], out, len(out))
            return bytes(out)
        except Exception:
            return None
    return None


def _cpio_entries(data):
    """Parse the entry table of a newc CPIO archive.

    Args:
        data: The CPIO data.

    Returns:
        list: The (name, data offset, size) triples."""
    entries = []
    pos = 0
    seen = 0
    while pos + 110 <= len(data) and seen < 4096:
        if data[pos:pos + 6] != b"070701":
            break
        try:
            fields = [int(data[pos + i * 8:pos + (i + 1) * 8], 16) for i in range(13)]
        except ValueError:
            break
        namesize, filesize = fields[6 + 4], fields[6 + 6]
        name_start = pos + 110
        name = data[name_start:name_start + namesize - 1]
        file_start = (name_start + namesize + 3) & ~3
        if name in (b"TRAILER!!!", b"."):
            if name == b"TRAILER!!!":
                break
        else:
            entries.append((name.decode("utf-8", "replace"), file_start, filesize))
        pos = (file_start + filesize + 3) & ~3
        if filesize == 0 and name == b"TRAILER!!!":
            break
        seen += 1
    return entries


def _iter_rec_blobs(data):
    """Walk the recovery image and list the boot, cpio, zip and compressed
    payloads in it.

    Args:
        data: The data of the recovery image.

    Yields:
        tuple: (tag, block)."""
    stack = [("root", data, 0)]
    yielded = set()
    while stack:
        label, blob, depth = stack.pop(0)
        if depth > REC_MAX_LAYERS:
            continue
        if id(blob) not in yielded:
            yielded.add(id(blob))
            yield label, blob
        targets = []
        boot = _parse_android_bootimg(blob)
        if boot:
            for name, off, size in boot:
                if off + size <= len(blob) and size > 0:
                    targets.append((name, blob[off:off + size]))
        if blob[:6] == b"070701":
            for name, off, size in _cpio_entries(blob):
                if size == 0 or size > REC_MAX_BLOB:
                    continue
                if off + size <= len(blob):
                    targets.append((name, blob[off:off + size]))
        if blob[:2] == b"PK":
            try:
                with zipfile.ZipFile(io.BytesIO(blob)) as z:
                    for info in z.infolist():
                        if info.file_size == 0 or info.file_size > REC_MAX_BLOB:
                            continue
                        targets.append((info.filename, z.read(info)))
            except Exception:
                pass
        if blob[:2] == b"\x1f\x8b" or blob[:4] in (b"\x04\x22\x4d\x18", (0x184C2102).to_bytes(4, "little"),
                                                  b"\xfd7zXZ\x00"[:4], b"\x28\xb5\x2f\xfd", b"BZh") \
                or blob[:6] == b"\xfd7zXZ\x00" or blob[:4] == b"\x89LZO":
            raw = _try_decompress_blob(blob)
            if raw:
                targets.append(("raw", raw))
        for name, target in targets:
            stack.append((name, target, depth + 1))


def rec_scan_keys(src, quiet=False):
    """Scan the recovery image for the keys, the ozip of the same source is the
    oracle.

    Args:
        src: The path of the ozip.
        quiet: Kept for the callers.

    Returns:
        list: The candidate keys."""
    return rec_extract_keys(src, ozip_oracle_probe(src))


def _ozip_out_name(src):
    """Derive the name of the output zip from the name of the ozip.

    Args:
        src: The path of the ozip.

    Returns:
        str: The name of the output file."""
    base = os.path.basename(src)
    if base.lower().endswith(".ozip"):
        return base[:-4] + "zip"
    return base + ".dec.zip"


def ozip_decrypt_alt(key, src, dst):
    """Decrypt a whole ozip with the spaced ECB layout.

    Every block is 16 bytes of cipher text followed by 0x4000 bytes of plain
    text, the blocks are handled in parallel.

    Args:
        key: The AES key.
        src: The path of the ozip.
        dst: The path of the output."""
    step = 16 + 0x4000
    total = max(0, os.path.getsize(src) - 0x1050)
    jobs = []
    pos = 0
    while pos < total:
        jobs.append((0x1050 + pos, pos))
        pos += step
    rf = os.open(src, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    wf = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o644)
    try:
        def work(job):
            """Decrypt one fragment of the spaced ECB layout.

    Args:
        job: (input offset, output offset)."""
            in_off, out_off = job
            head = _pread(rf, 16, in_off)
            if len(head) < 16:
                return
            _pwrite(wf, AES.new(key, AES.MODE_ECB).decrypt(head), out_off)
            plain = _pread(rf, 0x4000, in_off + 16)
            if plain:
                _pwrite(wf, plain, out_off + 16)
        _run_jobs(jobs, work, worker_threads())
    finally:
        os.close(rf)
        os.close(wf)


def ozip_decrypt_ecb_member(key, src, dst):
    """Decrypt a single ECB encrypted member of a zip.

    Args:
        key: The AES key.
        src: The path of the member.
        dst: The path of the output."""
    with open(src, "rb") as rf:
        rf.seek(0x10)
        dsize = int(rf.read(0x10).replace(b"\x00", b"").decode("utf-8"), 10)
    total = min(dsize, max(0, os.path.getsize(src) - 0x1050))
    if total <= 0:
        open(dst, "wb").close()
        return
    jobs = []
    off = 0
    while off < total:
        size = min(0x4000, total - off)
        jobs.append((0x1050 + off, off, size))
        off += size
    rf = os.open(src, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    wf = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o644)
    try:
        def work(job):
            """Decrypt one fragment of the ECB layout.

    Args:
        job: (input offset, output offset, length)."""
            in_off, out_off, size = job
            data = _pread(rf, size, in_off)
            pad = (-len(data)) % 16
            if pad:
                data += b"\x00" * pad
            _pwrite(wf, AES.new(key, AES.MODE_ECB).decrypt(data)[:size], out_off)
        _run_jobs(jobs, work, worker_threads())
    finally:
        os.close(rf)
        os.close(wf)


def ozip_extract_whole(src, out_dir, rec=None, custom_key=""):
    """Decrypt a whole ozip and write the zip.

    Args:
        src: The path of the ozip.
        out_dir: The output directory.
        rec: The path of the recovery image.
        custom_key: The key text of the user.

    Returns:
        list: The files that were written, an empty list on failure."""
    key = ozip_find_key(src, rec, custom_key)
    if key is None:
        return []
    dst = os.path.join(out_dir, _ozip_out_name(src))
    echo("> Decrypted {}".format(os.path.basename(dst)))
    ozip_decrypt_alt(key, src, dst)
    return [dst]


def _ozip_extract_member_to(zobj, name, tmp_path):
    """Unpack a member of a zip to a temporary path.

    Args:
        zobj: The ZipFile object.
        name: The name of the member.
        tmp_path: The path of the target."""
    info = zobj.getinfo(name)
    org = info.filename
    info.filename = os.path.basename(tmp_path)
    zobj.extract(info, os.path.dirname(tmp_path) or ".")
    info.filename = org


def ozip_extract_zip_metadata(src, out_dir, tmp_dir, rec=None, custom_key=""):
    """Decrypt a zip style ozip that carries an oppo_metadata.

    Args:
        src: The path of the ozip.
        out_dir: The output directory.
        tmp_dir: The temporary directory.
        rec: The path of the recovery image.
        custom_key: The key text of the user.

    Returns:
        list: The files that were written, an empty list on failure."""
    key = None
    clist = []
    with zipfile.ZipFile(src, "r") as zo:
        try:
            with zo.open("oppo_metadata") as rt:
                for line in rt:
                    line = line.rstrip(b"\r\n").decode("utf-8", "replace")
                    if line:
                        clist.append(line)
        except KeyError:
            return []
        fname = ""
        for cand in ("firmware-update/vbmeta.img", "vbmeta.img"):
            if cand in zo.namelist():
                fname = cand
                break
        if not fname:
            echo("> Not found: vbmeta.img <ozip, no key could be extracted>")
            return []
        _ozip_extract_member_to(zo, fname, os.path.join(tmp_dir, "keyprobe"))
        with open(os.path.join(tmp_dir, "keyprobe"), "rb") as rt:
            rt.seek(0x1050)
            key = ozip_resolve_key(rt.read(16), rec, custom_key)
        if key is None:
            return []
        outzip = os.path.join(out_dir, _ozip_out_name(src))
        echo("> Decrypted {}".format(os.path.basename(outzip)))
        with zipfile.ZipFile(outzip, "w", zipfile.ZIP_DEFLATED) as wobj:
            for info in zo.infolist():
                name = info.filename
                if name == "oppo_metadata":
                    continue
                tmp_path = os.path.join(tmp_dir, "member")
                _ozip_extract_member_to(zo, name, tmp_path)
                if name in clist:
                    echo("> Decrypted {}".format(name))
                    dec_path = tmp_path + ".dec"
                    ozip_decrypt_ecb_member(key, tmp_path, dec_path)
                    wobj.write(dec_path, name)
                    os.remove(dec_path)
                else:
                    wobj.write(tmp_path, name)
                os.remove(tmp_path)
    return [outzip]


def ozip_decrypt_member_stream(key, src, dst):
    """Decrypt a chunked OPPOENCRYPT! stream.

    Args:
        key: The AES key.
        src: The path of the member.
        dst: The path of the output.

    Returns:
        int: 0 on success, 1 when the format does not match."""
    ctx = AES.new(key, AES.MODE_ECB)
    with open(src, "rb") as rf, open(dst, "wb") as wf:
        rf.seek(0x50)
        bstart = 0
        while True:
            rf.seek(bstart)
            header = rf.read(12)
            if len(header) < 12:
                break
            if header != b"OPPOENCRYPT!":
                return 1
            rf.seek(0x10 + bstart)
            bdsize = int(rf.read(0x10).replace(b"\x00", b"").decode("utf-8"), 10)
            rf.seek(0x50 + bstart)
            while bdsize > 0:
                data = rf.read(0x10)
                if not data:
                    break
                size = min(0x10, bdsize)
                dr = ctx.decrypt(data)
                wf.write(dr[:size])
                bdsize -= size
                data = rf.read(0x3FF0)
                if not data:
                    break
                take = min(len(data), bdsize)
                wf.write(data[:take])
                bdsize -= take
            bstart = bstart + 0x40000 + 0x50
    return 0


def ozip_extract_mode2(src, out_dir, tmp_dir, rec=None, custom_key=""):
    """Decrypt a mode2 ozip whose members start with OPPOENCRYPT!.

    Args:
        src: The path of the ozip.
        out_dir: The output directory.
        tmp_dir: The temporary directory.
        rec: The path of the recovery image.
        custom_key: The key text of the user.

    Returns:
        list: The files that were written, an empty list on failure."""
    key = None
    with zipfile.ZipFile(src, "r") as zo:
        for name in zo.namelist():
            try:
                with zo.open(name) as fh:
                    magic = fh.read(12)
            except Exception:
                continue
            if magic != b"OPPOENCRYPT!" or "boot.img" not in name:
                continue
            tmp_path = os.path.join(tmp_dir, "keyprobe")
            _ozip_extract_member_to(zo, name, tmp_path)
            with open(tmp_path, "rb") as rt:
                rt.seek(0x50)
                key = ozip_resolve_key(rt.read(16), rec, custom_key)
            if key is None:
                return []
            break
        if key is None:
            echo("> Not found: boot.img <ozip, no key could be extracted>")
            return []
        outzip = os.path.join(out_dir, _ozip_out_name(src))
        echo("> Decrypted {}".format(os.path.basename(outzip)))
        with zipfile.ZipFile(outzip, "w", zipfile.ZIP_DEFLATED) as wobj:
            for info in zo.infolist():
                name = info.filename
                tmp_path = os.path.join(tmp_dir, "member")
                _ozip_extract_member_to(zo, name, tmp_path)
                with open(tmp_path, "rb") as rt:
                    magic = rt.read(12)
                if magic == b"OPPOENCRYPT!":
                    echo("> Decrypted {}".format(name))
                    dec_path = tmp_path + ".dec"
                    if ozip_decrypt_member_stream(key, tmp_path, dec_path) == 1:
                        echo("> Extraction failed! ! ! ")
                        return []
                    wobj.write(dec_path, name)
                    os.remove(dec_path)
                else:
                    wobj.write(tmp_path, name)
                os.remove(tmp_path)
    return [outzip]


def qc_keysets():
    """Expand the Qualcomm OFP key sets.

    Yields:
        tuple: (version tag, AES key, IV)."""
    for dkey in QC_KEYSETS:
        mc = bytearray.fromhex(dkey[1])
        userkey = bytearray.fromhex(dkey[2])
        ivec = bytearray.fromhex(dkey[3])
        # The user key and the IV are xored with the rotated mask nibbles, the first 16 bytes of the MD5 become the AES-CFB parameters.
        key = (hashlib.md5(bytes(_deobfuscate(userkey, mc))).hexdigest()[:16]).encode()
        iv = (hashlib.md5(bytes(_deobfuscate(ivec, mc))).hexdigest()[:16]).encode()
        yield dkey[0], key, iv


def qc_extract_xml(src, key, iv):
    """Decrypt the ProFile.xml from the last page of an OFP.

    Args:
        src: The path of the OFP.
        key: The AES key.
        iv: The IV.

    Returns:
        tuple: (page size, the XML bytes), (0, b"") on failure."""
    filesize = os.path.getsize(src)
    pagesize = 0
    # The magic of the last Qualcomm OFP page is 0x7CEF, the XML offset is aligned to the page size (0x200/0x1000) and decrypted with CFB.
    with open(src, "rb") as rf:
        for x in (0x200, 0x1000):
            rf.seek(filesize - x + 0x10)
            if struct.unpack("<I", rf.read(4))[0] == 0x7CEF:
                pagesize = x
                break
        if pagesize == 0:
            return 0, b""
        xmloffset = filesize - pagesize
        rf.seek(xmloffset + 0x14)
        offset = struct.unpack("<I", rf.read(4))[0] * pagesize
        length = struct.unpack("<I", rf.read(4))[0]
        if length < 200:
            length = xmloffset - offset - 0x57
        if length <= 0 or length > filesize:
            return 0, b""
        rf.seek(offset)
        data = rf.read(length)
    dec = aes_cfb(data, key, iv)
    if b"<?xml" in dec:
        return pagesize, dec[:dec.rfind(b">") + 1]
    return 0, b""


def _copy_stream(rf, wf, length):
    """Copy a number of bytes in blocks.

    Args:
        rf: The source stream.
        wf: The target stream.
        length: The number of bytes to copy.

    Returns:
        int: The number of bytes that were copied."""
    rlen = 0
    while length > 0:
        size = min(length, CHUNK)
        data = rf.read(size)
        if not data:
            break
        wf.write(data)
        rlen += len(data)
        length -= len(data)
    return rlen


def qc_copy_region(src, dst, start, length, checksums):
    """Copy a range of an OFP as it is and check the hashes.

    Args:
        src: The source file.
        dst: The target file.
        start: The start offset.
        length: The length.
        checksums: The expected (sha256, md5)."""
    with open(src, "rb") as rf, open(dst, "wb") as wf:
        rf.seek(start)
        _copy_stream(rf, wf, length)
    qc_check_hashes(dst, checksums, True)


def qc_check_hashes(path, checksums, iscopy):
    """Check the MD5 and the SHA256 of an extracted file.

    Args:
        path: The path of the file.
        checksums: The expected (sha256, md5).
        iscopy: It was copied as it is, this only shows up in the log."""
    sha256sum, md5sum = checksums
    md5status = "empty"
    sha256status = "empty"
    sha256bad = False
    md5bad = False
    size = os.path.getsize(path)
    with open(path, "rb") as rf:
        head = rf.read(0x40000)
        md5 = hashlib.md5(head)
        if sha256sum:
            sha256 = hashlib.sha256()
            sha256.update(head)
            if size > 0x40000:
                for chunk in iter(lambda: rf.read(CHUNK), b""):
                    sha256.update(chunk)
            if sha256sum == sha256.hexdigest():
                sha256status = "verified"
            else:
                sha256bad = True
                sha256status = "bad"
        if md5sum:
            if md5sum == md5.hexdigest():
                md5status = "verified"
            else:
                md5bad = True
                md5status = "bad"
    if (sha256bad and md5bad) or (sha256bad and not md5sum) or (md5bad and not sha256sum):
        echo("> Warning: the hash of {} does not match, the file may be damaged".format(os.path.basename(path)))
    else:
        debug("qc hash {} (md5: {} | sha256: {})".format(path, md5status, sha256status))


def qc_decryptitem(item, pagesize):
    """Read the file information out of a node of the ProFile.xml.

    Args:
        item: The XML node.
        pagesize: The size of a page.

    Returns:
        tuple: (file name, start offset, length, real length, [sha256, md5])."""
    sha256sum = ""
    md5sum = ""
    wfilename = ""
    start = -1
    rlength = 0
    length = 0
    if "Path" in item.attrib:
        wfilename = item.attrib["Path"]
    elif "filename" in item.attrib:
        wfilename = item.attrib["filename"]
    if "sha256" in item.attrib:
        sha256sum = item.attrib["sha256"]
    if "md5" in item.attrib:
        md5sum = item.attrib["md5"]
    if "FileOffsetInSrc" in item.attrib:
        start = int(item.attrib["FileOffsetInSrc"]) * pagesize
    elif "SizeInSectorInSrc" in item.attrib:
        start = int(item.attrib["SizeInSectorInSrc"]) * pagesize
    if "SizeInByteInSrc" in item.attrib:
        rlength = int(item.attrib["SizeInByteInSrc"])
    if "SizeInSectorInSrc" in item.attrib:
        length = int(item.attrib["SizeInSectorInSrc"]) * pagesize
    else:
        length = rlength
    return wfilename, start, length, rlength, [sha256sum, md5sum]


def qc_extract(src, out_dir):
    """Try every Qualcomm key set and extract the OFP.

    Args:
        src: The path of the OFP.
        out_dir: The output directory.

    Returns:
        list: The files that were written, an empty list on failure."""
    for _name, key, iv in qc_keysets():
        pagesize, xml = qc_extract_xml(src, key, iv)
        if pagesize:
            break
    else:
        echo("> Unknown key, ProFile.xml cannot be decrypted")
        return []
    return qc_extract_with(src, out_dir, key, iv, pagesize, xml)


def qc_extract_with(src, out_dir, key, iv, pagesize, xml):
    """Extract the partitions of a Qualcomm OFP with the XML that was
    decrypted already.

    Args:
        src: The path of the OFP.
        out_dir: The output directory.
        key: The AES key.
        iv: The IV.
        pagesize: The size of a page.
        xml: The bytes of the ProFile.xml.

    Returns:
        list: The files that were written."""
    import xml.etree.ElementTree as ET
    info_path = os.path.join(out_dir, "ProFile.xml")
    with open(info_path, "wb") as wf:
        wf.write(xml)
    root = ET.fromstring(xml.decode("utf-8"))
    files = []
    for child in root:
        for item in child:
            if "Path" not in item.attrib and "filename" not in item.attrib:
                for subitem in item:
                    wfilename, start, length, rlength, checksums = qc_decryptitem(subitem, pagesize)
                    if wfilename == "" or start == -1:
                        continue
                    files.append(qc_region(src, out_dir, child.tag, wfilename, start, length,
                                           rlength, checksums, key, iv, QC_DECRYPT_CHUNK))
            wfilename, start, length, rlength, checksums = qc_decryptitem(item, pagesize)
            if wfilename == "" or start == -1:
                continue
            ds = rlength if child.tag == "Sahara" else QC_DECRYPT_CHUNK
            ln = rlength if child.tag in ("Config", "Provision", "ChainedTableOfDigests",
                                          "DigestsToSign", "Firmware") else length
            files.append(qc_region(src, out_dir, child.tag, wfilename, start, ln,
                                   rlength, checksums, key, iv, ds))
    return files


def qc_region(src, out_dir, tag, wfilename, start, length, rlength, checksums, key, iv, decryptsize):
    """Extract or decrypt a single region of a Qualcomm OFP.

    Args:
        src: The path of the OFP.
        out_dir: The output directory.
        tag: The tag of the XML node.
        wfilename: The path of the output, relative to the output directory.
        start: The start offset.
        length: The number of bytes to copy.
        rlength: The real length.
        checksums: The expected (sha256, md5).
        key: The AES key.
        iv: The IV.
        decryptsize: The size of the blocks that are decrypted.

    Returns:
        str: The path of the output."""
    dst = os.path.join(out_dir, wfilename.replace("\\", "/").lstrip("/"))
    parent = os.path.dirname(dst)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    if tag in ("DigestsToSign", "ChainedTableOfDigests", "Firmware"):
        echo("> Extracted {}".format(wfilename))
        qc_copy_region(src, dst, start, length, checksums)
    else:
        echo("> Decrypted {}".format(wfilename))
        with open(src, "rb") as rf, open(dst, "wb") as wf:
            rf.seek(start)
            size = min(rlength, decryptsize)
            data = rf.read(size)
            if len(data) % 4:
                data += (4 - (len(data) % 4)) * b"\x00"
            wf.write(aes_cfb(data, key, iv)[:size])
            remain = rlength - size
            if remain > 0:
                _copy_stream(rf, wf, remain)
        qc_check_hashes(dst, checksums, False)
    return dst


def mtk_shuffle(key, keylength, data, inputlength):
    """The MediaTek nibble swap xor.

    It is used to undo the obfuscation of a key and to decrypt the table at
    the end.

    Args:
        key: The obfuscated key.
        keylength: The length of the key.
        data: The bytes to work on.
        inputlength: The number of bytes to process.

    Returns:
        bytearray: The result."""
    for i in range(inputlength):
        k = key[i % keylength]
        h = (((data[i]) & 0xF0) >> 4) | (16 * ((data[i]) & 0xF))
        data[i] = k ^ h
    return data


def mtk_getkey(index):
    """Expand the AES key and the IV of one index of the MediaTek OFP key
    table.

    Args:
        index: The index in the key table.

    Returns:
        tuple: (AES key, IV)."""
    kt = MTK_KEYTABLES[index]
    if len(kt) == 3:
        obskey = bytearray(unhexlify(kt[0]))
        encaeskey = bytearray(unhexlify(kt[1]))
        encaesiv = bytearray(unhexlify(kt[2]))
        aeskey = hexlify(hashlib.md5(bytes(mtk_shuffle(obskey, 16, encaeskey, 16))).digest())[:16]
        aesiv = hexlify(hashlib.md5(bytes(mtk_shuffle(obskey, 16, encaesiv, 16))).digest())[:16]
    else:
        aeskey = bytes(kt[0], "utf-8")
        aesiv = bytes(kt[1], "utf-8")
    return aeskey, aesiv


def mtk_brutekey(head16):
    """Try the MediaTek keys with the header of the file.

    Args:
        head16: The first 16 bytes of the header.

    Returns:
        tuple: (AES key, IV), (None, None) when nothing matched."""
    for keyid in range(len(MTK_KEYTABLES)):
        aeskey, aesiv = mtk_getkey(keyid)
        ctx = AES.new(aeskey, AES.MODE_CFB, IV=aesiv, segment_size=128)
        data = ctx.decrypt(head16)
        if data[:3] == b"MMM":
            return aeskey, aesiv
    return None, None


def mtk_extract(src, out_dir):
    """Decrypt a MediaTek OFP.

    The keys are tried, the table at the end is decrypted and the partitions are
    written.

        Args:
            src: The path of the OFP.
            out_dir: The output directory.

        Returns:
            list: The files that were written, an empty list on failure."""
    hdrkey = bytearray(b"geyixue")
    filesize = os.path.getsize(src)
    hdrlength = 0x6C
    with open(src, "rb") as rf:
        head = rf.read(16)
        aeskey, aesiv = mtk_brutekey(head)
        if aeskey is None:
            echo("> Unknown key, the ofp-mtk payload cannot be decrypted")
            return []
        # The 0x6C byte project header at the end and the partition table are obfuscated with the fixed string geyixue.
        rf.seek(filesize - hdrlength)
        hdr = mtk_shuffle(hdrkey, len(hdrkey), bytearray(rf.read(hdrlength)), hdrlength)
        prjname, _unknown, _reserved, cpu, flashtype, hdr2entries, prjinfo, _crc = \
            struct.unpack("46s Q 4s 7s 5s H 32s H", bytes(hdr))
        prjname = prjname.replace(b"\x00", b"").decode("utf-8", "replace")
        cpu = cpu.replace(b"\x00", b"").decode("utf-8", "replace")
        flashtype = flashtype.replace(b"\x00", b"").decode("utf-8", "replace")
        prjinfo = prjinfo.replace(b"\x00", b"").decode("utf-8", "replace")
        if prjname:
            echo("> Item: {}".format(prjname))
        if cpu:
            echo("> CPU: {}".format(cpu))
        if flashtype:
            echo("> Flash: {}".format(flashtype))
        if prjinfo:
            echo("> Info: {}".format(prjinfo))
        hdr2length = hdr2entries * 0x60
        rf.seek(filesize - hdr2length - hdrlength)
        hdr2 = mtk_shuffle(hdrkey, len(hdrkey), bytearray(rf.read(hdr2length)), hdr2length)
        files = []
        for i in range(len(hdr2) // 0x60):
            name, start, length, enclength, filename, _crc = \
                struct.unpack("<32s Q Q Q 32s Q", bytes(hdr2[i * 0x60:(i * 0x60) + 0x60]))
            name = name.replace(b"\x00", b"").decode("utf-8", "replace")
            filename = filename.replace(b"\x00", b"").decode("utf-8", "replace")
            echo("> Decrypted {} -> {}".format(name, filename))
            dst = os.path.join(out_dir, filename)
            with open(dst, "wb") as wb:
                rf.seek(start)
                if enclength > 0:
                    ctx = AES.new(aeskey, AES.MODE_CFB, IV=aesiv, segment_size=128)
                    remain = enclength
                    while remain > 0:
                        n = min(CHUNK, remain)
                        data = rf.read(n)
                        if not data:
                            break
                        pad = (-len(data)) % 16
                        if pad:
                            data += b"\x00" * pad
                        out = ctx.decrypt(data)
                        take = min(len(data) - pad, remain)
                        wb.write(out[:take])
                        remain -= take
                    length -= enclength
                while length > 0:
                    size = min(0x200000, length)
                    data = rf.read(size)
                    if not data:
                        break
                    wb.write(data)
                    length -= len(data)
            files.append(dst)
        return files


def _gsbox(offset):
    """Read a 4 byte little endian word from the S-Box of the OPS.

    Args:
        offset: The offset of the byte.

    Returns:
        int: The value."""
    return int.from_bytes(OPS_SBOX[offset:offset + 4], "little")


def _key_update(iv1, asbox):
    """Update the round keys of the OPS stream cipher.

    Args:
        iv1: The current round key.
        asbox: The MBox of the version.

    Returns:
        list: The four new 32 bit round keys."""
    d = iv1[0] ^ asbox[0]
    a = iv1[1] ^ asbox[1]
    b = iv1[2] ^ asbox[2]
    c = iv1[3] ^ asbox[3]
    e = _gsbox(((b >> 0x10) & 0xff) * 8 + 2) ^ _gsbox(((a >> 8) & 0xff) * 8 + 3) ^ _gsbox((c >> 0x18) * 8 + 1) ^ \
        _gsbox((d & 0xff) * 8) ^ asbox[4]
    h = _gsbox(((c >> 0x10) & 0xff) * 8 + 2) ^ _gsbox(((b >> 8) & 0xff) * 8 + 3) ^ _gsbox((d >> 0x18) * 8 + 1) ^ \
        _gsbox((a & 0xff) * 8) ^ asbox[5]
    i = _gsbox(((d >> 0x10) & 0xff) * 8 + 2) ^ _gsbox(((c >> 8) & 0xff) * 8 + 3) ^ _gsbox((a >> 0x18) * 8 + 1) ^ \
        _gsbox((b & 0xff) * 8) ^ asbox[6]
    a = _gsbox(((d >> 8) & 0xff) * 8 + 3) ^ _gsbox(((a >> 0x10) & 0xff) * 8 + 2) ^ _gsbox((b >> 0x18) * 8 + 1) ^ \
        _gsbox((c & 0xff) * 8) ^ asbox[7]
    g = 8
    for f in range(asbox[0x3c] - 2):
        d = e >> 0x18
        m = h >> 0x10
        s = h >> 0x18
        z = e >> 0x10
        l = i >> 0x18
        t = e >> 8
        e = _gsbox(((i >> 0x10) & 0xff) * 8 + 2) ^ _gsbox(((h >> 8) & 0xff) * 8 + 3) ^ \
            _gsbox((a >> 0x18) * 8 + 1) ^ _gsbox((e & 0xff) * 8) ^ asbox[g]
        h = _gsbox(((a >> 0x10) & 0xff) * 8 + 2) ^ _gsbox(((i >> 8) & 0xff) * 8 + 3) ^ \
            _gsbox(d * 8 + 1) ^ _gsbox((h & 0xff) * 8) ^ asbox[g + 1]
        i = _gsbox((z & 0xff) * 8 + 2) ^ _gsbox(((a >> 8) & 0xff) * 8 + 3) ^ \
            _gsbox(s * 8 + 1) ^ _gsbox((i & 0xff) * 8) ^ asbox[g + 2]
        a = _gsbox((t & 0xff) * 8 + 3) ^ _gsbox((m & 0xff) * 8 + 2) ^ \
            _gsbox(l * 8 + 1) ^ _gsbox((a & 0xff) * 8) ^ asbox[g + 3]
        g = g + 4
    return [(_gsbox(((i >> 0x10) & 0xff) * 8) & 0xff0000) ^ (_gsbox(((h >> 8) & 0xff) * 8 + 1) & 0xff00) ^
            (_gsbox((a >> 0x18) * 8 + 3) & 0xff000000) ^ _gsbox((e & 0xff) * 8 + 2) & 0xFF ^ asbox[g],
            (_gsbox(((a >> 0x10) & 0xff) * 8) & 0xff0000) ^ (_gsbox(((i >> 8) & 0xff) * 8 + 1) & 0xff00) ^
            (_gsbox((e >> 0x18) * 8 + 3) & 0xff000000) ^ (_gsbox((h & 0xff) * 8 + 2) & 0xFF) ^ asbox[g + 3],
            (_gsbox(((e >> 0x10) & 0xff) * 8) & 0xff0000) ^ (_gsbox(((a >> 8) & 0xff) * 8 + 1) & 0xff00) ^
            (_gsbox((h >> 0x18) * 8 + 3) & 0xff000000) ^ (_gsbox((i & 0xff) * 8 + 2) & 0xFF) ^ asbox[g + 2],
            (_gsbox(((h >> 0x10) & 0xff) * 8) & 0xff0000) ^ (_gsbox(((e >> 8) & 0xff) * 8 + 1) & 0xff00) ^
            (_gsbox((i >> 0x18) * 8 + 3) & 0xff000000) ^ (_gsbox((a & 0xff) * 8 + 2) & 0xFF) ^ asbox[g + 1]]


class OpsStream(object):
    """The stream cipher of the OPS firmware: the round keys are updated every
        16 bytes and the data is xored."""

    def __init__(self, mbox, encrypt=False):
        """Set up the state of the stream.

    Args:
        mbox: The MBox of the version.
        encrypt: True to encrypt, False to decrypt."""
        self.rkey = list(OPS_KEY)
        self.mbox = mbox
        self.encrypt = encrypt
        self._buf = b""
        self._blocks = 0

    def _block(self, block):
        """Process one 16 byte block.

    Args:
        block: The 16 bytes of the input.

    Returns:
        bytes: The output block."""
        self.rkey = _key_update(self.rkey, self.mbox)
        words = [int.from_bytes(block[i * 4:(i + 1) * 4], "little") for i in range(4)]
        tmp = [self.rkey[i] ^ words[i] for i in range(4)]
        self.rkey = tmp if self.encrypt else words
        self._blocks += 1
        return b"".join(w.to_bytes(4, "little") for w in tmp)

    def update(self, data):
        """Process the whole blocks of 16 bytes.

    The rest that is shorter than 16 bytes is kept inside.

    Args:
        data: The input data.

    Returns:
        bytes: The output data."""
        buf = self._buf + data
        full = len(buf) // 0x10
        out = bytearray()
        for i in range(full):
            out += self._block(buf[i * 0x10:(i + 1) * 0x10])
        self._buf = buf[full * 0x10:]
        return bytes(out)

    def finish(self):
        """Flush the padding of the last block.

    Returns:
        bytes: The output that is left."""
        if not self._buf:
            return b""
        if self._blocks == 0:
            rkey = _key_update(self.rkey, OPS_SBOX)
            out = bytearray()
            j = 0
            m = 0
            length = len(self._buf)
            while length > 0:
                data = self._buf[j:j + 4]
                if len(data) < 4:
                    data += b"\x00" * (4 - len(data))
                tmp = int.from_bytes(data, "little")
                out += (tmp ^ rkey[m]).to_bytes(4, "little")
                length -= 4
                j += 4
                m += 1
            self._buf = b""
            return bytes(out)
        block = self._buf + b"\x00" * (0x10 - len(self._buf))
        out = self._block(block)
        self._buf = b""
        return out


def ops_crypt_stream(rf, wf, length, mbox, encrypt=False):
    """Encrypt or decrypt a number of bytes of OPS data in a stream.

    Args:
        rf: The source stream.
        wf: The target stream.
        length: The number of bytes to process.
        mbox: The MBox of the version.
        encrypt: True to encrypt, False to decrypt."""
    cipher = OpsStream(mbox, encrypt)
    remain = length
    while remain > 0:
        n = min(CHUNK, remain)
        data = rf.read(n)
        if not data:
            break
        out = cipher.update(data)
        if remain < len(out):
            out = out[:remain]
        wf.write(out)
        remain -= len(out)
    if remain > 0:
        out = cipher.finish()
        wf.write(out[:remain])


def ops_crypt_bytes(data, mbox, encrypt=False):
    """Encrypt or decrypt a buffer of OPS data.

    Args:
        data: The input data.
        mbox: The MBox of the version.
        encrypt: True to encrypt, False to decrypt.

    Returns:
        bytes: The output data."""
    cipher = OpsStream(mbox, encrypt)
    return cipher.update(data) + cipher.finish()


def ops_extract_xml(src, out_dir, mbox):
    """Decrypt the settings.xml from the end of an OPS.

    Args:
        src: The path of the OPS.
        out_dir: The output directory.
        mbox: The MBox of the version.

    Returns:
        str: The XML text, None on failure."""
    filesize = os.path.getsize(src)
    with open(src, "rb") as rf:
        rf.seek(filesize - 0x200)
        hdr = rf.read(0x200)
        xmllength = int.from_bytes(hdr[0x18:0x18 + 4], "little")
        if xmllength <= 0 or xmllength > filesize - 0x400:
            return None
        xmlpad = 0x200 - (xmllength % 0x200)
        rf.seek(filesize - 0x200 - (xmllength + xmlpad))
        cipher = OpsStream(mbox)
        out = bytearray()
        remain = xmllength + xmlpad
        while remain > 0:
            data = rf.read(min(CHUNK, remain))
            if not data:
                break
            out += cipher.update(data)
            remain -= len(data)
        out += cipher.finish()
    if b"xml " not in bytes(out[:xmllength + 64]):
        return None
    xml = bytes(out[:xmllength])
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "settings.xml"), "wb") as wf:
        wf.write(xml)
    return xml.decode("utf-8", "replace")


def ops_copy_region(src, dst, start, length):
    """Copy a range of an OPS as it is.

    Args:
        src: The source file.
        dst: The target file.
    start: The start offset.
    length: The length."""
    with open(src, "rb") as rf, open(dst, "wb") as wf:
        rf.seek(start)
        _copy_stream(rf, wf, length)


def ops_calc_digest(path):
    """Compute the SHA256 of a file.

    The part that is below 4K is padded with zeros.

    Args:
        path: The path of the file.

    Returns:
        str: The SHA256 as hex."""
    sha256 = hashlib.sha256()
    with open(path, "rb") as rf:
        for chunk in iter(lambda: rf.read(CHUNK), b""):
            sha256.update(chunk)
        size = os.path.getsize(path)
        if size % 0x1000 > 0:
            sha256.update(b"\x00" * (0x1000 - (size % 0x1000)))
    return sha256.hexdigest()


def ops_extract(src, out_dir):
    """Extract the partitions of an OPS with the settings.xml.

    Args:
        src: The path of the OPS.
        out_dir: The output directory.

    Returns:
        list: The files that were written, an empty list on failure."""
    import xml.etree.ElementTree as ET
    mbox = None
    xml = None
    # MBox5/6/4 are tried in turn, the version is known once settings.xml comes out.
    for version in (5, 6, 4):
        xml = ops_extract_xml(src, out_dir, OPS_MBOX[version])
        if xml is not None:
            mbox = OPS_MBOX[version]
            echo("> MBox{}".format(version))
            break
    if xml is None:
        echo("> Unknown key, the ops payload cannot be decrypted")
        return []
    root = ET.fromstring(xml)
    if root.tag in ("SAHARA", "UFS_PROVISION") or "Program" in root.tag:
        sections = [root]
    else:
        sections = list(root)
    files = []
    for child in sections:
        if child.tag == "SAHARA":
            for item in child:
                if item.tag != "File":
                    continue
                wfilename = item.attrib["Path"]
                start = int(item.attrib["FileOffsetInSrc"]) * 0x200
                length = int(item.attrib["SizeInByteInSrc"])
                echo("> Decrypted {}".format(wfilename))
                dst = os.path.join(out_dir, wfilename)
                with open(src, "rb") as rf, open(dst, "wb") as wf:
                    rf.seek(start)
                    ops_crypt_stream(rf, wf, length, mbox)
                files.append(dst)
        elif child.tag == "UFS_PROVISION" or "Program" in child.tag:
            items = []
            for item in child:
                if "filename" in item.attrib or "Path" in item.attrib:
                    items.append(item)
                else:
                    items.extend(item)
            for item in items:
                try:
                    wfilename = item.attrib["Path"]
                except Exception:
                    wfilename = item.attrib["filename"]
                if not wfilename:
                    continue
                start = int(item.attrib["FileOffsetInSrc"]) * 0x200
                length = int(item.attrib["SizeInByteInSrc"])
                echo("> Extracted {}".format(wfilename))
                dst = os.path.join(out_dir, wfilename)
                ops_copy_region(src, dst, start, length)
                sha256 = item.attrib.get("Sha256", "")
                if sha256 and sha256 != ops_calc_digest(dst) and item.attrib.get("sparse") != "true":
                    echo("> Warning: the sha256 of {} does not match".format(wfilename))
                files.append(dst)
    return files


def detect_oppo(src):
    """Detect the type of the firmware of OPPO, Realme or OnePlus.

    Args:
        src: The path of the firmware.

    Returns:
        str: The type (ozip, ofp-qc, ofp-mtk, ops, ...), unknow when it is not
            known."""
    with open(src, "rb") as f:
        magic = f.read(16)
    # The magic, the zip members and the last page tell ozip, ofp-qc, ofp-mtk and ops apart.
    if magic[:12] == b"OPPOENCRYPT!":
        return "ozip"
    if magic[:2] == b"PK":
        with zipfile.ZipFile(src) as z:
            names = z.namelist()
        if "oppo_metadata" in names:
            return "ozip-zip"
        with zipfile.ZipFile(src) as z:
            infos = z.infolist()
            if infos and infos[0].flag_bits & 0x1:
                try:
                    with z.open(infos[0], pwd=QC_ZIP_PASSWORD) as fh:
                        fh.read(16)
                    return "ofp-qc-zip"
                except Exception:
                    pass
        with zipfile.ZipFile(src) as z:
            for name in names:
                try:
                    with z.open(name) as fh:
                        if fh.read(12) == b"OPPOENCRYPT!":
                            return "ozip-mode2"
                except Exception:
                    continue
        return "unknow"
    if len(magic) >= 16:
        key, iv = mtk_brutekey(magic)
        if key is not None:
            return "ofp-mtk"
    filesize = os.path.getsize(src)
    if filesize >= 0x600:
        with open(src, "rb") as f:
            for pagesize in (0x200, 0x1000):
                if filesize < pagesize:
                    continue
                f.seek(filesize - pagesize + 0x10)
                magic4 = f.read(4)
                if len(magic4) == 4 and struct.unpack("<I", magic4)[0] == 0x7CEF:
                    for _name, key, iv in qc_keysets():
                        ps, xml = qc_extract_xml(src, key, iv)
                        if ps:
                            return "ofp-qc"
                    break
    if filesize > 0x400:
        for version in (5, 6, 4):
            with open(src, "rb") as f:
                f.seek(filesize - 0x200)
                hdr = f.read(0x200)
            xmllength = int.from_bytes(hdr[0x18:0x18 + 4], "little")
            if 0 < xmllength < filesize - 0x400:
                xmlpad = 0x200 - (xmllength % 0x200)
                with open(src, "rb") as f:
                    f.seek(filesize - 0x200 - (xmllength + xmlpad))
                    data = f.read(min(xmllength + xmlpad, CHUNK))
                out = ops_crypt_bytes(data, OPS_MBOX[version])
                if b"xml " in out[:xmllength + 64]:
                    return "ops"
    return "unknow"




KIND_LABELS = {
    "ozip": "ozip",
    "ozip-zip": "ozip",
    "ozip-mode2": "ozip",
    "ofp-qc": "ofp-qc",
    "ofp-qc-zip": "ofp-qc",
    "ofp-mtk": "ofp-mtk",
    "ops": "ops",
}


def run_oppo(args):
    """Detect the firmware and decrypt it according to its type.

    Args:
        args: The parsed arguments with the file, out, rec, custom_key, auto and
        delete fields."""
    if AES is None:
        echo("> Missing dependency: pip install pycryptodome")
        echo("> Details: " + (_AES_IMPORT_ERROR or "unknown"))
        return
    src = resolve_input(getattr(args, "file", ""))
    if not src or not os.path.isfile(src):
        echo("> Not found: {}".format(src or "<empty>"))
        return
    out = (getattr(args, "out", "") or "").strip()
    if not out:
        pro = _pro_dir()
        out = pro if pro else os.path.dirname(src)
    out = os.path.abspath(out)
    os.makedirs(out, exist_ok=True)
    tmp_dir = os.path.join(out, "oppo_tmp")
    os.makedirs(tmp_dir, exist_ok=True)
    debug("oppo_decrypt src={} out={}".format(file_info(src), out))
    try:
        kind = detect_oppo(src)
    except Exception as exc:
        debug_exc("oppo detect failed: ")
        echo("> The firmware could not be identified: {}".format(exc))
        return
    if kind == "unknow":
        echo("> Unsupported format: {} <oppo>".format(os.path.basename(src)))
        echo("> Hint: unpack a standard OTA zip with the unzip command")
        return
    label = KIND_LABELS.get(kind, kind)
    echo("> Start the extraction: {} <{}>".format(os.path.basename(src), label))
    rec = resolve_input(getattr(args, "rec", "") or "")
    if rec and not os.path.isfile(rec):
        echo("> Not found: {} <recovery>".format(rec))
        rec = ""
    custom_key = getattr(args, "custom_key", "") or ""
    try:
        if kind == "ozip":
            files = ozip_extract_whole(src, out, rec, custom_key)
        elif kind == "ozip-zip":
            files = ozip_extract_zip_metadata(src, out, tmp_dir, rec, custom_key)
        elif kind == "ozip-mode2":
            files = ozip_extract_mode2(src, out, tmp_dir, rec, custom_key)
        elif kind == "ofp-qc-zip":
            files = []
            with zipfile.ZipFile(src) as z:
                for name in z.namelist():
                    echo("> Decompressed {}".format(name))
                    z.extract(name, out, pwd=QC_ZIP_PASSWORD)
                    files.append(os.path.join(out, name))
        elif kind == "ofp-qc":
            files = qc_extract(src, out)
        elif kind == "ofp-mtk":
            files = mtk_extract(src, out)
        elif kind == "ops":
            files = ops_extract(src, out)
        else:
            files = []
    except Exception as exc:
        debug_exc("oppo extract failed: ")
        echo("> Extracting the OPPO firmware failed: {}".format(exc))
        return
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
    if not files:
        return
    echo("> Extraction complete, files are in: {}".format(out))
    if int(getattr(args, "delete", 0) or 0):
        try:
            os.remove(src)
        except OSError as exc:
            debug("delete source failed: {}".format(exc))


def parse_argv(argv):
    """Parse the oppo_decrypt command line arguments.

    Args:
        argv: The argument list without the program name.

    Returns:
        Namespace: The parsed arguments."""
    p = argparse.ArgumentParser(prog="oppo_decrypt", description="Decrypt OPPO/Realme/OnePlus ozip, ofp, ops firmware")
    p.add_argument("file", help="Path to ozip/ofp/ops firmware file")
    p.add_argument("--custom_key", dest="custom_key", default="",
                   help="User supplied AES-128 key (32 hex chars, 16 chars, or any string md5-derived)")
    p.add_argument("--rec", default="", help="Recovery image/binary for static AES key extraction when built-in keys fail")
    p.add_argument("--out", default="", help="Output directory (default: current project)")
    p.add_argument("--delete", help="Delete source after decrypt (default is 0)", type=int, default=0)
    p.add_argument("--debug", action="store_true", help="Enable debug output")
    return p.parse_args(argv)


def run_oppo_extract_key(args):
    """Extract the ozip keys from a recovery image and save them.

    Args:
        args: The parsed arguments with the rec and ozip fields."""
    if AES is None:
        echo("> Missing dependency: pip install pycryptodome")
        echo("> Details: " + (_AES_IMPORT_ERROR or "unknown"))
        return
    rec = resolve_input(getattr(args, "rec", ""))
    if not rec or not os.path.isfile(rec):
        echo("> Not found: {}".format(rec or "<empty>"))
        return
    ozip = resolve_input(getattr(args, "ozip", "") or "")
    if ozip and not os.path.isfile(ozip):
        echo("> Not found: {}".format(ozip))
        ozip = ""
    oracle = ozip_oracle_probe(ozip) if ozip else b""
    if ozip and len(oracle) >= 16:
        echo("> Using the oracle: {} (0x1050)".format(os.path.basename(ozip)))
    else:
        oracle = None
        echo("> No ozip was given, the key schedule was scanned (the result has to be checked by hand)")
    keys = rec_extract_keys(rec, oracle)
    if not keys:
        echo("> No usable key was found in the recovery image")
        return
    echo("")
    echo("Found {} keys:".format(len(keys)))
    for key in keys:
        echo("  {}".format(key.hex().upper()))
    saved = save_extracted_keys(keys, oracle)
    if saved:
        echo("")
        echo("> The key was saved: {}".format(saved))
        echo("> oppo_decrypt loads this file automatically")


KEYS_HEADER = "# OPPO ozip AES keys (one 32-hex-char key per line, # comment)\n"


def save_extracted_keys(new_keys, oracle_ct16=None):
    """Merge the new keys into oppo_keys.txt.

    Args:
        new_keys: The keys that were found.
        oracle_ct16: The cipher text that verifies a key, unused for now.

    Returns:
        str: The path of the key file, an empty string when it could not be
        saved."""
    path = custom_key_file() or os.path.join(
        _pro_dir() or os.path.dirname(os.path.abspath(__file__)), "oppo_keys.txt")
    existing = []
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    key = parse_key_text(line.split("#", 1)[0].strip())
                    if key and key not in existing:
                        existing.append(key)
        except OSError:
            pass
    merged = list(existing)
    added = 0
    for key in new_keys:
        if key not in merged:
            merged.append(key)
            added += 1
    if not added:
        debug("no new keys to save to {}".format(path))
        return path
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(KEYS_HEADER)
            for key in merged:
                f.write(key.hex().upper() + "\n")
        os.replace(tmp, path)
    except OSError as exc:
        debug_exc("save keys failed: ")
        echo("> Saving the key failed: {}".format(exc))
        return ""
    debug("saved {} new key(s) to {}".format(added, path))
    return path


def parse_extract_key_argv(argv):
    """Parse the command line arguments of the key extraction.

    Args:
        argv: The argument list without the program name.

    Returns:
        Namespace: The parsed arguments."""
    p = argparse.ArgumentParser(prog="oppo_extract_key", description="Extract OPPO ozip AES keys from a recovery image")
    p.add_argument("rec", help="Path to recovery image/binary (bootimg, ramdisk, cpio, ELF)")
    p.add_argument("ozip", nargs="?", default="", help="Optional ozip file used as decryption oracle")
    p.add_argument("--debug", action="store_true", help="Enable debug output")
    return p.parse_args(argv)


def main(argv=None):
    """The command line entry point, it decrypts ozip, ofp and ops.

    Args:
        argv: The argument list, sys.argv by default."""
    args = parse_argv(sys.argv[1:] if argv is None else argv)
    try:
        from .log import apply_args as _apply
        _apply(args)
    except Exception:
        if getattr(args, "debug", False):
            from .log import set_debug
            set_debug(True)
    run_oppo(args)


def main_extract_key(argv=None):
    """The command line entry point, it extracts the keys from a recovery
    image.

    Args:
        argv: The argument list, sys.argv by default."""
    args = parse_extract_key_argv(sys.argv[1:] if argv is None else argv)
    try:
        from .log import apply_args as _apply
        _apply(args)
    except Exception:
        if getattr(args, "debug", False):
            from .log import set_debug
            set_debug(True)
    run_oppo_extract_key(args)


if __name__ == "__main__":
    main()
