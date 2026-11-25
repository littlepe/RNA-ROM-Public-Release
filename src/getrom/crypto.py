# -*- coding: utf-8 -*-
"""Pure Python crypto.

Provides AES-128/192/256 (CBC and CTR), RSA-OAEP(SHA1) encryption and a few
Base64 helpers. Everything is implemented in plain Python, without openssl
or pycryptodome, so the behaviour is the same on Windows, macOS, Linux and
Android.

AES-CBC encrypts the Xiaomi OTA requests, RSA-OAEP plus AES-CTR the official
ColorOS / OPPO / OnePlus / Realme OTA queries.
"""

from __future__ import print_function

import base64
import hashlib
import os

# Pure Python AES: S-Box, inverse S-Box and Rcon.
_SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]
_INV = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV[_v] = _i


def _xtime(a):
    """Multiply by 2 in GF(2^8).

    Args:
        a: Input byte.

    Returns:
        int: The resulting byte.
    """
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF


def _mul(a, b):
    """Multiply in GF(2^8).

    Args:
        a: First factor.
        b: Second factor.

    Returns:
        int: The product.
    """
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r & 0xFF


def _expand(key):
    """Expand an AES key into round keys.

    128, 192 and 256 bit keys are supported.

    Args:
        key: The key bytes.

    Returns:
        tuple: (round keys, number of rounds).
    """
    nk = len(key) // 4
    nr = nk + 6
    words = [list(key[i * 4:(i + 1) * 4]) for i in range(nk)]
    rcon = 0x01
    for i in range(nk, 4 * (nr + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= rcon
            rcon = _xtime(rcon)
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        words.append([a ^ b for a, b in zip(words[i - nk], temp)])
    keys = []
    for r in range(nr + 1):
        rk = []
        for word in words[r * 4:(r + 1) * 4]:
            rk.extend(word)
        keys.append(rk)
    return keys, nr


def _add(s, k):
    """Add the round key.

    Args:
        s: State bytes.
        k: Round key bytes.

    Returns:
        list: The new state.
    """
    return [a ^ b for a, b in zip(s, k)]


def _sub(s, box):
    """Substitute the bytes.

    Args:
        s: State bytes.
        box: The S-Box or its inverse.

    Returns:
        list: The new state.
    """
    return [box[b] for b in s]


def _shift(s):
    """Shift the rows.

    Args:
        s: State bytes.

    Returns:
        list: The new state.
    """
    return [
        s[0], s[5], s[10], s[15],
        s[4], s[9], s[14], s[3],
        s[8], s[13], s[2], s[7],
        s[12], s[1], s[6], s[11],
    ]


def _inv_shift(s):
    """Shift the rows backwards.

    Args:
        s: State bytes.

    Returns:
        list: The new state.
    """
    return [
        s[0], s[13], s[10], s[7],
        s[4], s[1], s[14], s[11],
        s[8], s[5], s[2], s[15],
        s[12], s[9], s[6], s[3],
    ]


def _mix(s):
    """Mix the columns.

    Args:
        s: State bytes.

    Returns:
        list: The new state.
    """
    o = []
    for i in range(4):
        c = s[i * 4:(i + 1) * 4]
        o.extend([
            _mul(c[0], 2) ^ _mul(c[1], 3) ^ c[2] ^ c[3],
            c[0] ^ _mul(c[1], 2) ^ _mul(c[2], 3) ^ c[3],
            c[0] ^ c[1] ^ _mul(c[2], 2) ^ _mul(c[3], 3),
            _mul(c[0], 3) ^ c[1] ^ c[2] ^ _mul(c[3], 2),
        ])
    return o


def _inv_mix(s):
    """Mix the columns backwards.

    Args:
        s: State bytes.

    Returns:
        list: The new state.
    """
    o = []
    for i in range(4):
        c = s[i * 4:(i + 1) * 4]
        o.extend([
            _mul(c[0], 14) ^ _mul(c[1], 11) ^ _mul(c[2], 13) ^ _mul(c[3], 9),
            _mul(c[0], 9) ^ _mul(c[1], 14) ^ _mul(c[2], 11) ^ _mul(c[3], 13),
            _mul(c[0], 13) ^ _mul(c[1], 9) ^ _mul(c[2], 14) ^ _mul(c[3], 11),
            _mul(c[0], 11) ^ _mul(c[1], 13) ^ _mul(c[2], 9) ^ _mul(c[3], 14),
        ])
    return o


def _enc_block(block, keys, nr):
    """Encrypt one 16 byte block.

    Args:
        block: The plaintext block.
        keys: The round keys.
        nr: The number of rounds.

    Returns:
        bytes: The ciphertext block.
    """
    s = _add(list(block), keys[0])
    for r in range(1, nr):
        s = _mix(_shift(_sub(s, _SBOX)))
        s = _add(s, keys[r])
    return bytes(_add(_shift(_sub(s, _SBOX)), keys[nr]))


def _dec_block(block, keys, nr):
    """Decrypt one 16 byte block.

    Args:
        block: The ciphertext block.
        keys: The round keys.
        nr: The number of rounds.

    Returns:
        bytes: The plaintext block.
    """
    s = _add(list(block), keys[nr])
    for r in range(nr - 1, 0, -1):
        s = _inv_mix(_add(_inv_shift(_sub(s, _INV)), keys[r]))
    return bytes(_add(_inv_shift(_sub(s, _INV)), keys[0]))


def pkcs7_pad(data, block=16):
    """Pad the data with PKCS7.

    Args:
        data: The raw data.
        block: Block size.

    Returns:
        bytes: The padded data.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    pad = block - (len(data) % block)
    return data + bytes([pad]) * pad


def pkcs7_unpad(data):
    """Strip the PKCS7 padding.

    Args:
        data: The padded data.

    Returns:
        bytes: The data without padding.
    """
    if not data:
        return data
    pad = data[-1]
    if not isinstance(pad, int):
        pad = ord(pad)
    if pad < 1 or pad > 16 or len(data) < pad:
        return data
    tail = data[-pad:]
    if any((b if isinstance(b, int) else ord(b)) != pad for b in tail):
        return data
    return data[:-pad]


def aes_cbc_encrypt(plain, key, iv):
    """Encrypt with AES-CBC.

    Args:
        plain: The plaintext.
        key: The key (16, 24 or 32 bytes).
        iv: The initial vector (16 bytes).

    Returns:
        bytes: The ciphertext, PKCS7 padded.
    """
    data = pkcs7_pad(plain)
    keys, nr = _expand(key)
    outb = []
    prev = list(iv)
    for i in range(0, len(data), 16):
        block = [a ^ b for a, b in zip(data[i:i + 16], prev)]
        enc = _enc_block(block, keys, nr)
        outb.append(enc)
        prev = list(enc)
    return b"".join(outb)


def aes_cbc_decrypt(blob, key, iv):
    """Decrypt with AES-CBC.

    Args:
        blob: The ciphertext.
        key: The key (16, 24 or 32 bytes).
        iv: The initial vector (16 bytes).

    Returns:
        bytes: The plaintext, padding removed.
    """
    keys, nr = _expand(key)
    outb = []
    prev = list(iv)
    for i in range(0, len(blob), 16):
        cur = blob[i:i + 16]
        dec = _dec_block(cur, keys, nr)
        outb.append(bytes([a ^ b for a, b in zip(dec, prev)]))
        prev = list(cur)
    return pkcs7_unpad(b"".join(outb))


def aes_ctr(data, key, iv):
    """Encrypt or decrypt with AES-CTR, the same call does both.

    Args:
        data: The input data.
        key: The key (16, 24 or 32 bytes).
        iv: The counter start value (16 bytes).

    Returns:
        bytes: The output data.
    """
    if not data:
        return b""
    keys, nr = _expand(key)
    out = bytearray()
    counter = int.from_bytes(bytes(iv), "big")
    total = len(data)
    for offset in range(0, total, 16):
        stream = _enc_block(counter.to_bytes(16, "big"), keys, nr)
        chunk = data[offset:offset + 16]
        out.extend(bytes(a ^ b for a, b in zip(chunk, stream)))
        counter = (counter + 1) % (1 << 128)
    return bytes(out)


def _der_read(data, offset):
    """Read one DER element.

    Args:
        data: The DER data.
        offset: The start offset.

    Returns:
        tuple: (tag, content, next offset).
    """
    tag = data[offset]
    offset += 1
    length = data[offset]
    offset += 1
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    return tag, data[offset:offset + length], offset + length


def _pem_body(text):
    """Parse a PEM block.

    Args:
        text: The PEM text.

    Returns:
        tuple: (type, DER data).
    """
    kind = ""
    body = []
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("-----BEGIN "):
            kind = line[len("-----BEGIN "):].strip().rstrip("-").strip()
            continue
        if line.startswith("-----END "):
            break
        if line:
            body.append(line)
    raw = base64.b64decode("".join(body))
    return kind, raw


def parse_rsa_public_key(text):
    """Parse a PEM public key.

    Both SPKI (``BEGIN PUBLIC KEY``) and PKCS#1 (``BEGIN RSA PUBLIC KEY``) are
    supported.

    Args:
        text: The PEM text.

    Returns:
        tuple: (modulus n, exponent e).

    Raises:
        ValueError: When the format is unsupported or parsing fails.
    """
    kind, der = _pem_body(text)
    if not der:
        raise ValueError("empty public key")
    if kind == "RSA PUBLIC KEY":
        rsa = der
    else:
        _, spki, _ = _der_read(der, 0)
        _, _, offset = _der_read(spki, 0)
        _, bits, _ = _der_read(spki, offset)
        rsa = bits[1:]
    _, content, _ = _der_read(rsa, 0)
    _, modulus, offset = _der_read(content, 0)
    _, exponent, _ = _der_read(content, offset)
    return int.from_bytes(modulus, "big"), int.from_bytes(exponent, "big")


def _mgf1(seed, length, hashfunc=hashlib.sha1):
    """The MGF1 mask generation function.

    Args:
        seed: The seed.
        length: The wanted length.
        hashfunc: The hash function.

    Returns:
        bytes: The mask.
    """
    out = b""
    counter = 0
    while len(out) < length:
        out += hashfunc(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def rsa_oaep_encrypt(message, modulus, exponent, hashfunc=hashlib.sha1):
    """Encrypt with RSA-OAEP.

    Args:
        message: The plaintext.
        modulus: The modulus n.
        exponent: The exponent e.
        hashfunc: The digest function.

    Returns:
        bytes: The ciphertext, as long as the modulus.

    Raises:
        ValueError: When the message is too long.
    """
    key_size = (modulus.bit_length() + 7) // 8
    hlen = hashfunc().digest_size
    if len(message) > key_size - 2 * hlen - 2:
        raise ValueError("message too long for RSA key")
    lhash = hashfunc(b"").digest()
    padding = b"\x00" * (key_size - len(message) - 2 * hlen - 2)
    db = lhash + padding + b"\x01" + message
    seed = os.urandom(hlen)
    masked_db = bytes(a ^ b for a, b in zip(db, _mgf1(seed, key_size - hlen - 1, hashfunc)))
    masked_seed = bytes(a ^ b for a, b in zip(seed, _mgf1(masked_db, hlen, hashfunc)))
    em = b"\x00" + masked_seed + masked_db
    cipher = pow(int.from_bytes(em, "big"), exponent, modulus)
    return cipher.to_bytes(key_size, "big")


def rsa_oaep_encrypt_pem(message, pem_text):
    """Encrypt with RSA-OAEP using a PEM public key.

    Args:
        message: The plaintext.
        pem_text: The PEM public key.

    Returns:
        bytes: The ciphertext.
    """
    modulus, exponent = parse_rsa_public_key(pem_text)
    return rsa_oaep_encrypt(message, modulus, exponent)


def b64url(data):
    """Encode with the URL safe Base64 alphabet.

    Args:
        data: The raw bytes.

    Returns:
        str: The encoded text.
    """
    text = base64.urlsafe_b64encode(data)
    if not isinstance(text, str):
        text = text.decode("ascii")
    return text


def b64encode(data):
    """Encode with the standard Base64 alphabet.

    Args:
        data: The raw bytes.

    Returns:
        str: The encoded text.
    """
    text = base64.b64encode(data)
    if not isinstance(text, str):
        text = text.decode("ascii")
    return text


def b64mime_decode(text):
    """Decode standard Base64.

    Args:
        text: The Base64 text.

    Returns:
        bytes: The decoded bytes, padding is added when needed.
    """
    if isinstance(text, bytes):
        text = text.decode("ascii", "replace")
    pad = (-len(text)) % 4
    return base64.b64decode(text + ("=" * pad))
