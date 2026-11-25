# -*- coding: utf-8 -*-
"""Tests for the crypto helpers."""

from __future__ import print_function

import hashlib
import os
import random

import pytest

from getrom import crypto

IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
PLAIN = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")


@pytest.mark.parametrize("key_hex,expect", [
    ("2b7e151628aed2a6abf7158809cf4f3c", "7649abac8119b246cee98e9b12e9197d"),
    ("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "4f021db243bc633d7178183a9fa071e8"),
    ("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
     "f58c4c04d6e5f1ba779eabfb5f7bfbd6"),
])
def test_aes_cbc_known_vector(key_hex, expect):
    """The first block of AES-CBC has to match the standard vector."""
    out = crypto.aes_cbc_encrypt(PLAIN, bytes.fromhex(key_hex), IV)
    assert out[:16].hex() == expect


@pytest.mark.parametrize("key_hex,expect", [
    ("2b7e151628aed2a6abf7158809cf4f3c", "874d6191b620e3261bef6864990db6ce"),
    ("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
     "601ec313775789a5b7a7f504bbf3d228"),
])
def test_aes_ctr_known_vector(key_hex, expect):
    """AES-CTR has to match the standard vector."""
    counter = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    assert crypto.aes_ctr(PLAIN, bytes.fromhex(key_hex), counter).hex() == expect


def test_aes_cbc_roundtrip():
    """Encrypting and decrypting has to give the original data back."""
    key = os.urandom(16)
    iv = os.urandom(16)
    data = os.urandom(100)
    blob = crypto.aes_cbc_encrypt(data, key, iv)
    assert crypto.aes_cbc_decrypt(blob, key, iv) == data


def test_aes_ctr_roundtrip():
    """Encrypting and decrypting has to give the original data back."""
    key = os.urandom(32)
    iv = os.urandom(16)
    data = os.urandom(64)
    assert crypto.aes_ctr(crypto.aes_ctr(data, key, iv), key, iv) == data


def test_pkcs7_padding():
    """Padding and unpadding have to undo each other."""
    for size in (0, 1, 15, 16, 17):
        data = os.urandom(size)
        padded = crypto.pkcs7_pad(data)
        assert len(padded) % 16 == 0
        assert crypto.pkcs7_unpad(padded) == data


def _is_probable_prime(num, rounds=12):
    """Tell whether a number is probably a prime.

    Args:
        num: The number to test.
        rounds: The number of Miller-Rabin rounds.

    Returns:
        bool: True when the number is probably a prime.
    """
    if num < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if num % small == 0:
            return num == small
    d = num - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        base = random.randrange(2, num - 1)
        value = pow(base, d, num)
        if value in (1, num - 1):
            continue
        for _ in range(r - 1):
            value = value * value % num
            if value == num - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits):
    """Build a prime of the given size.

    Args:
        bits: The number of bits.

    Returns:
        int: The prime.
    """
    while True:
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def _oaep_decode(cipher, modulus, private_exp, hlen=20):
    """Decrypt with OAEP(SHA1), for the test only.

    Args:
        cipher: The ciphertext.
        modulus: The modulus.
        private_exp: The private exponent.
        hlen: The digest length.

    Returns:
        bytes: The plaintext.
    """
    size = (modulus.bit_length() + 7) // 8
    em = pow(int.from_bytes(cipher, "big"), private_exp, modulus).to_bytes(size, "big")
    masked_seed = em[1:1 + hlen]
    masked_db = em[1 + hlen:]
    seed = bytes(a ^ b for a, b in zip(masked_seed, crypto._mgf1(masked_db, hlen)))
    db = bytes(a ^ b for a, b in zip(masked_db, crypto._mgf1(seed, size - hlen - 1)))
    assert db[:hlen] == hashlib.sha1(b"").digest()
    index = db.find(b"\x01", hlen)
    assert index >= 0
    return db[index + 1:]


def test_rsa_oaep_roundtrip():
    """The RSA-OAEP output has to decrypt back to the original text."""
    random.seed(1234)
    p = _gen_prime(256)
    q = _gen_prime(256)
    modulus = p * q
    exponent = 65537
    private_exp = pow(exponent, -1, (p - 1) * (q - 1))
    message = b"0123456789abcdef"
    cipher = crypto.rsa_oaep_encrypt(message, modulus, exponent)
    assert len(cipher) == (modulus.bit_length() + 7) // 8
    assert _oaep_decode(cipher, modulus, private_exp) == message


def test_rsa_oaep_message_too_long():
    """A message that does not fit has to raise."""
    with pytest.raises(ValueError):
        crypto.rsa_oaep_encrypt(b"x" * 100, 0xC0FFEE, 65537)


def test_parse_rsa_public_key():
    """Parsing the SPKI key has to give a 2048 bit modulus and the exponent 65537."""
    from getrom.vendors import coloros

    modulus, exponent = crypto.parse_rsa_public_key(coloros.COLOROS_PUBLIC_KEY)
    assert modulus.bit_length() == 2048
    assert exponent == 65537


def test_base64_helpers():
    """The Base64 helpers have to undo each other."""
    data = os.urandom(40)
    assert crypto.b64mime_decode(crypto.b64encode(data)) == data
    url_safe = crypto.b64url(data)
    assert crypto.b64mime_decode(url_safe.replace("-", "+").replace("_", "/")) == data
