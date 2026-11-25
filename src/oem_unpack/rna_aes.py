#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A very small stand in for pycryptodome, used by oppo_decrypt.

On Android the native extension of the Termux build of pycryptodome depends on
its own library, which cannot be loaded inside the sandbox of the app, so
this module implements the same subset of the interface with the
cryptography package that is shipped anyway:

    AES.new(key, AES.MODE_ECB|MODE_CBC|MODE_CFB, iv=..., segment_size=128)
    the object offers encrypt(data) / decrypt(data)
    AES.block_size / AES.key_size
    pad(data, block_size) / unpad(data, block_size)  (PKCS7)

Only the parts that oppo_decrypt uses are covered, both the iv and the IV
keyword work."""

from cryptography.hazmat.primitives import padding as _padding
from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher
from cryptography.hazmat.primitives.ciphers import algorithms as _algorithms
from cryptography.hazmat.primitives.ciphers import modes as _modes

try:
    # cryptography >= 48 moved CFB into the decrepit module
    from cryptography.hazmat.decrepit.ciphers.modes import CFB as _CFB
except Exception:
    from cryptography.hazmat.primitives.ciphers.modes import CFB as _CFB

MODE_ECB = 1
MODE_CBC = 2
MODE_CFB = 3

block_size = 16
key_size = (16, 24, 32)


def _make_mode(mode, iv):
    """Map the pycryptodome mode constants to cryptography mode objects.

    Args:
        mode: MODE_ECB / MODE_CBC / MODE_CFB.
        iv: The initial vector, used by the stream and the chained modes.

    Returns:
        The cryptography mode object."""
    if mode == MODE_ECB:
        return _modes.ECB()
    if mode == MODE_CBC:
        return _modes.CBC(iv)
    if mode == MODE_CFB:
        return _CFB(iv)
    raise ValueError("unsupported AES mode: {!r}".format(mode))


class _AESCipher:
    """An AES context driven by cryptography, with the pycryptodome interface."""

    block_size = block_size
    key_size = key_size

    def __init__(self, key, mode, iv):
        """Set up an encrypt or decrypt context from key, mode and iv.

    Args:
        key: The AES key (16, 24 or 32 bytes).
        mode: A MODE_* constant.
        iv: The initial vector."""
        self._encryptor = _Cipher(
            _algorithms.AES(key), _make_mode(mode, iv)
        ).encryptor()
        self._decryptor = _Cipher(
            _algorithms.AES(key), _make_mode(mode, iv)
        ).decryptor()

    def encrypt(self, data):
        """Encrypt a chunk of data.

        Args:
            data: The plaintext.

        Returns:
            bytes: The ciphertext."""
        return self._encryptor.update(data)

    def decrypt(self, data):
        """Decrypt a chunk of data.

        Args:
            data: The ciphertext.

        Returns:
            bytes: The plaintext."""
        return self._decryptor.update(data)


def new(key, mode, iv=None, IV=None, segment_size=None, **kwargs):
    """Create an AES context, the keywords match pycryptodome.

    Args:
        key: The AES key.
        mode: A MODE_* constant.
        iv: The initial vector.
        IV: An alias of the initial vector.
        segment_size: Kept for compatibility, it always works on 128 bits.

    Returns:
        _AESCipher: The encrypt and decrypt context."""
    if iv is None and IV is not None:
        iv = IV
    return _AESCipher(key, mode, iv)


def pad(data, block=block_size):
    """PKCS7 padding.

    Args:
        data: The data to pad.
        block: The block size in bytes.

    Returns:
        bytes: The padded data."""
    padder = _padding.PKCS7(block * 8).padder()
    return padder.update(data) + padder.finalize()


def unpad(data, block=block_size):
    """PKCS7 unpadding.

    Args:
        data: The padded data.
        block: The block size in bytes.

    Returns:
        bytes: The data without padding."""
    unpadder = _padding.PKCS7(block * 8).unpadder()
    return unpadder.update(data) + unpadder.finalize()
