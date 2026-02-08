from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AeadError(ValueError):
    """Raised when AEAD operations fail."""


NONCE_SIZE = 12


@dataclass(frozen=True)
class AeadResult:
    nonce: bytes
    ciphertext: bytes


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes) -> AeadResult:
    if len(key) != 32:
        raise AeadError("AES-256-GCM requires 32-byte key")
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return AeadResult(nonce=nonce, ciphertext=ciphertext)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes) -> bytes:
    if len(key) != 32:
        raise AeadError("AES-256-GCM requires 32-byte key")
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)


def split_ciphertext(data: bytes) -> Tuple[bytes, bytes]:
    if len(data) < NONCE_SIZE + 16:
        raise AeadError("ciphertext too short")
    return data[:NONCE_SIZE], data[NONCE_SIZE:]
