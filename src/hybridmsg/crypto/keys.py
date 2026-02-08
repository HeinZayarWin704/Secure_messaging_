from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519


class KeyError(ValueError):
    """Raised when key operations fail."""


@dataclass(frozen=True)
class IdentityKeyPair:
    private_key: ed25519.Ed25519PrivateKey
    public_key: ed25519.Ed25519PublicKey


@dataclass(frozen=True)
class SessionKeyPair:
    private_key: x25519.X25519PrivateKey
    public_key: x25519.X25519PublicKey


def generate_identity_keypair() -> IdentityKeyPair:
    private_key = ed25519.Ed25519PrivateKey.generate()
    return IdentityKeyPair(private_key=private_key, public_key=private_key.public_key())


def generate_session_keypair() -> SessionKeyPair:
    private_key = x25519.X25519PrivateKey.generate()
    return SessionKeyPair(private_key=private_key, public_key=private_key.public_key())


def identity_public_bytes(pub: ed25519.Ed25519PublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def session_public_bytes(pub: x25519.X25519PublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def key_id(pub_bytes: bytes) -> str:
    return hashlib.sha256(pub_bytes).hexdigest()[:16]


def save_private_key(path: Path, private_key) -> None:
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem)
    os.chmod(path, 0o600)


def load_identity_private(path: Path) -> ed25519.Ed25519PrivateKey:
    data = path.read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise KeyError("invalid identity private key")
    return key


def load_identity_public(pub_bytes: bytes) -> ed25519.Ed25519PublicKey:
    return ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)


def load_session_public(pub_bytes: bytes) -> x25519.X25519PublicKey:
    return x25519.X25519PublicKey.from_public_bytes(pub_bytes)


def load_session_private(path: Path) -> x25519.X25519PrivateKey:
    data = path.read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, x25519.X25519PrivateKey):
        raise KeyError("invalid session private key")
    return key
