from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class KdfError(ValueError):
    """Raised when HKDF derivation fails."""


def hkdf_sha256(ikm: bytes, *, salt: bytes, info: bytes, length: int) -> bytes:
    if not isinstance(ikm, (bytes, bytearray)):
        raise KdfError("ikm must be bytes")
    if length <= 0:
        raise KdfError("length must be positive")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(bytes(ikm))
