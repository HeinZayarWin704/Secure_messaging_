from __future__ import annotations

import base64
import json
from typing import Any, Dict

from .types import PROTOCOL_VERSION, from_dict, to_dict


class CodecError(ValueError):
    """Raised when packet encoding/decoding fails."""


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(data: str) -> bytes:
    try:
        return base64.b64decode(data.encode("ascii"), validate=True)
    except (ValueError, TypeError) as exc:
        raise CodecError("invalid base64") from exc


def encode_packet(packet: Any) -> bytes:
    payload = to_dict(packet)
    if payload.get("version") != PROTOCOL_VERSION:
        raise CodecError("invalid protocol version")
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"


def decode_packet(raw: bytes) -> Any:
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CodecError("invalid json") from exc
    _validate_payload(data)
    return from_dict(data)


def _validate_payload(data: Dict[str, Any]) -> None:
    if not isinstance(data, dict):
        raise CodecError("payload must be dict")
    if data.get("version") != PROTOCOL_VERSION:
        raise CodecError("protocol version mismatch")
    packet_type = data.get("type")
    if packet_type not in {"hello", "hello_sig", "key_exchange", "confirm", "data"}:
        raise CodecError("unknown packet type")
    for field in ("sender",):
        if field in data and not isinstance(data[field], str):
            raise CodecError("invalid sender")
