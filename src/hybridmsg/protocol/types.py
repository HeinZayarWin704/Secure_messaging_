from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

PROTOCOL_VERSION = 1


@dataclass(frozen=True)
class Hello:
    sender: str
    identity_pub: str
    session_pub: str
    timestamp: int


@dataclass(frozen=True)
class HelloSignature:
    sender: str
    signature: str
    timestamp: int


@dataclass(frozen=True)
class KeyExchange:
    sender: str
    identity_pub: str
    session_pub: str
    timestamp: int
    signature: str


@dataclass(frozen=True)
class Confirm:
    sender: str
    signature: str
    timestamp: int


@dataclass(frozen=True)
class DataMessage:
    sender: str
    receiver: str
    key_id: str
    counter: int
    timestamp: int
    nonce: str
    ciphertext: str


def to_dict(obj: Any) -> Dict[str, Any]:
    if isinstance(obj, Hello):
        return {
            "type": "hello",
            "version": PROTOCOL_VERSION,
            "sender": obj.sender,
            "identity_pub": obj.identity_pub,
            "session_pub": obj.session_pub,
            "timestamp": obj.timestamp,
        }
    if isinstance(obj, HelloSignature):
        return {
            "type": "hello_sig",
            "version": PROTOCOL_VERSION,
            "sender": obj.sender,
            "signature": obj.signature,
            "timestamp": obj.timestamp,
        }
    if isinstance(obj, KeyExchange):
        return {
            "type": "key_exchange",
            "version": PROTOCOL_VERSION,
            "sender": obj.sender,
            "identity_pub": obj.identity_pub,
            "session_pub": obj.session_pub,
            "timestamp": obj.timestamp,
            "signature": obj.signature,
        }
    if isinstance(obj, Confirm):
        return {
            "type": "confirm",
            "version": PROTOCOL_VERSION,
            "sender": obj.sender,
            "signature": obj.signature,
            "timestamp": obj.timestamp,
        }
    if isinstance(obj, DataMessage):
        return {
            "type": "data",
            "version": PROTOCOL_VERSION,
            "sender": obj.sender,
            "receiver": obj.receiver,
            "key_id": obj.key_id,
            "counter": obj.counter,
            "timestamp": obj.timestamp,
            "nonce": obj.nonce,
            "ciphertext": obj.ciphertext,
        }
    raise TypeError("unsupported packet type")


def from_dict(data: Dict[str, Any]) -> Any:
    packet_type = data.get("type")
    if packet_type == "hello":
        return Hello(
            sender=data["sender"],
            identity_pub=data["identity_pub"],
            session_pub=data["session_pub"],
            timestamp=data["timestamp"],
        )
    if packet_type == "hello_sig":
        return HelloSignature(
            sender=data["sender"],
            signature=data["signature"],
            timestamp=data["timestamp"],
        )
    if packet_type == "key_exchange":
        return KeyExchange(
            sender=data["sender"],
            identity_pub=data["identity_pub"],
            session_pub=data["session_pub"],
            timestamp=data["timestamp"],
            signature=data["signature"],
        )
    if packet_type == "confirm":
        return Confirm(
            sender=data["sender"],
            signature=data["signature"],
            timestamp=data["timestamp"],
        )
    if packet_type == "data":
        return DataMessage(
            sender=data["sender"],
            receiver=data["receiver"],
            key_id=data["key_id"],
            counter=data["counter"],
            timestamp=data["timestamp"],
            nonce=data["nonce"],
            ciphertext=data["ciphertext"],
        )
    raise ValueError("unknown packet type")
