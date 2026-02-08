from __future__ import annotations

import time
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from hybridmsg.crypto.kdf import hkdf_sha256
from hybridmsg.crypto.keys import (
    IdentityKeyPair,
    SessionKeyPair,
    identity_public_bytes,
    key_id,
    load_identity_public,
    session_public_bytes,
)
from hybridmsg.protocol import codec
from hybridmsg.protocol.types import Confirm, Hello, HelloSignature, KeyExchange


class HandshakeError(ValueError):
    """Raised when the handshake fails."""


def _timestamp() -> int:
    return int(time.time())


def _sign(private_key: ed25519.Ed25519PrivateKey, payload: bytes) -> bytes:
    return private_key.sign(payload)


def _verify(public_key: ed25519.Ed25519PublicKey, signature: bytes, payload: bytes) -> None:
    try:
        public_key.verify(signature, payload)
    except Exception as exc:  # cryptography raises InvalidSignature
        raise HandshakeError("invalid signature") from exc


def _transcript(*parts: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    for part in parts:
        digest.update(part)
    return digest.finalize()


@dataclass
class HandshakeResult:
    root_key: bytes
    session_key_id: str


@dataclass
class InitiatorState:
    identity: IdentityKeyPair
    session: SessionKeyPair
    hello: Hello
    hello_sig: HelloSignature


@dataclass
class ResponderState:
    name: str
    identity: IdentityKeyPair
    session: SessionKeyPair
    peer_hello: Hello


def initiator_hello(identity: IdentityKeyPair, session: SessionKeyPair, sender: str) -> InitiatorState:
    hello = Hello(
        sender=sender,
        identity_pub=codec.b64encode(identity_public_bytes(identity.public_key)),
        session_pub=codec.b64encode(session_public_bytes(session.public_key)),
        timestamp=_timestamp(),
    )
    payload = codec.encode_packet(hello)
    hello_sig = HelloSignature(
        sender=sender,
        signature=codec.b64encode(_sign(identity.private_key, payload)),
        timestamp=_timestamp(),
    )
    return InitiatorState(identity=identity, session=session, hello=hello, hello_sig=hello_sig)


def responder_accept(
    name: str,
    identity: IdentityKeyPair,
    session: SessionKeyPair,
    hello: Hello,
    signature: HelloSignature,
) -> ResponderState:
    peer_identity_pub = load_identity_public(codec.b64decode(hello.identity_pub))
    payload = codec.encode_packet(hello)
    _verify(peer_identity_pub, codec.b64decode(signature.signature), payload)
    return ResponderState(name=name, identity=identity, session=session, peer_hello=hello)


def responder_key_exchange(state: ResponderState) -> KeyExchange:
    payload = codec.encode_packet(state.peer_hello)
    exchange = KeyExchange(
        sender=state.name,
        identity_pub=codec.b64encode(identity_public_bytes(state.identity.public_key)),
        session_pub=codec.b64encode(session_public_bytes(state.session.public_key)),
        timestamp=_timestamp(),
        signature=codec.b64encode(_sign(state.identity.private_key, payload)),
    )
    return exchange


def initiator_finalize(state: InitiatorState, exchange: KeyExchange) -> Confirm:
    responder_identity_pub = load_identity_public(codec.b64decode(exchange.identity_pub))
    payload = codec.encode_packet(state.hello)
    _verify(responder_identity_pub, codec.b64decode(exchange.signature), payload)
    confirm_payload = _transcript(payload, codec.encode_packet(exchange))
    signature = _sign(state.identity.private_key, confirm_payload)
    return Confirm(sender=state.hello.sender, signature=codec.b64encode(signature), timestamp=_timestamp())


def responder_finalize(state: ResponderState, exchange: KeyExchange, confirm: Confirm) -> HandshakeResult:
    confirm_payload = _transcript(codec.encode_packet(state.peer_hello), codec.encode_packet(exchange))
    peer_pub = load_identity_public(codec.b64decode(state.peer_hello.identity_pub))
    _verify(peer_pub, codec.b64decode(confirm.signature), confirm_payload)
    shared = state.session.private_key.exchange(
        x25519.X25519PublicKey.from_public_bytes(codec.b64decode(state.peer_hello.session_pub))
    )
    root_key = hkdf_sha256(
        shared,
        salt=confirm_payload,
        info=b"hybridmsg-root",
        length=32,
    )
    session_key_id = key_id(codec.b64decode(exchange.session_pub))
    return HandshakeResult(root_key=root_key, session_key_id=session_key_id)


def initiator_result(state: InitiatorState, exchange: KeyExchange) -> HandshakeResult:
    shared = state.session.private_key.exchange(
        x25519.X25519PublicKey.from_public_bytes(codec.b64decode(exchange.session_pub))
    )
    salt = _transcript(codec.encode_packet(state.hello), codec.encode_packet(exchange))
    root_key = hkdf_sha256(
        shared,
        salt=salt,
        info=b"hybridmsg-root",
        length=32,
    )
    session_key_id = key_id(codec.b64decode(exchange.session_pub))
    return HandshakeResult(root_key=root_key, session_key_id=session_key_id)
