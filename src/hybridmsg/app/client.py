from __future__ import annotations

import argparse
import json
import socket
import time
from dataclasses import dataclass
from typing import Iterator, Tuple

from hybridmsg.crypto import aead
from hybridmsg.crypto.kdf import hkdf_sha256
from hybridmsg.crypto.keys import (
    IdentityKeyPair,
    generate_session_keypair,
    load_identity_private,
)
from hybridmsg.protocol import codec
from hybridmsg.protocol.handshake import (
    initiator_finalize,
    initiator_hello,
    initiator_result,
    responder_accept,
    responder_finalize,
    responder_key_exchange,
)
from hybridmsg.protocol.types import Confirm, DataMessage, Hello, HelloSignature, KeyExchange
from hybridmsg.ratchet.state import RatchetState, RatchetError
from hybridmsg.storage.state import Storage, SessionState


@dataclass
class RelayTarget:
    host: str
    port: int


def _now() -> int:
    return int(time.time())


def _load_identity(storage: Storage) -> IdentityKeyPair:
    private_key = load_identity_private(storage.load_identity_private_path())
    public_key = private_key.public_key()
    return IdentityKeyPair(private_key=private_key, public_key=public_key)


def _connect(relay: RelayTarget) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((relay.host, relay.port))
    return sock


def _register(sock: socket.socket, name: str) -> None:
    payload = {"type": "register", "name": name}
    sock.sendall(json.dumps(payload).encode("utf-8") + b"\n")


def _send_route(sock: socket.socket, recipient: str, packet: bytes) -> None:
    payload = {"type": "route", "to": recipient, "packet": packet.decode("utf-8").strip()}
    sock.sendall(json.dumps(payload).encode("utf-8") + b"\n")


def _packet_stream(sock: socket.socket) -> Iterator[object]:
    file = sock.makefile("r")
    for line in file:
        payload = json.loads(line)
        packet_raw = payload.get("packet")
        if not packet_raw:
            continue
        yield codec.decode_packet(packet_raw.encode("utf-8"))


def _initial_chain_key(root_key: bytes) -> bytes:
    return hkdf_sha256(root_key, salt=b"init", info=b"hybridmsg-chain-init", length=32)


def cmd_init(args: argparse.Namespace) -> None:
    storage = Storage()
    identity = storage.init_identity(args.name)
    print(f"Initialized identity for {identity.name}")
    print(f"Public key: {identity.identity_pub}")


def cmd_add_contact(args: argparse.Namespace) -> None:
    storage = Storage()
    storage.save_contact(args.name, args.pubkey)
    print(f"Added contact {args.name}")


def cmd_relay(args: argparse.Namespace) -> None:
    from hybridmsg.app.relay import RelayServer

    RelayServer(args.host, args.port).start()


def cmd_connect(args: argparse.Namespace) -> None:
    storage = Storage()
    identity = _load_identity(storage)
    contacts = storage.load_contacts()
    if args.to not in contacts:
        raise SystemExit("unknown contact")
    relay = RelayTarget(*args.relay.split(":"))
    relay = RelayTarget(relay.host, int(relay.port))
    sock = _connect(relay)
    with sock:
        _register(sock, storage.load_identity().name)
        session = generate_session_keypair()
        state = initiator_hello(identity, session, storage.load_identity().name)
        _send_route(sock, args.to, codec.encode_packet(state.hello))
        _send_route(sock, args.to, codec.encode_packet(state.hello_sig))
        stream = _packet_stream(sock)
        exchange = _wait_for_packet(stream, KeyExchange)
        confirm = initiator_finalize(state, exchange)
        _send_route(sock, args.to, codec.encode_packet(confirm))
        result = initiator_result(state, exchange)
        session_state = SessionState(
            peer=args.to,
            root_key=codec.b64encode(result.root_key),
            key_id=result.session_key_id,
            send_counter=0,
            receive_counter=0,
        )
        storage.save_session(session_state)
        print(f"Session established with {args.to}")


def cmd_send(args: argparse.Namespace) -> None:
    storage = Storage()
    sessions = storage.load_sessions()
    if args.to not in sessions:
        raise SystemExit("no session for contact")
    session = sessions[args.to]
    chain_key = _initial_chain_key(codec.b64decode(session.root_key))
    ratchet = RatchetState(chain_key=chain_key, send_counter=session.send_counter, receive_counter=session.receive_counter)
    message_key, counter = ratchet.next_send_key()
    associated_data = _associated_data(storage.load_identity().name, args.to, session.key_id, counter, _now())
    result = aead.encrypt(message_key, args.message.encode("utf-8"), associated_data)
    data_msg = DataMessage(
        sender=storage.load_identity().name,
        receiver=args.to,
        key_id=session.key_id,
        counter=counter,
        timestamp=_now(),
        nonce=codec.b64encode(result.nonce),
        ciphertext=codec.b64encode(result.ciphertext),
    )
    session.send_counter = counter
    storage.save_session(session)
    relay = RelayTarget(*args.relay.split(":"))
    relay = RelayTarget(relay.host, int(relay.port))
    sock = _connect(relay)
    with sock:
        _register(sock, storage.load_identity().name)
        _send_route(sock, args.to, codec.encode_packet(data_msg))
    print("Message sent")


def cmd_listen(args: argparse.Namespace) -> None:
    storage = Storage()
    identity = _load_identity(storage)
    contacts = storage.load_contacts()
    relay = RelayTarget(*args.relay.split(":"))
    relay = RelayTarget(relay.host, int(relay.port))
    sock = _connect(relay)
    with sock:
        _register(sock, storage.load_identity().name)
        stream = _packet_stream(sock)
        for packet in stream:
            if isinstance(packet, Hello):
                if packet.sender not in contacts:
                    print("Unknown contact")
                    continue
                if contacts[packet.sender].identity_pub != packet.identity_pub:
                    print("Identity mismatch")
                    continue
                signature_packet = _wait_for_packet(stream, HelloSignature)
                responder_state = responder_accept(storage.load_identity().name, identity, generate_session_keypair(), packet, signature_packet)
                exchange = responder_key_exchange(responder_state)
                _send_route(sock, packet.sender, codec.encode_packet(exchange))
                confirm = _wait_for_packet(stream, Confirm)
                result = responder_finalize(responder_state, exchange, confirm)
                session_state = SessionState(
                    peer=packet.sender,
                    root_key=codec.b64encode(result.root_key),
                    key_id=result.session_key_id,
                    send_counter=0,
                    receive_counter=0,
                )
                storage.save_session(session_state)
                print(f"Session established with {packet.sender}")
            elif isinstance(packet, DataMessage):
                _handle_data_message(storage, packet)


def _wait_for_packet(stream: Iterator[object], expected_type: type):
    for packet in stream:
        if isinstance(packet, expected_type):
            return packet
    raise SystemExit("expected packet not received")


def _associated_data(sender: str, receiver: str, key_id: str, counter: int, timestamp: int) -> bytes:
    ad = {
        "version": 1,
        "sender": sender,
        "receiver": receiver,
        "key_id": key_id,
        "counter": counter,
        "timestamp": timestamp,
    }
    return json.dumps(ad, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _handle_data_message(storage: Storage, packet: DataMessage) -> None:
    sessions = storage.load_sessions()
    if packet.sender not in sessions:
        print("Unknown session")
        return
    session = sessions[packet.sender]
    chain_key = _initial_chain_key(codec.b64decode(session.root_key))
    ratchet = RatchetState(chain_key=chain_key, send_counter=session.send_counter, receive_counter=session.receive_counter)
    try:
        message_key = ratchet.next_receive_key(packet.counter)
    except RatchetError:
        print("Replay detected")
        return
    associated_data = _associated_data(packet.sender, packet.receiver, packet.key_id, packet.counter, packet.timestamp)
    plaintext = aead.decrypt(
        message_key,
        codec.b64decode(packet.nonce),
        codec.b64decode(packet.ciphertext),
        associated_data,
    )
    session.receive_counter = packet.counter
    storage.save_session(session)
    print(f"{packet.sender}: {plaintext.decode('utf-8')}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="HybridMsg client")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init")
    init_parser.add_argument("--name", required=True)
    init_parser.set_defaults(func=cmd_init)

    add_contact = subparsers.add_parser("add-contact")
    add_contact.add_argument("--name", required=True)
    add_contact.add_argument("--pubkey", required=True)
    add_contact.set_defaults(func=cmd_add_contact)

    relay = subparsers.add_parser("relay")
    relay.add_argument("--host", default="127.0.0.1")
    relay.add_argument("--port", type=int, default=9000)
    relay.set_defaults(func=cmd_relay)

    connect = subparsers.add_parser("connect")
    connect.add_argument("--to", required=True)
    connect.add_argument("--relay", required=True)
    connect.set_defaults(func=cmd_connect)

    send = subparsers.add_parser("send")
    send.add_argument("--to", required=True)
    send.add_argument("--message", required=True)
    send.add_argument("--relay", required=True)
    send.set_defaults(func=cmd_send)

    listen = subparsers.add_parser("listen")
    listen.add_argument("--relay", required=True)
    listen.set_defaults(func=cmd_listen)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
