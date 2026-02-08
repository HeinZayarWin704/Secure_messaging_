import json
import socket
import threading
import time

from hybridmsg.app.relay import RelayServer
from hybridmsg.crypto import aead
from hybridmsg.crypto.kdf import hkdf_sha256
from hybridmsg.crypto.keys import generate_identity_keypair, generate_session_keypair
from hybridmsg.protocol import codec
from hybridmsg.protocol.handshake import (
    initiator_finalize,
    initiator_hello,
    initiator_result,
    responder_accept,
    responder_finalize,
    responder_key_exchange,
)
from hybridmsg.protocol.types import DataMessage, Hello, HelloSignature, KeyExchange
from hybridmsg.ratchet.state import RatchetState, RatchetError


def _associated_data(sender: str, receiver: str, key_id: str, counter: int, timestamp: int) -> bytes:
    return json.dumps(
        {
            "version": 1,
            "sender": sender,
            "receiver": receiver,
            "key_id": key_id,
            "counter": counter,
            "timestamp": timestamp,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _send_route(sock: socket.socket, recipient: str, packet: bytes) -> None:
    payload = {"type": "route", "to": recipient, "packet": packet.decode("utf-8").strip()}
    sock.sendall(json.dumps(payload).encode("utf-8") + b"\n")


def _register(sock: socket.socket, name: str) -> None:
    sock.sendall(json.dumps({"type": "register", "name": name}).encode("utf-8") + b"\n")


def _recv_packet(file):
    line = file.readline()
    payload = json.loads(line)
    return codec.decode_packet(payload["packet"].encode("utf-8"))


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_integration_handshake_and_message():
    port = _free_port()
    server = RelayServer("127.0.0.1", port)
    thread = threading.Thread(target=server.start, daemon=True)
    thread.start()
    time.sleep(0.1)

    alice_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    alice_sock.connect(("127.0.0.1", port))
    bob_sock.connect(("127.0.0.1", port))
    alice_file = alice_sock.makefile("r")
    bob_file = bob_sock.makefile("r")
    _register(alice_sock, "Alice")
    _register(bob_sock, "Bob")

    alice_id = generate_identity_keypair()
    bob_id = generate_identity_keypair()

    alice_state = initiator_hello(alice_id, generate_session_keypair(), "Alice")
    _send_route(alice_sock, "Bob", codec.encode_packet(alice_state.hello))
    _send_route(alice_sock, "Bob", codec.encode_packet(alice_state.hello_sig))

    hello = _recv_packet(bob_file)
    signature = _recv_packet(bob_file)
    assert isinstance(hello, Hello)
    assert isinstance(signature, HelloSignature)

    responder_state = responder_accept("Bob", bob_id, generate_session_keypair(), hello, signature)
    exchange = responder_key_exchange(responder_state)
    _send_route(bob_sock, "Alice", codec.encode_packet(exchange))

    exchange_rx = _recv_packet(alice_file)
    assert isinstance(exchange_rx, KeyExchange)
    confirm = initiator_finalize(alice_state, exchange_rx)
    _send_route(alice_sock, "Bob", codec.encode_packet(confirm))

    confirm_rx = _recv_packet(bob_file)
    responder_result = responder_finalize(responder_state, exchange, confirm_rx)
    initiator_result_state = initiator_result(alice_state, exchange_rx)

    assert responder_result.root_key == initiator_result_state.root_key

    chain_key = hkdf_sha256(responder_result.root_key, salt=b"init", info=b"hybridmsg-chain-init", length=32)
    send_ratchet = RatchetState(chain_key=chain_key)
    msg_key, counter = send_ratchet.next_send_key()
    ad = _associated_data("Alice", "Bob", responder_result.session_key_id, counter, 1)
    enc = aead.encrypt(msg_key, b"hello", ad)
    data_msg = DataMessage(
        sender="Alice",
        receiver="Bob",
        key_id=responder_result.session_key_id,
        counter=counter,
        timestamp=1,
        nonce=codec.b64encode(enc.nonce),
        ciphertext=codec.b64encode(enc.ciphertext),
    )
    _send_route(alice_sock, "Bob", codec.encode_packet(data_msg))

    data_rx = _recv_packet(bob_file)
    assert isinstance(data_rx, DataMessage)
    recv_ratchet = RatchetState(chain_key=chain_key)
    msg_key_rx = recv_ratchet.next_receive_key(data_rx.counter)
    plaintext = aead.decrypt(msg_key_rx, codec.b64decode(data_rx.nonce), codec.b64decode(data_rx.ciphertext), ad)
    assert plaintext == b"hello"

    try:
        recv_ratchet.next_receive_key(data_rx.counter)
    except RatchetError:
        assert True
    else:
        assert False

    alice_file.close()
    bob_file.close()
    alice_sock.close()
    bob_sock.close()
