from hybridmsg.crypto.keys import generate_identity_keypair, generate_session_keypair
from hybridmsg.protocol.handshake import (
    initiator_finalize,
    initiator_hello,
    initiator_result,
    responder_accept,
    responder_finalize,
    responder_key_exchange,
)


def test_handshake_flow():
    alice_id = generate_identity_keypair()
    bob_id = generate_identity_keypair()
    alice_session = generate_session_keypair()
    bob_session = generate_session_keypair()

    initiator_state = initiator_hello(alice_id, alice_session, "Alice")
    responder_state = responder_accept("Bob", bob_id, bob_session, initiator_state.hello, initiator_state.hello_sig)
    exchange = responder_key_exchange(responder_state)
    confirm = initiator_finalize(initiator_state, exchange)
    responder_result = responder_finalize(responder_state, exchange, confirm)
    initiator_result_state = initiator_result(initiator_state, exchange)

    assert responder_result.root_key == initiator_result_state.root_key
    assert responder_result.session_key_id == initiator_result_state.session_key_id
