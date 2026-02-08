from hybridmsg.ratchet.state import RatchetState, RatchetError


def test_ratchet_advances_counters():
    state = RatchetState(chain_key=b"a" * 32)
    key1, counter1 = state.next_send_key()
    key2, counter2 = state.next_send_key()
    assert counter1 == 1
    assert counter2 == 2
    assert key1 != key2


def test_replay_detection():
    state = RatchetState(chain_key=b"b" * 32)
    state.next_receive_key(1)
    try:
        state.next_receive_key(1)
    except RatchetError:
        assert True
    else:
        assert False
