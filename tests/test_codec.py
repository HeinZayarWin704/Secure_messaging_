from hybridmsg.protocol import codec
from hybridmsg.protocol.types import Hello, HelloSignature


def test_codec_roundtrip():
    hello = Hello(sender="Alice", identity_pub="abc", session_pub="def", timestamp=1)
    encoded = codec.encode_packet(hello)
    decoded = codec.decode_packet(encoded)
    assert decoded == hello


def test_codec_rejects_invalid_base64():
    try:
        codec.b64decode("!!!")
    except codec.CodecError:
        assert True
    else:
        assert False


def test_hello_signature_roundtrip():
    sig = HelloSignature(sender="Alice", signature="sig", timestamp=2)
    encoded = codec.encode_packet(sig)
    decoded = codec.decode_packet(encoded)
    assert decoded == sig
