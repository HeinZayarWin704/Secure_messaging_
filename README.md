# HybridMsg: Secure Messaging with Hybrid Cryptography

HybridMsg is a semester-level demo project that implements a **hybrid crypto messaging protocol** in Python 3.11+. It uses **X25519** for ECDH, **HKDF-SHA256** for key derivation, and **AES-256-GCM** for authenticated encryption. It includes a lightweight ratchet per message, replay protection, signed handshakes with Ed25519 identity keys, and a TCP relay for demo transport.

## Protocol Overview

```
Alice                                   Relay                                 Bob
  |-- hello + hello_sig ----------------->|                                    |
  |                                       |-- hello + hello_sig -------------->|
  |<---------------- key_exchange --------|                                    |
  |-- confirm --------------------------->|                                    |
  |                                       |-------------- confirm ------------>|
  |-- encrypted data -------------------->|                                    |
  |                                       |----------- encrypted data -------->|
```

### Key Flow
- **Identity keys**: Ed25519 long-term keys stored locally.
- **Session keys**: Ephemeral X25519 key pair per session.
- **Root key**: HKDF(shared_secret, transcript) -> 32 bytes.
- **Chain key**: HKDF(root_key, "chain-init") -> 32 bytes.
- **Message key**: HKDF(chain_key, counter) -> 32 bytes, per message.

### Associated Data (AD)
Each encrypted message is bound to:
- protocol version
- sender/receiver
- key id
- message counter
- timestamp

## Security Properties
- **Authentication**: Handshake messages are signed with Ed25519 identity keys.
- **Forward secrecy**: Uses ephemeral X25519 per session.
- **Replay protection**: Receiver checks strictly increasing counters.
- **AEAD**: AES-256-GCM ensures confidentiality and integrity.

## Limitations
- Not full Signal/X3DH or Double Ratchet.
- No group messaging or key recovery.
- Out-of-order message handling is minimal.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[test]
```

## Demo Flow

Terminal 1:
```bash
hybridmsg relay --host 127.0.0.1 --port 9000
```

Terminal 2 (Alice):
```bash
export HYBRIDMSG_HOME=./data/alice
hybridmsg init --name Alice
# copy Alice's public key for Bob
```

Terminal 3 (Bob):
```bash
export HYBRIDMSG_HOME=./data/bob
hybridmsg init --name Bob
# copy Bob's public key for Alice
```

Terminal 2 (Alice adds Bob):
```bash
export HYBRIDMSG_HOME=./data/alice
hybridmsg add-contact --name Bob --pubkey <bob-ed25519-pub>
```

Terminal 3 (Bob adds Alice):
```bash
export HYBRIDMSG_HOME=./data/bob
hybridmsg add-contact --name Alice --pubkey <alice-ed25519-pub>
```

Terminal 3 (Bob listens):
```bash
export HYBRIDMSG_HOME=./data/bob
hybridmsg listen --relay 127.0.0.1:9000
```

Terminal 2 (Alice connects + sends):
```bash
export HYBRIDMSG_HOME=./data/alice
hybridmsg connect --to Bob --relay 127.0.0.1:9000
hybridmsg send --to Bob --message "hello" --relay 127.0.0.1:9000
```

## Tests

```bash
pytest
```

## Project Layout

```
src/hybridmsg/
  crypto/       # HKDF, AEAD wrappers, key helpers
  protocol/     # packet types, codec, handshake
  ratchet/      # chain key ratchet state
  storage/      # identity/contacts/session persistence
  app/          # relay server + CLI client
```

## License
MIT License
