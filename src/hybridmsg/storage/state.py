from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

from cryptography.hazmat.primitives import serialization

from hybridmsg.crypto.keys import generate_identity_keypair, key_id, save_private_key
from hybridmsg.protocol import codec


class StorageError(ValueError):
    """Raised when storage operations fail."""


@dataclass
class SessionState:
    peer: str
    root_key: str
    key_id: str
    send_counter: int
    receive_counter: int


@dataclass
class Contact:
    name: str
    identity_pub: str


@dataclass
class IdentityState:
    name: str
    identity_pub: str


class Storage:
    def __init__(self, base_dir: Optional[Path] = None) -> None:
        self.base_dir = base_dir or Path(os.getenv("HYBRIDMSG_HOME", Path.home() / ".hybridmsg"))
        self.base_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.base_dir, 0o700)
        self.identity_path = self.base_dir / "identity.json"
        self.contacts_path = self.base_dir / "contacts.json"
        self.sessions_path = self.base_dir / "sessions.json"

    def init_identity(self, name: str) -> IdentityState:
        if self.identity_path.exists():
            raise StorageError("identity already initialized")
        keypair = generate_identity_keypair()
        priv_path = self.base_dir / "identity_private.pem"
        save_private_key(priv_path, keypair.private_key)
        pub_b64 = codec.b64encode(
            keypair.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )
        identity = IdentityState(name=name, identity_pub=pub_b64)
        self.identity_path.write_text(json.dumps(identity.__dict__, indent=2))
        return identity

    def load_identity(self) -> IdentityState:
        if not self.identity_path.exists():
            raise StorageError("identity not initialized")
        data = json.loads(self.identity_path.read_text())
        return IdentityState(**data)

    def load_identity_private_path(self) -> Path:
        path = self.base_dir / "identity_private.pem"
        if not path.exists():
            raise StorageError("identity private key missing")
        return path

    def load_contacts(self) -> Dict[str, Contact]:
        if not self.contacts_path.exists():
            return {}
        data = json.loads(self.contacts_path.read_text())
        return {name: Contact(name=name, identity_pub=payload["identity_pub"]) for name, payload in data.items()}

    def save_contact(self, name: str, identity_pub: str) -> None:
        contacts = self.load_contacts()
        contacts[name] = Contact(name=name, identity_pub=identity_pub)
        payload = {name: contact.__dict__ for name, contact in contacts.items()}
        self.contacts_path.write_text(json.dumps(payload, indent=2))

    def load_sessions(self) -> Dict[str, SessionState]:
        if not self.sessions_path.exists():
            return {}
        data = json.loads(self.sessions_path.read_text())
        sessions: Dict[str, SessionState] = {}
        for peer, payload in data.items():
            payload_peer = payload.pop("peer", peer)
            sessions[peer] = SessionState(peer=payload_peer, **payload)
        return sessions

    def save_session(self, session: SessionState) -> None:
        sessions = self.load_sessions()
        sessions[session.peer] = session
        payload = {
            peer: {
                "peer": state.peer,
                "root_key": state.root_key,
                "key_id": state.key_id,
                "send_counter": state.send_counter,
                "receive_counter": state.receive_counter,
            }
            for peer, state in sessions.items()
        }
        self.sessions_path.write_text(json.dumps(payload, indent=2))

    def session_key_id(self, identity_pub_b64: str) -> str:
        return key_id(codec.b64decode(identity_pub_b64))
