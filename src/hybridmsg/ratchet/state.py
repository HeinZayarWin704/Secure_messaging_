from __future__ import annotations

from dataclasses import dataclass

from hybridmsg.crypto.kdf import hkdf_sha256


class RatchetError(ValueError):
    """Raised when ratchet state fails."""


@dataclass
class RatchetState:
    chain_key: bytes
    send_counter: int = 0
    receive_counter: int = 0

    def next_send_key(self) -> tuple[bytes, int]:
        self.send_counter += 1
        message_key = hkdf_sha256(
            self.chain_key,
            salt=self._counter_bytes(self.send_counter),
            info=b"hybridmsg-msg",
            length=32,
        )
        self.chain_key = hkdf_sha256(
            self.chain_key,
            salt=self._counter_bytes(self.send_counter),
            info=b"hybridmsg-chain",
            length=32,
        )
        return message_key, self.send_counter

    def next_receive_key(self, counter: int) -> bytes:
        if counter <= self.receive_counter:
            raise RatchetError("replay detected")
        self.receive_counter = counter
        return hkdf_sha256(
            self.chain_key,
            salt=self._counter_bytes(counter),
            info=b"hybridmsg-msg",
            length=32,
        )

    @staticmethod
    def _counter_bytes(counter: int) -> bytes:
        return counter.to_bytes(8, "big")
