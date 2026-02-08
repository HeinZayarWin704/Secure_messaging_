from __future__ import annotations

import json
import socket
import threading
from typing import Dict


class RelayServer:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self._clients: Dict[str, socket.socket] = {}
        self._lock = threading.Lock()

    def start(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen()
            while True:
                client, _addr = server.accept()
                thread = threading.Thread(target=self._handle_client, args=(client,), daemon=True)
                thread.start()

    def _handle_client(self, conn: socket.socket) -> None:
        name = None
        try:
            file = conn.makefile("rwb")
            for line in file:
                payload = json.loads(line.decode("utf-8"))
                msg_type = payload.get("type")
                if msg_type == "register":
                    name = payload.get("name")
                    if not name:
                        continue
                    with self._lock:
                        self._clients[name] = conn
                elif msg_type == "route":
                    recipient = payload.get("to")
                    if not recipient:
                        continue
                    with self._lock:
                        dest = self._clients.get(recipient)
                    if dest:
                        dest.sendall(line)
        finally:
            if name:
                with self._lock:
                    if self._clients.get(name) is conn:
                        self._clients.pop(name, None)
            conn.close()


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="HybridMsg relay server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    args = parser.parse_args()
    RelayServer(args.host, args.port).start()


if __name__ == "__main__":
    main()
