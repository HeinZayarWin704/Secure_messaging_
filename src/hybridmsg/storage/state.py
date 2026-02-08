"""State storage helpers for HybridMsg sessions."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict


@dataclass
class SessionState:
    peer: str
    established: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


class StateStorage:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.sessions_path = root / "sessions.json"

    def load_sessions(self) -> Dict[str, SessionState]:
        if not self.sessions_path.exists():
            return {}

        data = json.loads(self.sessions_path.read_text())
        sessions: Dict[str, SessionState] = {}
        for peer, payload in data.items():
            payload = dict(payload)
            payload.pop("peer", None)
            sessions[peer] = SessionState(peer=peer, **payload)
        return sessions

    def save_sessions(self, sessions: Dict[str, SessionState]) -> None:
        data = {
            peer: {"peer": state.peer, "established": state.established, "metadata": state.metadata}
            for peer, state in sessions.items()
        }
        self.sessions_path.write_text(json.dumps(data, indent=2))
