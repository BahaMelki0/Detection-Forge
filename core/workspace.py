"""Persistent UI investigation workspace for cumulative uploaded telemetry."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from core.event import Event


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class IngestedFile:
    filename: str
    profile: str
    source: str
    event_count: int
    uploaded_at: str
    id: str

    @classmethod
    def create(cls, filename: str, profile: str, source: str, event_count: int, file_id: str | None = None):
        return cls(filename, profile, source, event_count, utc_now(), file_id or str(uuid4()))

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "IngestedFile":
        return cls(**value)


@dataclass(slots=True)
class WorkspaceState:
    files: list[IngestedFile]
    events: list[Event]
    updated_at: str | None = None


class AnalysisWorkspace:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def load(self) -> WorkspaceState:
        if not self.path.exists():
            return WorkspaceState([], [])
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        return WorkspaceState(
            files=[IngestedFile.from_dict(value) for value in payload.get("files", [])],
            events=[Event.from_dict(value) for value in payload.get("events", [])],
            updated_at=payload.get("updated_at"),
        )

    def append(self, files: list[IngestedFile], events: list[Event]) -> WorkspaceState:
        state = self.load()
        state.files.extend(files)
        state.events.extend(events)
        state.updated_at = utc_now()
        self._save(state)
        return state

    def clear(self) -> None:
        self.path.unlink(missing_ok=True)

    def _save(self, state: WorkspaceState) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "updated_at": state.updated_at,
            "files": [asdict(value) for value in state.files],
            "events": [value.to_dict() for value in state.events],
        }
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        temporary.replace(self.path)
