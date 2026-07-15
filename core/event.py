"""Canonical event model shared by every connector and detection rule."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def parse_timestamp(value: str | datetime) -> datetime:
    """Return a timezone-aware UTC datetime."""
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class Event:
    timestamp: datetime
    source: str
    event_type: str
    action: str
    outcome: str = "unknown"
    user: str | None = None
    host: str | None = None
    source_ip: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    origin_file: str | None = None
    origin_type: str | None = None
    origin_file_id: str | None = None
    id: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self) -> None:
        object.__setattr__(self, "timestamp", parse_timestamp(self.timestamp))
        object.__setattr__(self, "source", self.source.lower())

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["timestamp"] = self.timestamp.isoformat().replace("+00:00", "Z")
        return value

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Event":
        return cls(**value)

    def get(self, dotted_path: str, default: Any = None) -> Any:
        """Resolve fields such as ``details.process_name`` for YAML rules."""
        current: Any = self.to_dict()
        for part in dotted_path.split("."):
            if not isinstance(current, dict) or part not in current:
                return default
            current = current[part]
        return current
