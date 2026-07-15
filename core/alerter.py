"""Alert model and JSON persistence used by both the CLI and Flask UI."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4

from core.event import Event
from core.rule_engine import Rule


@dataclass(slots=True)
class Alert:
    rule_id: str
    rule_title: str
    description: str
    severity: str
    sources: list[str]
    attack: dict[str, str]
    remediation: str
    events: list[dict[str, Any]]
    timestamp: str
    id: str = field(default_factory=lambda: str(uuid4()))

    @classmethod
    def create(cls, rule: Rule, events: list[Event]) -> "Alert":
        return cls(
            rule_id=rule.id, rule_title=rule.title, description=rule.description,
            severity=rule.severity, sources=sorted({event.source for event in events}),
            attack=rule.attack, remediation=rule.remediation,
            events=[event.to_dict() for event in events],
            timestamp=max(event.timestamp for event in events).isoformat().replace("+00:00", "Z"),
        )

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Alert":
        return cls(**value)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AlertStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def save(self, alerts: Iterable[Alert]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "alerts": [alert.to_dict() for alert in alerts],
        }
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        temporary.replace(self.path)

    def load(self) -> list[Alert]:
        if not self.path.exists():
            return []
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        return [Alert.from_dict(value) for value in payload.get("alerts", [])]

