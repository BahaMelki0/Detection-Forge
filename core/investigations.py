"""Persistent, explicitly scoped investigation cases for telemetry and alerts."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from core.alerter import Alert
from core.event import Event
from core.workspace import AnalysisWorkspace, IngestedFile, utc_now


@dataclass(slots=True)
class Investigation:
    id: str
    name: str
    description: str
    created_at: str
    updated_at: str
    files: list[IngestedFile] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)
    status: str = "open"
    resolved_at: str | None = None
    resolution_notes: str = ""
    watched_paths: list[str] = field(default_factory=list)
    poll_interval_seconds: int = 120
    watcher_enabled: bool = False
    file_checkpoints: dict[str, dict[str, Any]] = field(default_factory=dict)
    watch_last_scan: str | None = None
    watch_last_error: str = ""
    ai_analysis: str = ""
    ai_analyzed_at: str | None = None
    alert_reviews: dict[str, dict[str, Any]] = field(default_factory=dict)
    last_append_duplicates: int = field(default=0, repr=False)

    @classmethod
    def create(cls, name: str, description: str = "") -> "Investigation":
        now = utc_now()
        return cls(str(uuid4()), name.strip(), description.strip(), now, now)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Investigation":
        return cls(
            id=payload["id"], name=payload["name"], description=payload.get("description", ""),
            created_at=payload["created_at"], updated_at=payload.get("updated_at", payload["created_at"]),
            files=[IngestedFile.from_dict(item) for item in payload.get("files", [])],
            events=[Event.from_dict(item) for item in payload.get("events", [])],
            alerts=[Alert.from_dict(item) for item in payload.get("alerts", [])],
            status=payload.get("status", "open"),
            resolved_at=payload.get("resolved_at"), resolution_notes=payload.get("resolution_notes", ""),
            watched_paths=payload.get("watched_paths", []),
            poll_interval_seconds=payload.get("poll_interval_seconds", 120),
            watcher_enabled=payload.get("watcher_enabled", False),
            file_checkpoints=payload.get("file_checkpoints", {}),
            watch_last_scan=payload.get("watch_last_scan"), watch_last_error=payload.get("watch_last_error", ""),
            ai_analysis=payload.get("ai_analysis", ""), ai_analyzed_at=payload.get("ai_analyzed_at"),
            alert_reviews=payload.get('alert_reviews', {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 1, "id": self.id, "name": self.name, "description": self.description,
            "created_at": self.created_at, "updated_at": self.updated_at, "status": self.status,
            "resolved_at": self.resolved_at, "resolution_notes": self.resolution_notes,
            "watched_paths": self.watched_paths, "poll_interval_seconds": self.poll_interval_seconds,
            "watcher_enabled": self.watcher_enabled, "file_checkpoints": self.file_checkpoints,
            "watch_last_scan": self.watch_last_scan, "watch_last_error": self.watch_last_error,
            "ai_analysis": self.ai_analysis, "ai_analyzed_at": self.ai_analyzed_at,
            'alert_reviews': self.alert_reviews,
            "files": [asdict(item) for item in self.files],
            "events": [item.to_dict() for item in self.events],
            "alerts": [item.to_dict() for item in self.alerts],
        }


class InvestigationStore:
    def __init__(self, directory: str | Path, legacy_workspace: str | Path | None = None,
                 legacy_alerts: str | Path | None = None):
        self.directory = Path(directory)
        self.legacy_workspace = Path(legacy_workspace) if legacy_workspace else None
        self.legacy_alerts = Path(legacy_alerts) if legacy_alerts else None

    def _path(self, investigation_id: str) -> Path:
        if not re.fullmatch(r"[a-f0-9-]{36}", investigation_id):
            raise ValueError("Invalid investigation id")
        return self.directory / f"{investigation_id}.json"

    def create(self, name: str, description: str = "") -> Investigation:
        investigation = Investigation.create(name, description)
        self.save(investigation)
        return investigation

    def get(self, investigation_id: str) -> Investigation | None:
        try:
            path = self._path(investigation_id)
        except ValueError:
            return None
        if not path.is_file():
            return None
        return Investigation.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def list(self, migrate_legacy: bool = True) -> list[Investigation]:
        self.directory.mkdir(parents=True, exist_ok=True)
        paths = list(self.directory.glob("*.json"))
        if migrate_legacy and not paths:
            self._migrate_legacy()
            paths = list(self.directory.glob("*.json"))
        records = [Investigation.from_dict(json.loads(path.read_text(encoding="utf-8"))) for path in paths]
        records.sort(key=lambda item: item.updated_at, reverse=True)
        records.sort(key=lambda item: item.status != "open")
        return records

    def save(self, investigation: Investigation) -> None:
        path = self._path(investigation.id)
        self.directory.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(investigation.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        temporary.replace(path)

    def delete(self, investigation_id: str) -> bool:
        """Delete only this case record; never touch its configured source files."""
        try:
            path = self._path(investigation_id)
        except ValueError:
            return False
        if not path.is_file():
            return False
        path.unlink()
        return True

    def _migrate_legacy(self) -> None:
        if not self.legacy_workspace or not self.legacy_workspace.is_file():
            return
        legacy = AnalysisWorkspace(self.legacy_workspace).load()
        if not legacy.files and not legacy.events:
            return
        alerts = []
        if self.legacy_alerts and self.legacy_alerts.is_file():
            from core.alerter import AlertStore
            alerts = AlertStore(self.legacy_alerts).load()
        record = Investigation.create(
            "Imported shared workspace",
            "Migrated existing uploads and detections. These pre-case records were already analyzed together.",
        )
        record.files, record.events, record.alerts = legacy.files, legacy.events, alerts
        record.updated_at = legacy.updated_at or record.created_at
        self.save(record)
