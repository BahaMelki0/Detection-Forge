"""Sysmon event normalization."""

from __future__ import annotations

from typing import Any

from connectors.base import BaseConnector
from core.event import Event


class SysmonConnector(BaseConnector):
    source = "sysmon"

    _ACTIONS = {1: "process_created", 3: "network_connection", 7: "image_loaded", 11: "file_created"}

    def normalize(self, raw: dict[str, Any]) -> Event:
        event_id = int(raw["EventID"])
        return Event(
            timestamp=raw["UtcTime"],
            source=self.source,
            event_type="sysmon_event",
            action=self._ACTIONS.get(event_id, f"event_{event_id}"),
            outcome="success",
            user=raw.get("User"),
            host=raw.get("Computer"),
            source_ip=raw.get("SourceIp"),
            details={
                "event_id": event_id,
                "process_name": raw.get("Image"),
                "command_line": raw.get("CommandLine"),
                "parent_process": raw.get("ParentImage"),
                "destination_ip": raw.get("DestinationIp"),
                "destination_port": raw.get("DestinationPort"),
                "target_filename": raw.get("TargetFilename"),
                "hashes": raw.get("Hashes"),
            },
            raw=raw,
        )
