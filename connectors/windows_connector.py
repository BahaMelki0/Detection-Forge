"""Windows Security event normalization."""

from __future__ import annotations

from typing import Any

from connectors.base import BaseConnector
from core.event import Event


class WindowsConnector(BaseConnector):
    source = "windows"

    _ACTIONS = {
        1102: "audit_log_cleared",
        4624: "logon_success",
        4625: "logon_failure",
        4672: "special_privileges_assigned",
        4688: "process_created",
        4698: "scheduled_task_created",
        4720: "user_account_created",
        4728: "member_added_to_security_group",
        4732: "member_added_to_security_group",
        7045: "service_installed",
    }

    def normalize(self, raw: dict[str, Any]) -> Event:
        event_id = int(raw["EventID"])
        user = raw.get("TargetUserName", raw.get("SubjectUserName"))
        if event_id in {1102, 4698, 4728, 4732, 7045}:
            user = raw.get("SubjectUserName", user)
        return Event(
            timestamp=raw["TimeCreated"],
            source=self.source,
            event_type="security_event",
            action=self._ACTIONS.get(event_id, f"event_{event_id}"),
            outcome="failure" if event_id == 4625 else "success",
            user=user,
            host=raw.get("Computer"),
            source_ip=raw.get("IpAddress"),
            details={
                "event_id": event_id,
                "logon_type": raw.get("LogonType"),
                "process_name": raw.get("NewProcessName", raw.get("ProcessName")),
                "command_line": raw.get("CommandLine"),
                "parent_process": raw.get("ParentProcessName"),
                "task_name": raw.get("TaskName"),
                "task_content": raw.get("TaskContent"),
                "service_name": raw.get("ServiceName"),
                "service_file_name": raw.get("ImagePath", raw.get("ServiceFileName")),
                "member_name": raw.get("MemberName"),
                "group_name": raw.get("TargetUserName") if event_id in {4728, 4732} else None,
            },
            raw=raw,
        )
