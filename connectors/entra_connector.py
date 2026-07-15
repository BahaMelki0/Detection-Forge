"""Microsoft Entra ID sign-in and audit log normalization."""

from __future__ import annotations

from typing import Any

from connectors.base import BaseConnector
from core.event import Event


class EntraConnector(BaseConnector):
    source = "entra"

    def __init__(self, log_type: str = "auto"):
        if log_type not in {"auto", "signin", "audit"}:
            raise ValueError(f"Unsupported Entra log type: {log_type}")
        self.log_type = log_type

    def normalize(self, raw: dict[str, Any]) -> Event:
        log_type = self.log_type
        if log_type == "auto":
            log_type = "audit" if "activityDateTime" in raw or "initiatedBy" in raw else "signin"
        if log_type == "audit":
            return self._normalize_audit(raw)
        return self._normalize_signin(raw)

    def _normalize_signin(self, raw: dict[str, Any]) -> Event:
        status = raw.get("status", {})
        error_code = status.get("errorCode", raw.get("errorCode", 0))
        outcome = "success" if error_code in (0, "0", None) else "failure"
        return Event(
            timestamp=raw["createdDateTime"],
            source=self.source,
            event_type=raw.get("category", "sign_in"),
            action=raw.get("activityDisplayName", raw.get("action", "user_sign_in")),
            outcome=outcome,
            user=raw.get("userPrincipalName", raw.get("initiatedBy")),
            host=raw.get("deviceDetail", {}).get("displayName"),
            source_ip=raw.get("ipAddress"),
            details={
                "application": raw.get("appDisplayName"),
                "country": raw.get("location", {}).get("countryOrRegion"),
                "risk_level": raw.get("riskLevelDuringSignIn", "none"),
                "risk_state": raw.get("riskState", "none"),
                "conditional_access": raw.get("conditionalAccessStatus", "unknown"),
                "error_code": error_code,
            },
            raw=raw,
        )

    def _normalize_audit(self, raw: dict[str, Any]) -> Event:
        initiated = raw.get("initiatedBy", {})
        actor = initiated.get("user", {}) if isinstance(initiated, dict) else {}
        targets = raw.get("targetResources", [])
        result = str(raw.get("result", "unknown")).lower()
        return Event(
            timestamp=raw["activityDateTime"] if "activityDateTime" in raw else raw["createdDateTime"],
            source=self.source,
            event_type="audit",
            action=raw.get("activityDisplayName", raw.get("operationType", "directory_audit")),
            outcome="success" if result in {"success", "succeeded"} else result,
            user=actor.get("userPrincipalName", actor.get("displayName")),
            source_ip=actor.get("ipAddress"),
            details={
                "category": raw.get("category"),
                "operation_type": raw.get("operationType"),
                "result_reason": raw.get("resultReason"),
                "target_resources": targets,
                "target_names": [target.get("displayName") for target in targets if isinstance(target, dict)],
            },
            raw=raw,
        )
