"""Microsoft Entra ID sign-in and audit log normalization."""

from __future__ import annotations

from typing import Any
import json

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
        status = raw.get("status") or {}
        error_code = status.get("errorCode", raw.get("errorCode"))
        outcome = 'unknown' if error_code is None else "success" if error_code in (0, "0") else "failure"
        workload = bool(raw.get('servicePrincipalId')) and not raw.get('userPrincipalName')
        return Event(
            timestamp=raw["createdDateTime"],
            source=self.source,
            event_type='workload_sign_in' if workload else raw.get("category", "sign_in"),
            action=raw.get("activityDisplayName", raw.get("action", 'service_principal_sign_in' if workload else "user_sign_in")),
            outcome=outcome,
            user=raw.get("userPrincipalName", raw.get("initiatedBy")),
            host=(raw.get("deviceDetail") or {}).get("displayName"),
            source_ip=raw.get("ipAddress"),
            details={
                "application": raw.get("appDisplayName"),
                "country": raw.get("location", {}).get("countryOrRegion"),
                "risk_level": raw.get("riskLevelDuringSignIn", "none"),
                "risk_state": raw.get("riskState", "none"),
                "conditional_access": raw.get("conditionalAccessStatus", "unknown"),
                "error_code": error_code,
                'service_principal_id': raw.get('servicePrincipalId'),
                'application_id': raw.get('appId'),
                'primary_target_id': raw.get('servicePrincipalId'),
            },
            raw=raw,
        )

    def _normalize_audit(self, raw: dict[str, Any]) -> Event:
        initiated = raw.get("initiatedBy") or {}
        actor = (initiated.get("user") or {}) if isinstance(initiated, dict) else {}
        application = (initiated.get("app") or {}) if isinstance(initiated, dict) else {}
        actor = actor if isinstance(actor, dict) else {}
        application = application if isinstance(application, dict) else {}
        targets = raw.get("targetResources") or []
        targets = [target for target in targets if isinstance(target, dict)] if isinstance(targets, list) else []
        properties = [prop for target in targets for prop in (target.get('modifiedProperties') or []) if isinstance(prop, dict)]
        property_values = {}
        for prop in properties:
            name = prop.get('displayName')
            if not name:
                continue
            value = prop.get('newValue')
            if isinstance(value, str):
                try:
                    value = json.loads(value)
                except json.JSONDecodeError:
                    pass
            property_values[name] = value
        principal_targets = [target['id'] for target in targets if target.get('id') and str(target.get('type', '')).casefold() == 'serviceprincipal']
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
                "target_ids": [target['id'] for target in targets if target.get('id')],
                "target_types": [target['type'] for target in targets if target.get('type')],
                "modified_property_names": [prop['displayName'] for prop in properties if prop.get('displayName')],
                "actor_type": "user" if actor else "application" if application else "unknown",
                "actor_id": actor.get('id') or application.get('servicePrincipalId'),
                "actor_application_id": application.get('appId'),
                "actor_application_name": application.get('displayName'),
                "correlation_id": raw.get('correlationId'),
                'primary_target_id': principal_targets[0] if len(principal_targets) == 1 else None,
                'modified_property_values': property_values,
                'permission_changes': {name: value for name, value in property_values.items() if any(term in name.casefold() for term in ('permission', 'scope', 'approle'))},
                'role_changes': {name: value for name, value in property_values.items() if 'role' in name.casefold()},
            },
            raw=raw,
        )
