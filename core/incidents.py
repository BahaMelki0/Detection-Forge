"""Deterministic, explainable grouping of related detection alerts."""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass, field
from datetime import timedelta

from core.alerter import Alert
from core.event import parse_timestamp
from core.identity import same_entity

SEVERITY_SCORE = {"critical": 90, "high": 70, "medium": 45, "low": 20}


@dataclass(slots=True)
class IncidentCase:
    id: str
    title: str
    severity: str
    priority: int
    priority_reasons: list[str]
    alerts: list[Alert]
    sources: list[str]
    users: list[str]
    hosts: list[str]
    started_at: str
    updated_at: str
    all_events: list[dict] = field(default_factory=list)
    alert_reviews: dict = field(default_factory=dict)


def _when(alert: Alert):
    return parse_timestamp(alert.timestamp)


def _ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return value.strip().casefold()


def _alert_events(alert: Alert) -> list[dict]:
    return alert.events or []


def _share_entity(left: Alert, right: Alert) -> bool:
    for first in _alert_events(left):
        for second in _alert_events(right):
            if same_entity("user", first.get("user"), second.get("user")):
                return True
            if same_entity("host", first.get("host"), second.get("host")):
                return True
            first_ip, second_ip = _ip(first.get("source_ip")), _ip(second.get("source_ip"))
            if first_ip and first_ip == second_ip:
                return True
    return False


def _priority(alerts: list[Alert]) -> tuple[int, list[str]]:
    score = max((SEVERITY_SCORE.get(alert.severity, 20) for alert in alerts), default=0)
    reasons = [f"Highest alert severity: {max(alerts, key=lambda a: SEVERITY_SCORE.get(a.severity, 20)).severity}"] if alerts else []
    sources = {source for alert in alerts for source in alert.sources}
    rules = {alert.rule_id for alert in alerts}
    if len(sources) > 1:
        score += 10
        reasons.append("Evidence spans multiple telemetry sources")
    if len(rules) > 1:
        score += 8
        reasons.append("Multiple distinct detection rules fired")
    if any(len(alert.events) > 1 for alert in alerts):
        score += 7
        reasons.append("At least one alert is a multi-event sequence")
    return min(100, score), reasons


def summarize_investigation(investigation) -> IncidentCase:
    """Present all alerts in a user-owned investigation as one scoped case."""
    alerts = sorted(investigation.alerts, key=lambda alert: (_when(alert), alert.id))
    severity_alert = max(alerts, key=lambda alert: SEVERITY_SCORE.get(alert.severity, 20), default=None)
    sources = sorted({source for alert in alerts for source in alert.sources})
    users = sorted({event.get("user") for alert in alerts for event in _alert_events(alert) if event.get("user")})
    hosts = sorted({event.get("host") for alert in alerts for event in _alert_events(alert) if event.get("host")})
    priority, reasons = _priority(alerts)
    started = alerts[0].timestamp if alerts else investigation.created_at
    updated = alerts[-1].timestamp if alerts else investigation.updated_at
    return IncidentCase(
        id=investigation.id, title=investigation.name,
        severity=severity_alert.severity if severity_alert else "low", priority=priority,
        priority_reasons=reasons, alerts=alerts, sources=sources, users=users, hosts=hosts,
        started_at=started, updated_at=updated,
        all_events=[event.to_dict() for event in investigation.events],
        alert_reviews=investigation.alert_reviews,
    )


def build_incident_cases(alerts: list[Alert], window_minutes: int = 30) -> list[IncidentCase]:
    """Group alerts with a shared user, host, or source IP inside a time window."""
    ordered = sorted(alerts, key=lambda alert: (_when(alert), alert.id))
    parents = list(range(len(ordered)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parents[right_root] = left_root

    window = timedelta(minutes=window_minutes)
    for right in range(len(ordered)):
        for left in range(right - 1, -1, -1):
            delta = _when(ordered[right]) - _when(ordered[left])
            if delta > window:
                break
            if _share_entity(ordered[left], ordered[right]):
                union(left, right)

    grouped: dict[int, list[Alert]] = {}
    for index, alert in enumerate(ordered):
        grouped.setdefault(find(index), []).append(alert)

    cases = []
    for group in grouped.values():
        group.sort(key=lambda alert: (_when(alert), alert.id))
        severity_alert = max(group, key=lambda alert: SEVERITY_SCORE.get(alert.severity, 20))
        sources = sorted({source for alert in group for source in alert.sources})
        users = sorted({event.get("user") for alert in group for event in _alert_events(alert) if event.get("user")})
        hosts = sorted({event.get("host") for alert in group for event in _alert_events(alert) if event.get("host")})
        priority, reasons = _priority(group)
        seed = group[0].id
        case_id = "case-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
        title = severity_alert.rule_title if len(group) == 1 else f"{len(group)} related detections"
        cases.append(IncidentCase(
            id=case_id, title=title, severity=severity_alert.severity, priority=priority,
            priority_reasons=reasons, alerts=group, sources=sources, users=users, hosts=hosts,
            started_at=group[0].timestamp, updated_at=group[-1].timestamp,
        ))
    return sorted(cases, key=lambda case: (-case.priority, case.started_at, case.id))
