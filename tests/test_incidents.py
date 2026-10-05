from core.alerter import Alert
from core.incidents import build_incident_cases


def alert(alert_id, rule_id, severity, source, timestamp, user, host=None):
    return Alert(
        id=alert_id, rule_id=rule_id, rule_title=rule_id, description="Observed signal",
        severity=severity, sources=[source], attack={}, remediation="Investigate",
        timestamp=timestamp,
        events=[{"timestamp": timestamp, "source": source, "user": user, "host": host,
                 "source_ip": None, "origin_file": "events.json"}],
    )


def test_case_groups_aliases_within_window_and_calculates_explainable_priority():
    entra = alert("a1", "RISKY-SIGNIN", "high", "entra", "2026-01-01T10:00:00Z", "alice@example.com")
    windows = alert("a2", "PRIV-LOGON", "critical", "windows", "2026-01-01T10:08:00Z", r"CORP\alice", "DC01")
    unrelated = alert("a3", "OTHER", "medium", "sysmon", "2026-01-01T10:08:00Z", "bob@elsewhere.test", "WS02")

    cases = build_incident_cases([unrelated, windows, entra])

    assert len(cases) == 2
    incident = next(case for case in cases if len(case.alerts) == 2)
    assert incident.sources == ["entra", "windows"]
    assert incident.users == ["CORP\\alice", "alice@example.com"]
    assert incident.priority == 100
    assert "Evidence spans multiple telemetry sources" in incident.priority_reasons
    assert incident.id == next(case for case in build_incident_cases([entra, unrelated, windows]) if len(case.alerts) == 2).id


def test_same_user_outside_window_is_not_grouped():
    first = alert("old", "A", "high", "entra", "2026-01-01T10:00:00Z", "alice@example.com")
    later = alert("later", "B", "high", "windows", "2026-01-01T10:31:00Z", "alice@example.com")
    assert len(build_incident_cases([first, later])) == 2
