from connectors.entra_connector import EntraConnector
from connectors.sysmon_connector import SysmonConnector
from connectors.windows_connector import WindowsConnector


def test_entra_connector_normalizes_risky_sign_in():
    event = EntraConnector().normalize({
        "createdDateTime": "2026-01-01T10:00:00Z", "category": "sign_in",
        "activityDisplayName": "user_sign_in", "userPrincipalName": "alice@example.com",
        "ipAddress": "192.0.2.1", "status": {"errorCode": 0},
        "riskLevelDuringSignIn": "high",
    })
    assert event.source == "entra"
    assert event.outcome == "success"
    assert event.details["risk_level"] == "high"


def test_windows_and_sysmon_processes_share_canonical_action():
    windows = WindowsConnector().normalize({
        "TimeCreated": "2026-01-01T10:00:00Z", "EventID": 4688,
        "NewProcessName": "powershell.exe", "CommandLine": "powershell -enc AAA",
    })
    sysmon = SysmonConnector().normalize({
        "UtcTime": "2026-01-01T10:00:00Z", "EventID": 1,
        "Image": "powershell.exe", "CommandLine": "powershell -enc AAA",
    })
    assert windows.action == sysmon.action == "process_created"


def test_connector_reads_json_array_and_export_wrapper(tmp_path):
    array_file = tmp_path / "events.json"
    array_file.write_text(
        '[{"TimeCreated":"2026-01-01T10:00:00Z","EventID":4624}]', encoding="utf-8"
    )
    wrapper_file = tmp_path / "export.json"
    wrapper_file.write_text(
        '{"value":[{"TimeCreated":"2026-01-01T10:00:00Z","EventID":4625}]}', encoding="utf-8"
    )
    assert len(list(WindowsConnector().read(array_file))) == 1
    assert list(WindowsConnector().read(wrapper_file))[0].outcome == "failure"


def test_entra_audit_log_normalization():
    event = EntraConnector("audit").normalize({
        "activityDateTime": "2026-01-01T10:00:00Z",
        "activityDisplayName": "Add member to role",
        "result": "success",
        "initiatedBy": {"user": {"userPrincipalName": "admin@example.com", "ipAddress": "192.0.2.4"}},
        "targetResources": [{"displayName": "alice@example.com"}],
    })
    assert event.event_type == "audit"
    assert event.user == "admin@example.com"
    assert event.details["target_names"] == ["alice@example.com"]
