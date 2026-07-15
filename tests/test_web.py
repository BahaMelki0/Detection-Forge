from io import BytesIO

from core.alerter import Alert, AlertStore
from core.workspace import AnalysisWorkspace
from web.app import create_app


def sample_alert():
    return Alert(
        id="alert-123", rule_id="DF-TEST-001", rule_title="Test detection",
        description="Evidence description", severity="high", sources=["entra"],
        attack={"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1078/"},
        remediation="Reset credentials", timestamp="2026-01-01T10:00:00Z",
        events=[{"timestamp": "2026-01-01T10:00:00Z", "source": "entra", "action": "user_sign_in", "user": "alice@example.com", "host": None, "source_ip": "192.0.2.1", "outcome": "success", "raw": {}}],
    )


def test_dashboard_detail_and_rules_routes(tmp_path):
    store_path = tmp_path / "alerts.json"
    AlertStore(store_path).save([sample_alert()])
    app = create_app({"TESTING": True, "ALERTS_PATH": store_path, "WORKSPACE_PATH": tmp_path / "workspace.json"})
    client = app.test_client()
    dashboard = client.get("/")
    detail = client.get("/alerts/alert-123")
    rules = client.get("/rules")
    assert dashboard.status_code == detail.status_code == rules.status_code == 200
    assert b"Test detection" in dashboard.data
    assert b"brand-copy" in dashboard.data
    assert b"HYBRID THREAT ANALYTICS" in dashboard.data
    assert b"Evidence timeline" in detail.data
    assert b"DF-CROSS-001" in rules.data


def test_unknown_alert_returns_404(tmp_path):
    app = create_app({"TESTING": True, "ALERTS_PATH": tmp_path / "missing.json", "WORKSPACE_PATH": tmp_path / "workspace.json"})
    assert app.test_client().get("/alerts/missing").status_code == 404


def test_rules_can_be_filtered_by_telemetry_source(tmp_path):
    app = create_app({
        "TESTING": True, "ALERTS_PATH": tmp_path / "alerts.json",
        "WORKSPACE_PATH": tmp_path / "workspace.json",
    })
    client = app.test_client()
    entra = client.get("/rules?source=entra")
    windows = client.get("/rules?source=windows")
    sysmon = client.get("/rules?source=sysmon")
    assert b"DF-ENTRA-001" in entra.data and b"DF-CROSS-001" in entra.data
    assert b"DF-WIN-008" not in entra.data
    assert b"DF-WIN-008" in windows.data and b"DF-CROSS-001" in windows.data
    assert b"DF-ENTRA-001" not in windows.data
    assert b"DF-SYSMON-001" in sysmon.data and b"DF-CROSS-001" not in sysmon.data
    assert b"Showing" in sysmon.data and b"rules" in sysmon.data


def test_dashboard_can_upload_and_analyze_typed_log(tmp_path):
    alerts_path = tmp_path / "alerts.json"
    workspace_path = tmp_path / "workspace.json"
    app = create_app({"TESTING": True, "ALERTS_PATH": alerts_path, "WORKSPACE_PATH": workspace_path, "SECRET_KEY": "test"})
    response = app.test_client().post(
        "/analyze",
        data={
            "files": (BytesIO(
                b'[{"createdDateTime":"2026-01-01T10:00:00Z",'
                b'"activityDisplayName":"user_sign_in","userPrincipalName":"alice@example.com",'
                b'"status":{"errorCode":0},"riskLevelDuringSignIn":"high"}]'
            ), "signins.json"),
            "types": "entra_signin",
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    alerts = AlertStore(alerts_path).load()
    assert response.status_code == 200
    assert b"Added 1 events from 1 file(s)" in response.data
    assert len(alerts) == 1
    assert alerts[0].rule_id == "DF-ENTRA-001"
    assert alerts[0].events[0]["origin_file"] == "signins.json"
    workspace = AnalysisWorkspace(workspace_path).load()
    assert len(workspace.files) == 1
    assert workspace.files[0].filename == "signins.json"
    assert len(workspace.events) == 1


def test_dashboard_rejects_unsupported_upload_extension(tmp_path):
    app = create_app({
        "TESTING": True, "ALERTS_PATH": tmp_path / "alerts.json",
        "WORKSPACE_PATH": tmp_path / "workspace.json", "SECRET_KEY": "test",
    })
    response = app.test_client().post(
        "/analyze",
        data={"files": (BytesIO(b"not json"), "events.txt"), "types": "entra_signin"},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert b"expected a .json, .jsonl, or .ndjson file" in response.data


def test_upload_batches_accumulate_correlate_export_and_clear(tmp_path):
    alerts_path = tmp_path / "alerts.json"
    workspace_path = tmp_path / "workspace.json"
    app = create_app({
        "TESTING": True, "ALERTS_PATH": alerts_path,
        "WORKSPACE_PATH": workspace_path, "SECRET_KEY": "test",
    })
    client = app.test_client()
    client.post(
        "/analyze",
        data={
            "files": (BytesIO(
                b'{"createdDateTime":"2026-01-01T10:00:00Z","activityDisplayName":"user_sign_in",'
                b'"userPrincipalName":"alice@example.com","status":{"errorCode":0},'
                b'"riskLevelDuringSignIn":"high"}'
            ), "entra.jsonl"),
            "types": "entra_signin",
        },
        content_type="multipart/form-data",
    )
    second = client.post(
        "/analyze",
        data={
            "files": (BytesIO(
                b'{"TimeCreated":"2026-01-01T10:05:00Z","EventID":4672,'
                b'"Computer":"DC01","SubjectUserName":"alice@example.com"}'
            ), "security.jsonl"),
            "types": "windows_security",
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    state = AnalysisWorkspace(workspace_path).load()
    alerts = AlertStore(alerts_path).load()
    correlation = next(alert for alert in alerts if alert.rule_id == "DF-CROSS-001")
    assert len(state.files) == 2
    assert len(state.events) == 2
    assert {event["origin_file"] for event in correlation.events} == {"entra.jsonl", "security.jsonl"}
    assert b"entra.jsonl" in second.data and b"security.jsonl" in second.data

    report = client.get("/report")
    assert report.status_code == 200
    assert "attachment; filename=detection-forge-report.html" == report.headers["Content-Disposition"]
    assert b"Input file source:" in report.data
    assert b"entra.jsonl, security.jsonl" in report.data

    cleared = client.post("/workspace/clear", follow_redirects=True)
    assert b"Workspace cleared" in cleared.data
    assert AnalysisWorkspace(workspace_path).load().files == []
    assert AlertStore(alerts_path).load() == []


def valid_rule_form(rule_id="DF-TEST-100"):
    return {
        "rule_id": rule_id,
        "title": "Suspicious command interpreter",
        "description": "Detects a representative process creation pattern.",
        "rule_type": "event",
        "severity": "high",
        "sources": ["windows", "sysmon"],
        "condition_field": ["action", "details.process_name"],
        "condition_operator": ["equals", "contains"],
        "condition_value": ["process_created", "powershell"],
        "attack_id": "T1059.001",
        "attack_name": "PowerShell",
        "attack_tactic": "Execution",
        "attack_url": "https://attack.mitre.org/techniques/T1059/001/",
        "remediation": "Isolate and investigate the endpoint.",
        "false_positives": "Approved administration scripts",
    }


def test_rule_form_creates_valid_yaml_and_rejects_duplicate(tmp_path):
    rules_path = tmp_path / "rules"
    app = create_app({
        "TESTING": True, "RULES_PATH": rules_path,
        "ALERTS_PATH": tmp_path / "alerts.json", "WORKSPACE_PATH": tmp_path / "workspace.json",
        "SECRET_KEY": "test",
    })
    client = app.test_client()
    assert client.get("/rules/new").status_code == 200
    created = client.post("/rules/new", data=valid_rule_form(), follow_redirects=True)
    installed = rules_path / "windows" / "df-test-100.yml"
    assert created.status_code == 200
    assert b"Detection rule DF-TEST-100 created" in created.data
    assert installed.is_file()
    contents = installed.read_text(encoding="utf-8")
    assert "details.process_name:" in contents
    assert "contains: powershell" in contents

    duplicate = client.post("/rules/new", data=valid_rule_form())
    assert duplicate.status_code == 400
    assert b"already installed" in duplicate.data
    assert len(list(rules_path.rglob("*.yml"))) == 1


def test_rule_form_reports_bad_regex_without_writing_file(tmp_path):
    rules_path = tmp_path / "rules"
    app = create_app({
        "TESTING": True, "RULES_PATH": rules_path,
        "ALERTS_PATH": tmp_path / "alerts.json", "WORKSPACE_PATH": tmp_path / "workspace.json",
        "SECRET_KEY": "test",
    })
    data = valid_rule_form("DF-TEST-101")
    data["condition_field"] = ["details.command_line"]
    data["condition_operator"] = ["regex"]
    data["condition_value"] = ["(unclosed"]
    response = app.test_client().post("/rules/new", data=data)
    assert response.status_code == 400
    assert b"invalid regular expression" in response.data
    assert not list(rules_path.rglob("*.yml"))


def test_rule_form_creates_two_stage_correlation(tmp_path):
    rules_path = tmp_path / "rules"
    app = create_app({
        "TESTING": True, "RULES_PATH": rules_path,
        "ALERTS_PATH": tmp_path / "alerts.json", "WORKSPACE_PATH": tmp_path / "workspace.json",
        "SECRET_KEY": "test",
    })
    data = valid_rule_form("DF-CROSS-100")
    data.update({
        "rule_type": "correlation",
        "stage1_source": "entra", "stage1_field": "action",
        "stage1_operator": "equals", "stage1_value": "user_sign_in",
        "stage2_source": "windows", "stage2_field": "action",
        "stage2_operator": "equals", "stage2_value": "special_privileges_assigned",
        "group_by": "user", "timeframe_minutes": "20",
    })
    response = app.test_client().post("/rules/new", data=data, follow_redirects=True)
    installed = rules_path / "cross_source" / "df-cross-100.yml"
    assert response.status_code == 200
    assert installed.is_file()
    assert "timeframe_minutes: 20" in installed.read_text(encoding="utf-8")
