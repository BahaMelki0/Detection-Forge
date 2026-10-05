from io import BytesIO

from core.alerter import Alert, AlertStore
from core.investigations import InvestigationStore
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
    app = create_app({"TESTING": True, "ALERTS_PATH": tmp_path / "alerts.json", "WORKSPACE_PATH": tmp_path / "workspace.json", "CASES_PATH": tmp_path / "cases"})
    store = InvestigationStore(tmp_path / "cases")
    investigation = store.create("Test case")
    investigation.alerts = [sample_alert()]
    store.save(investigation)
    client = app.test_client()
    dashboard = client.get("/")
    detail = client.get(f"/cases/{investigation.id}/alerts/alert-123")
    rules = client.get("/rules")
    theme = client.get("/static/design-system.css")
    assert dashboard.status_code == detail.status_code == rules.status_code == theme.status_code == 200
    assert b"--brand-accent: #f04452" in theme.data
    assert b"--brand-bg: #090a0d" in theme.data
    assert all(marker not in dashboard.data for marker in (bytes.fromhex("c383"), bytes.fromhex("c3a2"), bytes.fromhex("c382")))
    assert all(marker not in dashboard.data for marker in (bytes.fromhex("c383"), bytes.fromhex("c3a2"), bytes.fromhex("c382")))
    assert all(marker not in dashboard.data for marker in (bytes.fromhex("c383"), bytes.fromhex("c3a2"), bytes.fromhex("c382")))
    assert all(marker not in dashboard.data for marker in (bytes.fromhex("c383"), bytes.fromhex("c3a2"), bytes.fromhex("c382")))
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
    cases_path = tmp_path / "cases"
    app = create_app({"TESTING": True, "ALERTS_PATH": tmp_path / "alerts.json", "WORKSPACE_PATH": tmp_path / "workspace.json", "CASES_PATH": cases_path, "SECRET_KEY": "test"})
    client = app.test_client()
    created = client.post("/cases", data={"name": "Risky sign-in"})
    case_id = created.headers["Location"].rsplit("/", 1)[-1]
    response = client.post(
        f"/cases/{case_id}/analyze",
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
    investigation = InvestigationStore(cases_path).get(case_id)
    assert response.status_code == 200
    assert all(marker not in response.data for marker in (bytes.fromhex("c383"), bytes.fromhex("c3a2"), bytes.fromhex("c382")))
    assert len(investigation.alerts) == 1
    assert investigation.alerts[0].rule_id == "DF-ENTRA-001"
    assert investigation.alerts[0].events[0]["origin_file"] == "signins.json"
    assert len(investigation.files) == 1
    assert investigation.files[0].filename == "signins.json"
    assert len(investigation.events) == 1


def test_dashboard_rejects_unsupported_upload_extension(tmp_path):
    app = create_app({
        "TESTING": True, "ALERTS_PATH": tmp_path / "alerts.json",
        "WORKSPACE_PATH": tmp_path / "workspace.json", "CASES_PATH": tmp_path / "cases", "SECRET_KEY": "test",
    })
    client = app.test_client()
    created = client.post("/cases", data={"name": "Invalid log"})
    case_id = created.headers["Location"].rsplit("/", 1)[-1]
    response = client.post(
        f"/cases/{case_id}/analyze",
        data={"files": (BytesIO(b"not json"), "events.txt"), "types": "entra_signin"},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert all(marker not in response.data for marker in (bytes.fromhex("c383"), bytes.fromhex("c3a2"), bytes.fromhex("c382")))


def test_auto_upload_detects_profile_from_content(tmp_path):
    cases_path = tmp_path / "cases"
    app = create_app({"TESTING": True, "CASES_PATH": cases_path, "ALERTS_PATH": tmp_path / "alerts.json", "WORKSPACE_PATH": tmp_path / "workspace.json"})
    client = app.test_client()
    created = client.post("/cases", data={"name": "Auto profile"})
    case_id = created.headers["Location"].rsplit("/", 1)[-1]
    response = client.post(f"/cases/{case_id}/analyze", data={
        "files": (BytesIO(b'{"createdDateTime":"2026-01-01T10:00:00Z","activityDisplayName":"user_sign_in","userPrincipalName":"alice@example.com","status":{"errorCode":0},"riskLevelDuringSignIn":"high"}\n'), "unknown.jsonl"),
        "types": "auto",
    }, content_type="multipart/form-data", follow_redirects=True)
    investigation = InvestigationStore(cases_path).get(case_id)
    assert response.status_code == 200
    assert investigation.files[0].profile == "entra_signin"


def test_case_can_be_resolved_then_deleted_without_touching_source_file(tmp_path):
    cases_path = tmp_path / "cases"
    source = tmp_path / "source.jsonl"
    source.write_text('{"EventID":4625}\n', encoding="utf-8")
    app = create_app({"TESTING": True, "CASES_PATH": cases_path, "ALERTS_PATH": tmp_path / "alerts.json", "WORKSPACE_PATH": tmp_path / "workspace.json"})
    client = app.test_client()
    created = client.post("/cases", data={"name": "Lifecycle case"})
    case_id = created.headers["Location"].rsplit("/", 1)[-1]
    client.post(f"/cases/{case_id}/watch", data={"paths": str(source), "interval": "60", "enabled": "on"})
    resolved = client.post(f"/cases/{case_id}/status", data={"status": "resolved", "resolution_notes": "False positive confirmed"})
    investigation = InvestigationStore(cases_path).get(case_id)
    assert resolved.status_code == 302
    assert investigation.status == "resolved"
    assert investigation.resolution_notes == "False positive confirmed"
    assert investigation.watcher_enabled is True
    failed_delete = client.post(f"/cases/{case_id}/delete", data={"confirm_name": "wrong"})
    assert failed_delete.status_code == 302
    assert InvestigationStore(cases_path).get(case_id) is not None
    deleted = client.post(f"/cases/{case_id}/delete", data={"confirm_name": "Lifecycle case"})
    assert deleted.status_code == 302
    assert InvestigationStore(cases_path).get(case_id) is None
    assert source.is_file()


def test_watched_jsonl_scan_updates_case_and_exports_pdf(tmp_path):
    cases_path = tmp_path / "cases"
    source = tmp_path / "entra.jsonl"
    source.write_text("", encoding="utf-8")
    app = create_app({"TESTING": True, "CASES_PATH": cases_path, "ALERTS_PATH": tmp_path / "alerts.json", "WORKSPACE_PATH": tmp_path / "workspace.json"})
    client = app.test_client()
    created = client.post("/cases", data={"name": "Live sign-in"})
    case_id = created.headers["Location"].rsplit("/", 1)[-1]
    client.post(f"/cases/{case_id}/watch", data={"paths": str(source), "interval": "60", "enabled": "on"})
    first_scan = client.post(f"/cases/{case_id}/scan", follow_redirects=True)
    assert b"No complete new JSONL records" in first_scan.data
    with source.open("a", encoding="utf-8") as stream:
        stream.write('{"createdDateTime":"2026-01-01T10:00:00Z","activityDisplayName":"user_sign_in","userPrincipalName":"alice@example.com","status":{"errorCode":0},"riskLevelDuringSignIn":"high"}\n')
    scanned = client.post(f"/cases/{case_id}/scan", follow_redirects=True)
    investigation = InvestigationStore(cases_path).get(case_id)
    assert b"Processed 1 new events" in scanned.data
    assert len(investigation.events) == 1
    assert investigation.files[0].profile == "entra_signin"
    report = client.get(f"/cases/{case_id}/report.pdf")
    assert report.status_code == 200
    assert report.mimetype == "application/pdf"
    assert report.data.startswith(b"%PDF")


def test_upload_batches_accumulate_correlate_export_and_clear(tmp_path):
    cases_path = tmp_path / "cases"
    app = create_app({
        "TESTING": True, "ALERTS_PATH": tmp_path / "alerts.json",
        "WORKSPACE_PATH": tmp_path / "workspace.json", "CASES_PATH": cases_path, "SECRET_KEY": "test",
    })
    client = app.test_client()
    created = client.post("/cases", data={"name": "Hybrid activity"})
    case_id = created.headers["Location"].rsplit("/", 1)[-1]
    client.post(
        f"/cases/{case_id}/analyze",
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
        f"/cases/{case_id}/analyze",
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
    state = InvestigationStore(cases_path).get(case_id)
    correlation = next(alert for alert in state.alerts if alert.rule_id == "DF-CROSS-001")
    assert len(state.files) == 2
    assert len(state.events) == 2
    assert {event["origin_file"] for event in correlation.events} == {"entra.jsonl", "security.jsonl"}
    assert b"entra.jsonl" in second.data and b"security.jsonl" in second.data

    report = client.get("/report")
    assert report.status_code == 200
    assert "attachment; filename=detection-forge-report.html" == report.headers["Content-Disposition"]
    assert b"Input file source:" in report.data
    assert b"entra.jsonl, security.jsonl" in report.data

    cleared = client.post(f"/cases/{case_id}/clear", follow_redirects=True)
    assert b"Telemetry and alerts cleared" in cleared.data
    assert InvestigationStore(cases_path).get(case_id).files == []


def test_separate_cases_never_correlate_each_others_events(tmp_path):
    cases_path = tmp_path / "cases"
    app = create_app({"TESTING": True, "CASES_PATH": cases_path, "ALERTS_PATH": tmp_path / "alerts.json", "WORKSPACE_PATH": tmp_path / "workspace.json"})
    client = app.test_client()
    ids = []
    for name in ("Entra investigation", "Windows investigation"):
        response = client.post("/cases", data={"name": name})
        ids.append(response.headers["Location"].rsplit("/", 1)[-1])
    client.post(f"/cases/{ids[0]}/analyze", data={
        "files": (BytesIO(b'{"createdDateTime":"2026-01-01T10:00:00Z","activityDisplayName":"user_sign_in","userPrincipalName":"alice@example.com","status":{"errorCode":0},"riskLevelDuringSignIn":"high"}'), "entra.jsonl"),
        "types": "entra_signin",
    }, content_type="multipart/form-data")
    client.post(f"/cases/{ids[1]}/analyze", data={
        "files": (BytesIO(b'{"TimeCreated":"2026-01-01T10:05:00Z","EventID":4672,"Computer":"DC01","SubjectUserName":"alice@example.com"}'), "security.jsonl"),
        "types": "windows_security",
    }, content_type="multipart/form-data")
    store = InvestigationStore(cases_path)
    first, second = (store.get(case_id) for case_id in ids)
    assert len(first.events) == len(second.events) == 1
    assert all(alert.rule_id != "DF-CROSS-001" for alert in first.alerts + second.alerts)


def test_reupload_deduplicates_events_and_keeps_both_file_origins(tmp_path):
    cases_path = tmp_path / "cases"
    app = create_app({"TESTING": True, "ALERTS_PATH": tmp_path / "alerts.json",
                      "WORKSPACE_PATH": tmp_path / "workspace.json", "CASES_PATH": cases_path, "SECRET_KEY": "test"})
    client = app.test_client()
    created = client.post("/cases", data={"name": "Duplicate check"})
    case_id = created.headers["Location"].rsplit("/", 1)[-1]
    payload = b'{"createdDateTime":"2026-01-01T10:00:00Z","activityDisplayName":"user_sign_in",' \
              b'"userPrincipalName":"alice@example.com","status":{"errorCode":0},' \
              b'"riskLevelDuringSignIn":"high"}'
    for filename in ("signins-a.jsonl", "signins-b.jsonl"):
        response = client.post(f"/cases/{case_id}/analyze", data={
            "files": (BytesIO(payload), filename), "types": "entra_signin",
        }, content_type="multipart/form-data", follow_redirects=True)
        assert response.status_code == 200
    state = InvestigationStore(cases_path).get(case_id)
    assert len(state.files) == 2
    assert len(state.events) == 1
    assert set(state.events[0].origin_files) == {"signins-a.jsonl", "signins-b.jsonl"}
    assert len(state.alerts) == 1
    assert "duplicate event record" in response.get_data(as_text=True)


def test_incident_case_route_and_local_triage_render(tmp_path, monkeypatch):
    alert = sample_alert()
    cases_path = tmp_path / "cases"
    app = create_app({"TESTING": True, "ALERTS_PATH": tmp_path / "alerts.json",
                      "WORKSPACE_PATH": tmp_path / "workspace.json", "CASES_PATH": cases_path})
    store = InvestigationStore(cases_path)
    investigation = store.create("Triage case")
    investigation.alerts = [alert]
    store.save(investigation)
    response = app.test_client().get(f"/cases/{investigation.id}")
    assert response.status_code == 200
    assert b"EXPLAINABLE REVIEW PRIORITY" in response.data
    assert all(marker not in response.data for marker in (bytes.fromhex("c383"), bytes.fromhex("c3a2"), bytes.fromhex("c382")))
    assert all(marker not in response.data for marker in (bytes.fromhex("c383"), bytes.fromhex("c3a2"), bytes.fromhex("c382")))
    monkeypatch.setattr("core.copilot.summarize_case", lambda _case: "Assessment: review the sign-in evidence.")
    triage = app.test_client().post(f"/cases/{investigation.id}/triage")
    assert triage.status_code == 200
    assert b"Assessment: review the sign-in evidence." in triage.data


def test_local_copilot_is_optional_and_evidence_is_redacted(monkeypatch):
    import json
    from core import copilot
    from core.incidents import build_incident_cases
    alert = sample_alert()
    alert.events[0]["details"] = {"command_line": "tool --password=supersecret", "risk": "high"}
    case = build_incident_cases([alert])[0]
    captured = {}

    class Response:
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def read(self): return json.dumps({"message": {"content": "Assessment: review.\nEvidence: one risky sign-in."}}).encode()

    def fake_urlopen(request, timeout):
        captured["body"] = json.loads(request.data)
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr(copilot, "urlopen", fake_urlopen)
    assert "Assessment: review" in copilot.summarize_case(case)
    serialized = json.dumps(captured["body"])
    assert "supersecret" not in serialized
    assert "[REDACTED]" in serialized
    assert captured["body"]["model"] == "qwen3.5:9b"
    assert "Never infer an IP's public/private status" in captured["body"]["messages"][0]["content"]


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
    assert all(marker not in response.data for marker in (bytes.fromhex("c383"), bytes.fromhex("c3a2"), bytes.fromhex("c382")))
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
