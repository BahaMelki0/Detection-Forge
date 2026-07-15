from pathlib import Path

import pytest

from main import RESET_COLOR, FILE_TYPES, build_parser, install_rule, main, make_input, severity_label, use_color


def test_severity_label_is_aligned_without_color():
    assert severity_label("high", colored=False) == "HIGH    "
    assert severity_label("critical", colored=False) == "CRITICAL"


def test_severity_label_adds_ansi_color_when_enabled():
    label = severity_label("critical", colored=True)
    assert label.startswith("\033[")
    assert "CRITICAL" in label
    assert label.endswith(RESET_COLOR)


def test_color_mode_can_be_forced(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert use_color("always") is True
    assert use_color("auto") is False
    assert use_color("never") is False


def test_file_type_profiles_infer_source_and_log_type():
    assert FILE_TYPES["entra_signin"] == ("entra", "signin")
    assert FILE_TYPES["windows_security"] == ("windows", "security")


def test_root_help_is_branded_and_example_driven():
    help_text = build_parser().format_help()
    assert "DETECTION FORGE" in help_text
    assert "QUICK ANALYSIS" in help_text
    assert "positional arguments" not in help_text


def test_no_command_only_displays_help(capsys):
    assert main([]) == 0
    output = capsys.readouterr().out
    assert "DETECTION FORGE" in output
    assert "Processed" not in output


def test_source_and_log_type_combination_is_validated():
    with pytest.raises(ValueError, match="not valid for windows"):
        make_input("windows", "signin", Path("events.json"))


def test_install_rule_validates_and_routes_rule(tmp_path):
    registry = tmp_path / "rules"
    candidate = tmp_path / "candidate.yml"
    candidate.write_text(
        """id: TEST-ENTRA-001
title: Test Entra rule
type: event
source: entra
severity: medium
match:
  conditions:
    action: user_sign_in
attack:
  id: T1078.004
  name: Cloud Accounts
  tactic: Initial Access
  url: https://attack.mitre.org/techniques/T1078/004/
remediation: Investigate the account.
""",
        encoding="utf-8",
    )
    installed = install_rule(candidate, registry)
    assert installed.parent.name == "entra"
    assert installed.is_file()
    with pytest.raises(ValueError, match="already installed"):
        install_rule(candidate, registry)


def test_analyze_command_accepts_uploaded_file(tmp_path, capsys):
    log_file = tmp_path / "signins.json"
    output = tmp_path / "alerts.json"
    log_file.write_text(
        '[{"createdDateTime":"2026-01-01T10:00:00Z","activityDisplayName":"user_sign_in",'
        '"userPrincipalName":"alice@example.com","status":{"errorCode":0},'
        '"riskLevelDuringSignIn":"high"}]',
        encoding="utf-8",
    )
    exit_code = main([
        "analyze", "--file", str(log_file), "--type", "entra_signin",
        "--output", str(output), "--color", "never",
    ])
    assert exit_code == 0
    assert output.is_file()
    assert "Generated 1 alerts" in capsys.readouterr().out
