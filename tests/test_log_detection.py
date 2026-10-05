import json

from core.log_detection import detect_log_type
from core.watcher import read_new_records


def test_detects_supported_log_type_from_content_not_filename(tmp_path):
    path = tmp_path / "mystery.jsonl"
    path.write_text(json.dumps({
        "createdDateTime": "2026-01-01T10:00:00Z", "activityDisplayName": "user_sign_in",
        "userPrincipalName": "analyst@example.test", "status": {"errorCode": 0},
        "riskLevelDuringSignIn": "high",
    }) + "\n", encoding="utf-8")
    detected = detect_log_type(path)
    assert detected["profile"] == "entra_signin"
    assert detected["confidence"] >= 0.6


def test_ambiguous_log_type_requires_manual_selection(tmp_path):
    path = tmp_path / "unknown.json"
    path.write_text('{"message":"hello"}\n', encoding="utf-8")
    assert detect_log_type(path)["profile"] is None


def test_file_watcher_waits_for_complete_lines_and_resumes_from_checkpoint(tmp_path):
    path = tmp_path / "entra.jsonl"
    path.write_bytes(b'{"createdDateTime":"2026-01-01T10:00:00Z"')
    initial, checkpoint, count = read_new_records(path, {})
    assert initial == b"" and count == 0 and checkpoint["offset"] == 0

    with path.open("ab") as stream:
        stream.write(b',"activityDisplayName":"user_sign_in"}\n')
    chunk, checkpoint, count = read_new_records(path, {})
    assert count == 1 and b"user_sign_in" in chunk
    path.write_bytes(path.read_bytes() + b'{"createdDateTime":"2026-01-01T10:01:00Z"}\n')
    appended, new_checkpoint, count = read_new_records(path, checkpoint)
    assert count == 1 and b"10:01:00" in appended
    assert new_checkpoint["offset"] > checkpoint["offset"]


def test_file_watcher_resets_checkpoint_after_truncation(tmp_path):
    path = tmp_path / "rotated.jsonl"
    path.write_text('{"EventID":4625,"TimeCreated":"2026-01-01T10:00:00Z"}\n', encoding="utf-8")
    _, checkpoint, _ = read_new_records(path, {})
    path.write_text('{"EventID":4625,"TimeCreated":"2026-01-01T10:00:01Z"}\n', encoding="utf-8")
    chunk, new_checkpoint, count = read_new_records(path, checkpoint)
    assert count == 1 and b"10:00:01" in chunk
    assert new_checkpoint["offset"] == path.stat().st_size
