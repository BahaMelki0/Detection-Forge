"""Content-based identification of supported JSON security log profiles."""

from __future__ import annotations

import json
from pathlib import Path

from core.pipeline import FILE_TYPES


def _records(path: str | Path, limit: int = 20) -> list[dict]:
    text = Path(path).read_text(encoding="utf-8-sig")[:2_000_000]
    try:
        payload = json.loads(text)
        if isinstance(payload, dict):
            for key in ("value", "records", "events", "items"):
                if isinstance(payload.get(key), list):
                    payload = payload[key]
                    break
        values = payload if isinstance(payload, list) else [payload]
        return [item for item in values[:limit] if isinstance(item, dict)]
    except json.JSONDecodeError:
        values = []
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                values.append(item)
            if len(values) >= limit:
                break
        return values


def _keys(record: dict) -> set[str]:
    keys = set(record)
    for value in record.values():
        if isinstance(value, dict):
            keys.update(value)
    return {str(key).casefold() for key in keys}


def detect_log_type(path: str | Path) -> dict:
    """Return profile, confidence and rationale; uncertain formats need analyst choice."""
    records = _records(path)
    if not records:
        return {"profile": None, "confidence": 0.0, "reason": "No JSON event records were recognized."}
    scores = {profile: 0 for profile in FILE_TYPES}
    for record in records:
        keys = _keys(record)
        entra_signin = {"userprincipalname", "risklevelduringlogin", "risklevelduringsignin", "conditionalaccessstatus", "isinteractive"}
        entra_audit = {"activitydatetime", "activitydisplayname", "category", "initiatedby", "targetresources"}
        windows = {"eventid", "timecreated", "providername", "eventdata", "system"}
        sysmon = {"processguid", "parentprocessguid", "image", "parentimage", "originalfilename"}
        if len(keys & entra_signin) >= 2 or ({"createddatetime", "status"} <= keys and "userprincipalname" in keys):
            scores["entra_signin"] += 3
        if {'createddatetime', 'serviceprincipalid'} <= keys and 'activitydatetime' not in keys:
            scores['entra_signin'] += 4
        if len(keys & entra_audit) >= 2 or ({"activitydatetime", "activitydisplayname"} <= keys):
            scores["entra_audit"] += 3
        if "eventid" in keys and ("timecreated" in keys or "system" in keys or "eventdata" in keys):
            scores["windows_security"] += 3
        if len(keys & sysmon) >= 2 and ("eventid" in keys or "utcTime".casefold() in keys):
            scores["sysmon"] += 4
    ranked = sorted(scores.items(), key=lambda pair: (-pair[1], pair[0]))
    best, score = ranked[0]
    total = sum(scores.values())
    confidence = score / max(total, 1)
    if score < 3 or (len(ranked) > 1 and ranked[1][1] == score):
        return {"profile": None, "confidence": round(confidence, 2), "reason": "The content is ambiguous or does not match a supported log profile."}
    return {"profile": best, "confidence": round(confidence, 2), "reason": f"Matched fields from the {best.replace('_', ' ')} schema across {len(records)} sample record(s)."}
