"""Build validated detection rule documents from structured form fields."""

from __future__ import annotations

from datetime import date
import re
from typing import Any
from urllib.parse import urlparse

CONDITION_FIELDS = (
    "action", "outcome", "event_type", "user", "host", "source_ip",
    "details.event_id", "details.logon_type", "details.process_name",
    "details.command_line", "details.parent_process", "details.group_name",
    "details.task_name", "details.service_name", "details.service_file_name",
    "details.risk_level", "details.risk_state", "details.conditional_access",
    "details.application", "details.country", "details.category", "details.operation_type",
)
CONDITION_OPERATORS = ("equals", "not_equals", "contains", "contains_any", "in", "regex")
SOURCES = ("entra", "windows", "sysmon")
SEVERITIES = ("low", "medium", "high", "critical")
GROUP_FIELDS = ("user", "host", "source_ip")


class RuleFormError(ValueError):
    pass


def build_rule_document(form: Any) -> dict[str, Any]:
    rule_id = _required(form, "rule_id")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}", rule_id):
        raise RuleFormError("Rule ID must be 3-64 characters using letters, numbers, dots, dashes, or underscores.")
    rule_type = _choice(form, "rule_type", {"event", "correlation"})
    severity = _choice(form, "severity", set(SEVERITIES))
    attack_url = _required(form, "attack_url")
    parsed_url = urlparse(attack_url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise RuleFormError("MITRE ATT&CK URL must be a valid http:// or https:// URL.")

    document: dict[str, Any] = {
        "id": rule_id,
        "title": _required(form, "title"),
        "description": _required(form, "description"),
        "type": rule_type,
        "severity": severity,
        "status": "experimental",
        "author": "Detection Forge UI",
        "date": date.today().isoformat(),
        "attack": {
            "id": _required(form, "attack_id"),
            "name": _required(form, "attack_name"),
            "tactic": _required(form, "attack_tactic"),
            "url": attack_url,
        },
        "remediation": _required(form, "remediation"),
    }
    false_positives = [value.strip() for value in form.get("false_positives", "").splitlines() if value.strip()]
    if false_positives:
        document["false_positives"] = false_positives

    if rule_type == "event":
        sources = form.getlist("sources")
        if not sources or any(source not in SOURCES for source in sources):
            raise RuleFormError("Select at least one valid telemetry source.")
        document["sources"] = list(dict.fromkeys(sources))
        document["match"] = {"conditions": _event_conditions(form)}
    else:
        first = _stage(form, 1)
        second = _stage(form, 2)
        document["sources"] = list(dict.fromkeys([first["source"], second["source"]]))
        document["group_by"] = _choice(form, "group_by", set(GROUP_FIELDS))
        try:
            timeframe = int(_required(form, "timeframe_minutes"))
        except ValueError as exc:
            raise RuleFormError("Correlation timeframe must be a whole number of minutes.") from exc
        if not 1 <= timeframe <= 1440:
            raise RuleFormError("Correlation timeframe must be between 1 and 1440 minutes.")
        document["timeframe_minutes"] = timeframe
        document["sequence"] = [first, second]
    return document


def _event_conditions(form: Any) -> dict[str, Any]:
    fields = form.getlist("condition_field")
    operators = form.getlist("condition_operator")
    values = form.getlist("condition_value")
    if not (len(fields) == len(operators) == len(values)):
        raise RuleFormError("Condition rows are incomplete or malformed.")
    conditions: dict[str, Any] = {}
    for index, (field, operator, value) in enumerate(zip(fields, operators, values), start=1):
        if not any((field.strip(), operator.strip(), value.strip())):
            continue
        if field in conditions:
            raise RuleFormError(f"Condition field '{field}' is duplicated; combine its values in one row.")
        conditions[field] = _condition(field, operator, value, f"Condition {index}")
    if not conditions:
        raise RuleFormError("Add at least one complete detection condition.")
    return conditions


def _stage(form: Any, number: int) -> dict[str, Any]:
    prefix = f"stage{number}"
    source = _choice(form, f"{prefix}_source", set(SOURCES))
    field = _required(form, f"{prefix}_field")
    operator = _required(form, f"{prefix}_operator")
    value = _required(form, f"{prefix}_value")
    return {"source": source, "conditions": {field: _condition(field, operator, value, f"Stage {number}")}}


def _condition(field: str, operator: str, value: str, label: str) -> Any:
    if field not in CONDITION_FIELDS:
        raise RuleFormError(f"{label}: unsupported normalized field '{field}'.")
    if operator not in CONDITION_OPERATORS:
        raise RuleFormError(f"{label}: unsupported operator '{operator}'.")
    value = value.strip()
    if not value:
        raise RuleFormError(f"{label}: a comparison value is required.")
    if operator == "equals":
        return _scalar(value)
    if operator == "regex":
        try:
            re.compile(value)
        except re.error as exc:
            raise RuleFormError(f"{label}: invalid regular expression: {exc}.") from exc
        return {operator: value}
    if operator in {"contains_any", "in"}:
        values = [_scalar(item.strip()) for item in value.split(",") if item.strip()]
        if not values:
            raise RuleFormError(f"{label}: enter at least one comma-separated value.")
        return {operator: values}
    return {operator: _scalar(value)}


def _scalar(value: str) -> Any:
    lowered = value.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    return value


def _required(form: Any, name: str) -> str:
    value = str(form.get(name, "")).strip()
    if not value:
        raise RuleFormError(f"{name.replace('_', ' ').title()} is required.")
    return value


def _choice(form: Any, name: str, choices: set[str]) -> str:
    value = _required(form, name).lower()
    if value not in choices:
        raise RuleFormError(f"{name.replace('_', ' ').title()} has an unsupported value.")
    return value
