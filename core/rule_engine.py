"""YAML rule loading, validation and condition evaluation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml

from core.event import Event


class RuleError(ValueError):
    """Raised when a detection rule is malformed."""


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    title: str
    description: str
    type: str
    severity: str
    sources: tuple[str, ...]
    attack: dict[str, str]
    remediation: str
    match: dict[str, Any] | None = None
    sequence: tuple[dict[str, Any], ...] = ()
    group_by: str = "user"
    timeframe_minutes: int = 15

    @classmethod
    def from_dict(cls, value: dict[str, Any], origin: Path) -> "Rule":
        required = {"id", "title", "type", "severity", "attack", "remediation"}
        missing = required - value.keys()
        if missing:
            raise RuleError(f"{origin}: missing {', '.join(sorted(missing))}")
        rule_type = value["type"]
        if rule_type not in {"event", "correlation"}:
            raise RuleError(f"{origin}: type must be event or correlation")
        severity = str(value["severity"]).lower()
        if severity not in {"low", "medium", "high", "critical"}:
            raise RuleError(f"{origin}: unsupported severity {severity}")
        sources = value.get("sources") or ([value["source"]] if value.get("source") else [])
        sequence = tuple(value.get("sequence", []))
        if rule_type == "event" and not value.get("match"):
            raise RuleError(f"{origin}: event rules require match")
        if rule_type == "correlation" and len(sequence) < 2:
            raise RuleError(f"{origin}: correlation rules require at least two stages")
        return cls(
            id=str(value["id"]), title=str(value["title"]),
            description=str(value.get("description", "")), type=rule_type,
            severity=severity, sources=tuple(str(source).lower() for source in sources),
            attack=dict(value["attack"]), remediation=str(value["remediation"]),
            match=value.get("match"), sequence=sequence,
            group_by=str(value.get("group_by", "user")),
            timeframe_minutes=int(value.get("timeframe_minutes", 15)),
        )


class RuleEngine:
    def __init__(self, rules: Iterable[Rule]):
        self.rules = list(rules)

    @classmethod
    def from_directory(cls, directory: str | Path) -> "RuleEngine":
        rules: list[Rule] = []
        seen: set[str] = set()
        root = Path(directory)
        paths = [root] if root.is_file() else sorted({*root.rglob("*.yml"), *root.rglob("*.yaml")})
        if not paths:
            raise RuleError(f"No YAML rules found in {root}")
        for path in paths:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
            values = document if isinstance(document, list) else [document]
            for value in values:
                if not isinstance(value, dict):
                    raise RuleError(f"{path}: expected a YAML mapping")
                rule = Rule.from_dict(value, path)
                if rule.id in seen:
                    raise RuleError(f"{path}: duplicate rule id {rule.id}")
                seen.add(rule.id)
                rules.append(rule)
        return cls(rules)

    @staticmethod
    def matches(event: Event, specification: dict[str, Any]) -> bool:
        source = specification.get("source")
        if source and event.source != str(source).lower():
            return False
        conditions = specification.get("conditions", specification)
        conditions = {key: value for key, value in conditions.items() if key != "source"}
        return all(_condition_matches(event.get(field), expected) for field, expected in conditions.items())


def _condition_matches(actual: Any, expected: Any) -> bool:
    if not isinstance(expected, dict):
        return _normalized(actual) == _normalized(expected)
    for operator, operand in expected.items():
        actual_text = str(actual or "").lower()
        if operator == "equals" and _normalized(actual) != _normalized(operand):
            return False
        if operator == "not_equals" and _normalized(actual) == _normalized(operand):
            return False
        if operator == "contains" and str(operand).lower() not in actual_text:
            return False
        if operator == "contains_any" and not any(str(item).lower() in actual_text for item in operand):
            return False
        if operator == "in" and _normalized(actual) not in {_normalized(item) for item in operand}:
            return False
        if operator == "regex" and re.search(str(operand), str(actual or ""), re.IGNORECASE) is None:
            return False
        if operator in {"gt", "gte", "lt", "lte"}:
            comparisons = {"gt": actual > operand, "gte": actual >= operand, "lt": actual < operand, "lte": actual <= operand}
            if not comparisons[operator]:
                return False
    return True


def _normalized(value: Any) -> Any:
    return value.lower() if isinstance(value, str) else value
