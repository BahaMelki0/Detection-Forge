"""Validated rule installation shared by the CLI and web form."""

from __future__ import annotations

from pathlib import Path
import re
import shutil
from typing import Any, Callable

import yaml

from core.rule_engine import Rule, RuleEngine, RuleError


def install_rule(source_file: Path, rules_path: Path, category: str = "auto") -> Path:
    candidate_rules = RuleEngine.from_directory(source_file).rules
    if len(candidate_rules) != 1:
        raise RuleError("rules add accepts exactly one rule per YAML file")
    return _install(
        candidate_rules[0], rules_path, category,
        lambda destination: shutil.copy2(source_file, destination),
    )


def install_rule_document(document: dict[str, Any], rules_path: Path, category: str = "auto") -> Path:
    rule = Rule.from_dict(document, Path("<rule form>"))

    def write(destination: Path) -> None:
        destination.write_text(
            yaml.safe_dump(document, sort_keys=False, allow_unicode=True, width=100),
            encoding="utf-8",
        )

    return _install(rule, rules_path, category, write)


def _install(rule: Rule, rules_path: Path, category: str, writer: Callable[[Path], object]) -> Path:
    existing = _existing_rules(rules_path)
    if any(candidate.id == rule.id for candidate in existing):
        raise RuleError(f"Rule id {rule.id} is already installed")
    selected_category = _rule_category(rule) if category == "auto" else category
    destination_dir = rules_path / selected_category
    destination_dir.mkdir(parents=True, exist_ok=True)
    safe_id = re.sub(r"[^a-z0-9._-]+", "_", rule.id.lower()).strip("._-")
    destination = destination_dir / f"{safe_id}.yml"
    if destination.exists():
        raise RuleError(f"Destination already exists: {destination}")
    writer(destination)
    try:
        RuleEngine.from_directory(rules_path)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return destination


def _existing_rules(rules_path: Path) -> list[Rule]:
    has_rules = rules_path.exists() and any(
        path.is_file() and path.suffix.lower() in {".yml", ".yaml"}
        for path in rules_path.rglob("*")
    )
    return RuleEngine.from_directory(rules_path).rules if has_rules else []


def _rule_category(rule: Rule) -> str:
    if rule.type == "correlation":
        return "cross_source"
    return "entra" if rule.sources == ("entra",) else "windows"
