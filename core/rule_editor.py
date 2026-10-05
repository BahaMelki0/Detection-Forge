"""Versioned edits preserving multi-rule packs and validating before publication."""
from pathlib import Path
from threading import RLock
from uuid import uuid4
import yaml

from core.rule_engine import Rule, RuleEngine, RuleError

LOCK = RLock()


def locate_rule(directory, rule_id):
    for path in sorted([*Path(directory).rglob('*.yml'), *Path(directory).rglob('*.yaml')]):
        document = yaml.safe_load(path.read_text(encoding='utf-8'))
        values = document if isinstance(document, list) else [document]
        for index, value in enumerate(values):
            if isinstance(value, dict) and value.get('id') == rule_id:
                return path, document, index, value
    raise LookupError('Rule not found')


def edit_rule(directory, history, rule_id, text):
    with LOCK:
        path, pack, index, current = locate_rule(directory, rule_id)
        candidate = yaml.safe_load(text)
        if not isinstance(candidate, dict) or candidate.get('id') != rule_id:
            raise RuleError('Editing must preserve the rule ID and contain one YAML mapping.')
        expected_version = current.get('version', 1)
        if candidate.get('version', 1) != expected_version:
            raise RuleError('Rule changed since this editor loaded; reload before saving.')
        candidate['version'] = expected_version + 1
        updated = Rule.from_dict(candidate, path)
        existing = RuleEngine.from_directory(directory).rules
        # Validate the candidate's regex and operators before touching the registry.
        for spec in [updated.match or {}, *updated.sequence, *updated.exclusions]:
            for condition in spec.get('conditions', spec).values():
                if isinstance(condition, dict):
                    import re
                    if set(condition) - {'equals','not_equals','contains','contains_any','in','regex','gt','gte','lt','lte'}:
                        raise RuleError('Unsupported condition operator')
                    if 'regex' in condition:
                        try: re.compile(condition['regex'])
                        except (TypeError, re.error) as exc: raise RuleError('Invalid regex') from exc
        if isinstance(pack, list):
            pack[index] = candidate
        else:
            pack = candidate
        original = path.read_bytes()
        history = Path(history)
        history.mkdir(parents=True, exist_ok=True)
        safe_id = __import__('hashlib').sha256(rule_id.encode()).hexdigest()[:16]
        snapshot = history / f'{safe_id}-v{expected_version}-{uuid4().hex[:8]}.yml'
        snapshot.write_text(yaml.safe_dump(current, sort_keys=False, allow_unicode=True), encoding='utf-8')
        temporary = path.with_suffix('.pending')
        try:
            temporary.write_text(yaml.safe_dump(pack, sort_keys=False, allow_unicode=True), encoding='utf-8')
            temporary.replace(path)
            RuleEngine.from_directory(directory)
        except Exception:
            path.write_bytes(original)
            temporary.unlink(missing_ok=True)
            snapshot.unlink(missing_ok=True)
            raise
        return candidate
