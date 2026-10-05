import yaml
import pytest
from core.rule_editor import edit_rule
from core.rule_engine import RuleEngine, RuleError


def test_edit_preserves_pack_and_rejects_stale_revision(tmp_path):
    rules = tmp_path / 'rules'; rules.mkdir()
    candidate = {'id': 'one', 'title': 'Test', 'type': 'event', 'severity': 'medium', 'attack': {}, 'remediation': 'Review', 'match': {'action': 'test'}}
    other = {**candidate, 'id': 'two'}
    (rules / 'pack.yml').write_text(yaml.safe_dump([candidate, other]))
    revised = edit_rule(rules, tmp_path / 'history', 'one', yaml.safe_dump({**candidate, 'title': 'Updated'}))
    assert revised['version'] == 2
    assert len(RuleEngine.from_directory(rules).rules) == 2
    assert len(list((tmp_path / 'history').glob('*.yml'))) == 1
    with pytest.raises(RuleError): edit_rule(rules, tmp_path / 'history', 'one', yaml.safe_dump(candidate))
