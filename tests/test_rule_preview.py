from pathlib import Path

import pytest

from core.detector import Detector
from core.event import Event
from core.investigations import InvestigationStore
from core.rule_engine import Rule, RuleEngine, RuleError
from web.app import create_app


def document():
    return {'id': 'PREVIEW-001', 'title': 'Preview', 'type': 'event', 'severity': 'medium',
            'sources': ['entra'], 'attack': {}, 'remediation': 'Review', 'match': {'action': 'test'},
            'exclusions': [{'conditions': {'user': 'approved@example.test'}}]}


def event(user):
    return Event(timestamp='2026-10-05T10:00:00Z', source='entra', event_type='test', action='test', user=user)


def test_exclusion_only_suppresses_matching_actor():
    rule = Rule.from_dict(document(), Path('fixture'))
    alerts = Detector(RuleEngine([rule])).run([event('approved@example.test'), event('other@example.test')])
    assert len(alerts) == 1
    assert alerts[0].events[0]['user'] == 'other@example.test'


@pytest.mark.parametrize('exclusions', [[], [{'conditions': {'user': {'typo_operator': 'anything'}}}], [{'conditions': {}}]])
def test_exclusion_validation(exclusions):
    value = {**document(), 'exclusions': exclusions}
    if not exclusions:
        assert Rule.from_dict(value, Path('fixture')).exclusions == ()
    else:
        with pytest.raises(RuleError):
            Rule.from_dict(value, Path('fixture'))


def test_preview_preserves_case_and_does_not_install_rule(tmp_path):
    cases = tmp_path / 'cases'
    rules = tmp_path / 'rules'
    store = InvestigationStore(cases)
    case = store.create('Preview case')
    case.events = [event('approved@example.test'), event('other@example.test')]
    store.save(case)
    before = (cases / f'{case.id}.json').read_bytes()
    app = create_app({'TESTING': True, 'CASES_PATH': cases, 'RULES_PATH': rules})
    response = app.test_client().post('/rules/new', data={
        'intent': 'preview', 'preview_case': case.id, 'rule_id': 'PREVIEW-001',
        'title': 'Preview', 'description': 'Fixture', 'rule_type': 'event', 'severity': 'medium',
        'attack_id': 'T1078', 'attack_name': 'Valid Accounts', 'attack_tactic': 'Initial Access',
        'attack_url': 'https://attack.mitre.org/techniques/T1078/', 'remediation': 'Review',
        'sources': 'entra', 'condition_field': 'action', 'condition_operator': 'equals',
        'condition_value': 'test', 'exclusions': '[{"conditions":{"user":"approved@example.test"}}]',
    })
    assert response.status_code == 200
    assert b'2 events, 1 alerts, 1 alerts suppressed' in response.data
    assert not rules.exists()
    assert (cases / f'{case.id}.json').read_bytes() == before
