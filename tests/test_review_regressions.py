from types import SimpleNamespace

from core.copilot import _case_evidence
from core.detector import Detector
from core.event import Event
from core.rule_engine import Rule, RuleEngine


def test_missing_identity_cannot_join_unrelated_events():
    rule = Rule(id='identity', title='Identity', description='', type='correlation',
                severity='high', sources=(), attack={}, remediation='Review',
                sequence=({'action': 'first'}, {'action': 'last'}))
    events = [Event(timestamp='2026-01-01T10:00:00Z', source='entra', event_type='test', action='first', user='alice'),
              Event(timestamp='2026-01-01T10:01:00Z', source='windows', event_type='test', action='last')]
    assert Detector(RuleEngine([rule])).run(events) == []


def test_missing_or_incompatible_numeric_field_is_not_a_match():
    for value in (None, 'unknown'):
        event = Event(timestamp='2026-01-01T10:00:00Z', source='entra', event_type='test', action='test', details={'count': value})
        assert not RuleEngine.matches(event, {'details.count': {'gte': 3}})


def test_ai_includes_late_attack_instead_of_only_earliest_events():
    events = [{'id': f'evt-{i}', 'timestamp': f'2026-01-01T10:{i:02}:00Z', 'details': {}} for i in range(30)]
    alert = SimpleNamespace(id='alert-late', rule_id='late', rule_title='Late attack', severity='critical',
                            timestamp=events[-1]['timestamp'], events=[events[-1]], description='Evidence', remediation='Review')
    case = SimpleNamespace(all_events=events, alerts=[alert], priority=90, priority_reasons=[], severity='critical', sources=[], users=[], hosts=[])
    result = _case_evidence(case)
    assert 'evt-29' in [event['event_id'] for event in result['events']]
    assert len(result['events']) == 20
    assert result['coverage']['total_events'] == 30
    assert result['detections'][0]['alert_id'] == 'alert-late'
