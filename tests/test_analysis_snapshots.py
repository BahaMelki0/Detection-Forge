import json

import pytest

from core.copilot import LocalCopilotError, validate_analysis
from core.analysis_tasks import evidence_revision
from core.investigations import Investigation
from core.event import Event


def test_unknown_citation_is_rejected():
    evidence = {'events': [{'event_id': 'evt-1'}], 'detections': [], 'coverage': {}}
    result = {'assessment': 'Review', 'evidence': [{'claim': 'Observed', 'references': ['invented']}], 'unknowns': [], 'next_checks': []}
    with pytest.raises(LocalCopilotError):
        validate_analysis(json.dumps(result), evidence)
    result['evidence'][0]['references'] = ['evt-1']
    assert validate_analysis(json.dumps(result), evidence)['evidence'][0]['references'] == ['evt-1']
    evidence['events'][0]['reference'] = 'E1'
    result['evidence'][0]['references'] = ['E1']
    assert validate_analysis(json.dumps(result), evidence)['evidence'][0]['references'] == ['evt-1']


def test_revision_changes_when_evidence_changes_but_not_case_name():
    case = Investigation.create('Test')
    before = evidence_revision(case)
    case.name = 'Renamed'
    assert evidence_revision(case) == before
    case.events.append(Event(timestamp='2026-10-05T10:00:00Z', source='entra', event_type='audit', action='test'))
    assert evidence_revision(case) != before
