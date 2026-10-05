from pathlib import Path

import pytest

from connectors.entra_connector import EntraConnector
from core.detector import Detector
from core.rule_engine import RuleEngine

PACK = Path(__file__).resolve().parents[1] / 'rules/entra/audit_identity.yml'


def audit(action, result='success', **extra):
    return EntraConnector('audit').normalize({
        'activityDateTime': '2026-10-05T10:00:00Z', 'activityDisplayName': action,
        'result': result, 'initiatedBy': {'user': {'id': 'actor-1', 'userPrincipalName': 'admin@example.test'}},
        'targetResources': [{'id': 'target-1', 'displayName': 'Test application', 'type': 'ServicePrincipal'}],
        **extra,
    })


@pytest.mark.parametrize('action,expected', [
    ('Add service principal credentials', 'DF-ENTRA-002'),
    ('Add application password', 'DF-ENTRA-002'),
    ('Update application - Certificates and secrets management', 'DF-ENTRA-002'),
    ('Consent to application', 'DF-ENTRA-003'),
    ('Add delegated permission grant', 'DF-ENTRA-003'),
    ('Add app role assignment to the service principal', 'DF-ENTRA-003'),
    ('Add member to role', 'DF-ENTRA-004'),
    ('Add eligible member to role', 'DF-ENTRA-004'),
    ('Add scoped member to role', 'DF-ENTRA-004'),
])
def test_audit_operation_routes_to_expected_review_rule(action, expected):
    detector = Detector(RuleEngine.from_directory(PACK))
    alerts = detector.run([audit(action)])
    assert [alert.rule_id for alert in alerts] == [expected]
    assert detector.run([audit(action, result='failure')]) == []
    assert detector.run([audit('Update user')]) == []


def test_application_actor_is_not_invented_as_a_human():
    event = audit('Consent to application', initiatedBy={'user': None, 'app': {
        'servicePrincipalId': 'sp-actor', 'appId': 'app-actor', 'displayName': 'Automation'}})
    assert event.user is None
    assert event.details['actor_type'] == 'application'
    assert event.details['actor_id'] == 'sp-actor'
    assert event.details['target_ids'] == ['target-1']


def test_absent_audit_actor_and_targets_remain_unknown():
    event = audit('Add member to role', initiatedBy=None, targetResources=None)
    assert event.details['actor_type'] == 'unknown'
    assert event.details['target_ids'] == []


def test_workload_sequence_requires_same_explicit_target_id():
    credential = audit('Add service principal credentials')
    signin = EntraConnector().normalize({'createdDateTime': '2026-10-05T10:05:00Z', 'servicePrincipalId': 'target-1', 'status': {'errorCode': 0}})
    pack = PACK.parent / 'workload_sequence.yml'
    detector = Detector(RuleEngine.from_directory(pack))
    assert len(detector.run([credential, signin])) == 1
    unrelated = EntraConnector().normalize({'createdDateTime': '2026-10-05T10:05:00Z', 'servicePrincipalId': 'other', 'status': {'errorCode': 0}})
    assert detector.run([credential, unrelated]) == []
    unknown = EntraConnector().normalize({'createdDateTime': '2026-10-05T10:05:00Z', 'servicePrincipalId': 'target-1'})
    assert unknown.outcome == 'unknown'
    assert detector.run([credential, unknown]) == []
