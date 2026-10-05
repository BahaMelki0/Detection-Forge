from threading import Event as Signal

from core.analysis_tasks import AnalysisTasks
from core.event import Event
from core.investigations import InvestigationStore


def test_cancelled_inference_cannot_publish_or_overwrite_case(tmp_path, monkeypatch):
    store = InvestigationStore(tmp_path)
    case = store.create('Snapshot')
    case.events = [Event(timestamp='2026-10-05T10:00:00Z', source='entra', event_type='audit', action='test')]
    store.save(case)
    started, release, finished = Signal(), Signal(), Signal()
    def fake_model(*args, **kwargs):
        started.set()
        release.wait(3)
        finished.set()
        return {'assessment': 'Should never publish', 'evidence': [], 'unknowns': [], 'next_checks': []}
    monkeypatch.setattr('core.analysis_tasks.summarize_case', fake_model)
    tasks = AnalysisTasks(tmp_path)
    task = tasks.submit(case.id)
    assert started.wait(2)
    tasks.cancel(case.id, task['id'])
    release.set()
    assert finished.wait(2)
    assert tasks.list(case.id)[0]['status'] == 'cancelled'
    assert tasks.list(case.id)[0]['result'] is None
    assert store.get(case.id).ai_analysis == ''


def test_restart_recovers_abandoned_task(tmp_path):
    tasks = AnalysisTasks(tmp_path)
    tasks._write({'id': 'interrupted', 'case_id': 'demo', 'status': 'running', 'created_at': '2026-10-05'})
    restarted = AnalysisTasks(tmp_path)
    assert restarted.list()[0]['status'] == 'failed'


def test_case_purge_removes_only_its_analysis_artifacts(tmp_path):
    tasks = AnalysisTasks(tmp_path)
    tasks._write({'id': 'one', 'case_id': 'first', 'status': 'succeeded', 'created_at': '2026-10-05'})
    tasks._write({'id': 'two', 'case_id': 'second', 'status': 'succeeded', 'created_at': '2026-10-05'})
    tasks.purge('first')
    assert [task['case_id'] for task in tasks.list()] == ['second']
