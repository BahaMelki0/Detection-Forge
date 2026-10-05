"""Case snapshot analysis; one background worker, independent durable task files."""
import hashlib
import json
import os
from pathlib import Path
from threading import Lock, Thread
from uuid import uuid4

from core.copilot import summarize_case
from core.incidents import summarize_investigation
from core.investigations import InvestigationStore
from core.workspace import utc_now


def evidence_revision(investigation):
    material = [[event.id for event in investigation.events], [alert.to_dict() for alert in investigation.alerts], investigation.alert_reviews]
    return hashlib.sha256(json.dumps(material, sort_keys=True, default=str).encode()).hexdigest()


class AnalysisTasks:
    def __init__(self, cases_path):
        self.store = InvestigationStore(cases_path)
        self.directory = Path(cases_path) / 'analysis_tasks'
        self.directory.mkdir(parents=True, exist_ok=True)
        self.lock = Lock()
        self.worker_lock = Lock()
        for task in self.list():
            if task['status'] in ('queued', 'running'):
                task.update(status='failed', error='App restarted; retry analysis.', finished_at=utc_now())
                self._write(task)

    def _write(self, task):
        path = self.directory / (task['id'] + '.json')
        temporary = path.with_suffix('.tmp')
        temporary.write_text(json.dumps(task, ensure_ascii=False, indent=2), encoding='utf-8')
        temporary.replace(path)

    def list(self, case_id=None):
        tasks = [json.loads(path.read_text(encoding='utf-8')) for path in self.directory.glob('*.json')]
        return sorted([task for task in tasks if case_id is None or task['case_id'] == case_id], key=lambda task: task['created_at'], reverse=True)

    def submit(self, case_id):
        investigation = self.store.get(case_id)
        if investigation is None:
            raise LookupError('Case not found')
        if not investigation.events and not investigation.alerts:
            raise ValueError('Add evidence before requesting analysis.')
        with self.lock:
            active = [task for task in self.list() if task['status'] in ('queued', 'running')]
            if any(task['case_id'] == case_id for task in active):
                raise ValueError('This case already has an active analysis.')
            if len(active) >= 4:
                raise ValueError('Analysis queue is full.')
            task = {'id': uuid4().hex, 'case_id': case_id, 'status': 'queued', 'created_at': utc_now(),
                    'revision': evidence_revision(investigation), 'model': os.environ.get('DETECTION_FORGE_OLLAMA_MODEL', 'qwen3.5:9b'),
                    'prompt_version': 'cited-case-v1', 'result': None, 'error': None}
            self._write(task)
        Thread(target=self._run, args=(task['id'], investigation), daemon=True).start()
        return task

    def cancel(self, case_id, task_id):
        with self.lock:
            task = next((item for item in self.list(case_id) if item['id'] == task_id), None)
            if task is None:
                raise LookupError('Analysis not found')
            if task['status'] in ('queued', 'running'):
                task.update(status='cancelled', finished_at=utc_now())
                self._write(task)

    def purge(self, case_id):
        with self.lock:
            for path in self.directory.glob('*.json'):
                task = json.loads(path.read_text(encoding='utf-8'))
                if task['case_id'] == case_id:
                    path.unlink()

    def _run(self, task_id, investigation):
        with self.worker_lock:
            with self.lock:
                task = next((item for item in self.list() if item['id'] == task_id), None)
                if task is None or task['status'] == 'cancelled':
                    return
                task.update(status='running', started_at=utc_now())
                self._write(task)
            try:
                result = summarize_case(summarize_investigation(investigation), structured=True)
                status, error = 'succeeded', None
            except Exception as exc:
                result, status, error = None, 'failed', str(exc)[:500]
            with self.lock:
                current = next((item for item in self.list() if item['id'] == task_id), None)
                if current is None or current['status'] == 'cancelled':
                    return
                current_case = self.store.get(investigation.id)
                if current_case is None:
                    result, status, error = None, 'cancelled', 'Case deleted.'
                current.update(status=status, result=result, error=error, finished_at=utc_now())
                self._write(current)
