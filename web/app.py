"""Read-only Flask presentation layer for Detection Forge alerts."""

from __future__ import annotations

from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
import os
from pathlib import Path
import secrets
from tempfile import TemporaryDirectory

from flask import Flask, abort, flash, make_response, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

from core.pipeline import FILE_TYPES, detect_events, infer_profile, input_from_profile, load_inputs
from core.incidents import summarize_investigation
from core.investigations import Investigation, InvestigationStore
from core.rule_builder import (
    CONDITION_FIELDS, CONDITION_OPERATORS, GROUP_FIELDS, SEVERITIES, SOURCES,
    RuleFormError, build_rule_document,
)
from core.rule_engine import Rule, RuleEngine, RuleError
from core.detector import Detector
from core.rule_manager import install_rule_document
from core.workspace import AnalysisWorkspace, IngestedFile
from core.watcher import ALLOWED_INTERVALS, read_new_records, validate_paths

ROOT = Path(__file__).resolve().parents[1]
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(
        ALERTS_PATH=ROOT / "data" / "alerts.json",
        WORKSPACE_PATH=ROOT / "data" / "workspace.json",
        CASES_PATH=ROOT / "data" / "cases",
        RULES_PATH=ROOT / "rules",
        MAX_CONTENT_LENGTH=32 * 1024 * 1024,
        SECRET_KEY=os.environ.get("DETECTION_FORGE_SECRET", secrets.token_hex(32)),
    )
    if config:
        app.config.update(config)
    from core.analysis_tasks import AnalysisTasks, evidence_revision
    analysis_tasks = AnalysisTasks(app.config['CASES_PATH'])

    def analysis_state(investigation):
        tasks = analysis_tasks.list(investigation.id)
        for task in tasks:
            task['stale'] = task['revision'] != evidence_revision(investigation)
        return tasks

    def report_analysis(investigation):
        snapshots = [task for task in analysis_state(investigation) if task['status'] == 'succeeded']
        if snapshots:
            snapshot = snapshots[0]
            result = snapshot['result']
            lines = [result['assessment'], 'Evidence:']
            lines.extend(item['claim'] + ' [' + ', '.join(item['references']) + ']' for item in result['evidence'])
            lines.extend(['Unknowns:', *result['unknowns'], 'Next checks:', *result['next_checks'],
                          f"Model: {snapshot['model']} | Prompt: {snapshot['prompt_version']} | Stale: {snapshot['stale']}",
                          str(result['coverage'])])
            investigation.ai_analysis = '\n'.join(lines)
            investigation.ai_analyzed_at = snapshot['finished_at']
        return investigation

    @app.post('/cases/<case_id>/alerts/<alert_id>/review')
    def review_alert(case_id, alert_id):
        investigation = case_store().get(case_id)
        if investigation is None or not any(alert.id == alert_id for alert in investigation.alerts):
            abort(404)
        disposition = request.form.get('disposition')
        if disposition not in {'new', 'investigating', 'confirmed', 'false_positive', 'accepted_risk'}:
            abort(400)
        investigation.alert_reviews[alert_id] = {'disposition': disposition,
            'notes': request.form.get('notes', '')[:10000], 'updated_at': datetime.now(timezone.utc).isoformat()}
        case_store().save(investigation)
        return redirect(url_for('incident_detail', case_id=case_id) + '#alerts')

    scheduler = None

    def run_scheduled_watch(case_id: str):
        with app.test_request_context():
            store = case_store()
            investigation = store.get(case_id)
            if investigation is None or not investigation.watcher_enabled or investigation.status != "open":
                return
            # Reuse the exact same bounded, checkpointed processing path as the manual scan route.
            with app.test_client() as client:
                client.post(url_for("scan_case_files", case_id=case_id))

    def sync_watch_jobs():
        nonlocal scheduler
        if app.testing and not app.config.get("ENABLE_TEST_SCHEDULER", False):
            return
        try:
            from apscheduler.schedulers.background import BackgroundScheduler
        except ImportError:
            return
        investigations = case_store().list()
        desired = {item.id: item for item in investigations if item.watcher_enabled and item.status == "open" and item.watched_paths}
        if not desired and scheduler is None:
            return
        if scheduler is None:
            scheduler = BackgroundScheduler(daemon=True, timezone="UTC")
            scheduler.start()
        for job in scheduler.get_jobs():
            if job.id.startswith("case-") and job.id[5:] not in desired:
                scheduler.remove_job(job.id)
        for case_id, investigation in desired.items():
            job_id = f"case-{case_id}"
            if scheduler.get_job(job_id) is None:
                scheduler.add_job(run_scheduled_watch, "interval", seconds=investigation.poll_interval_seconds,
                                  args=[case_id], id=job_id, replace_existing=True,
                                  max_instances=1, coalesce=True)

    app.extensions["detection_forge_sync_watch_jobs"] = sync_watch_jobs

    @app.before_request
    def refresh_watch_jobs():
        sync_watch_jobs()

    def case_store():
        return InvestigationStore(
            app.config["CASES_PATH"], app.config["WORKSPACE_PATH"], app.config["ALERTS_PATH"],
        )

    @app.get("/")
    def dashboard():
        investigations = case_store().list()
        open_cases = [item for item in investigations if item.status == "open"]
        alerts = [alert for item in open_cases for alert in item.alerts]
        alerts.sort(key=lambda alert: (SEVERITY_RANK.get(alert.severity, 99), alert.timestamp))
        counts = Counter(alert.severity for alert in alerts)
        cases = [summarize_investigation(item) for item in investigations]
        investigation_by_id = {item.id: item for item in investigations}
        alert_rows = [
            {"alert": alert, "case": investigation_by_id[item.id]}
            for item in open_cases for alert in item.alerts
        ]
        rule_count = len(RuleEngine.from_directory(app.config["RULES_PATH"]).rules)
        return render_template(
            "dashboard.html", alerts=alerts, counts=counts, rule_count=rule_count,
            file_types=FILE_TYPES, cases=cases, investigation_by_id=investigation_by_id,
            alert_rows=alert_rows, open_case_count=len(open_cases),
            workspace_event_count=sum(len(item.events) for item in open_cases),
        )

    @app.post("/cases")
    def create_case():
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        if not name or len(name) > 160 or len(description) > 2000:
            flash("Enter a case name (1-160 characters); description may be up to 2,000 characters.", "error")
            return redirect(url_for("dashboard"))
        investigation = case_store().create(name, description)
        flash(f"Case '{investigation.name}' created. Upload related telemetry into this case.", "success")
        return redirect(url_for("incident_detail", case_id=investigation.id))

    @app.post("/cases/<case_id>/analyze")
    def analyze_upload(case_id: str):
        store = case_store()
        investigation = store.get(case_id)
        if investigation is None:
            abort(404)
        if investigation.status != "open":
            abort(409, "Reopen this case before adding telemetry.")
        uploads = request.files.getlist("files")
        profiles = request.form.getlist("types")
        submitted = [(upload, profile) for upload, profile in zip(uploads, profiles) if upload.filename]
        if not submitted:
            flash("Choose at least one JSON or JSONL telemetry file.", "error")
            return redirect(url_for("incident_detail", case_id=case_id))

        try:
            with TemporaryDirectory(prefix=f"detection-forge-{case_id[:8]}-") as temporary:
                inputs = []
                pending_files = []
                for index, (upload, profile) in enumerate(submitted):
                    filename = secure_filename(upload.filename)
                    if not filename or Path(filename).suffix.lower() not in {".json", ".jsonl", ".ndjson"}:
                        raise ValueError(f"{upload.filename}: expected a .json, .jsonl, or .ndjson file")
                    destination = Path(temporary) / f"{index}_{filename}"
                    upload.save(destination)
                    if profile == "auto":
                        detected = infer_profile(destination)
                        if not detected["profile"] or detected["confidence"] < 0.6:
                            raise ValueError(f"Could not confidently identify {filename}: {detected['reason']} Select its type manually.")
                        profile = detected["profile"]
                    if profile not in FILE_TYPES:
                        raise ValueError(f"Unsupported file type: {profile}")
                    file_record = IngestedFile.create(
                        filename=filename, profile=profile, source=FILE_TYPES[profile][0], event_count=0,
                    )
                    inputs.append(input_from_profile(
                        profile, destination, display_name=filename, origin_file_id=file_record.id,
                    ))
                    pending_files.append(file_record)
                new_events, input_counts = load_inputs(inputs)
                completed_files = [
                    IngestedFile(
                        filename=record.filename, profile=record.profile, source=record.source,
                        event_count=count, uploaded_at=record.uploaded_at, id=record.id,
                    )
                    for record, count in zip(pending_files, input_counts)
                ]
                combined_events, duplicate_count = AnalysisWorkspace.merge_events(investigation.events, new_events)
                alerts = detect_events(combined_events, Path(app.config["RULES_PATH"]))
                investigation.files.extend(completed_files)
                investigation.events = combined_events
                investigation.alerts = alerts
                investigation.ai_analysis = ""
                investigation.ai_analyzed_at = None
                investigation.updated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                store.save(investigation)
        except (OSError, ValueError) as exc:
            flash(f"Analysis failed: {exc}", "error")
            return redirect(url_for("incident_detail", case_id=case_id))

        flash(
            f"Added {len(new_events) - duplicate_count} unique events to case '{investigation.name}' from {len(completed_files)} file(s). "
                f"Case analysis generated {len(alerts)} alerts.",
            "success",
        )
        if duplicate_count:
            flash(
                f"Merged {duplicate_count} duplicate event record(s) in this case; their input-file provenance was retained.",
                "success",
            )
        return redirect(url_for("incident_detail", case_id=investigation.id))

    @app.post("/cases/<case_id>/status")
    def set_case_status(case_id: str):
        store = case_store()
        investigation = store.get(case_id)
        if investigation is None:
            abort(404)
        status = request.form.get("status")
        if status not in {"open", "closed", "resolved"}:
            abort(400)
        investigation.status = status
        investigation.resolved_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z") if status == "resolved" else None
        investigation.resolution_notes = request.form.get("resolution_notes", "")[:4000] if status == "resolved" else ""
        investigation.updated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        store.save(investigation)
        flash(f"Case '{investigation.name}' marked {status}.", "success")
        return redirect(url_for("incident_detail", case_id=case_id))

    @app.post("/cases/<case_id>/delete")
    def delete_case(case_id: str):
        store = case_store()
        investigation = store.get(case_id)
        if investigation is None:
            abort(404)
        if request.form.get("confirm_name", "").strip() != investigation.name:
            flash("Type the exact case name to confirm deletion.", "error")
            return redirect(url_for("incident_detail", case_id=case_id))
        store.delete(case_id)
        analysis_tasks.purge(case_id)
        flash("Case deleted. Original watched log files were left untouched.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/cases/<case_id>/watch")
    def configure_watch(case_id: str):
        store = case_store()
        investigation = store.get(case_id)
        if investigation is None:
            abort(404)
        try:
            watched_paths = validate_paths(request.form.get("paths", ""))
            interval = int(request.form.get("interval", "120"))
            if interval not in ALLOWED_INTERVALS:
                raise ValueError("Choose an interval of 1, 2, 5, or 10 minutes.")
        except (ValueError, OSError) as exc:
            flash(f"File watch setup failed: {exc}", "error")
            return redirect(url_for("incident_detail", case_id=case_id))
        investigation.watched_paths = watched_paths
        investigation.poll_interval_seconds = interval
        investigation.watcher_enabled = request.form.get("enabled") == "on" and investigation.status == "open"
        investigation.file_checkpoints = {key: value for key, value in investigation.file_checkpoints.items() if key in watched_paths}
        investigation.updated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        store.save(investigation)
        sync_watch_jobs()
        flash("File watch updated. It runs while this app is active; source log files are read-only.", "success")
        return redirect(url_for("incident_detail", case_id=case_id))

    @app.post("/cases/<case_id>/scan")
    def scan_case_files(case_id: str):
        store = case_store()
        investigation = store.get(case_id)
        if investigation is None:
            abort(404)
        if investigation.status != "open":
            abort(409, "Reopen this case to scan its files.")
        outcomes = []
        errors = []
        changed = False
        with TemporaryDirectory(prefix=f"df-watch-{case_id[:8]}-") as temporary:
            specs, pending = [], []
            for index, path_value in enumerate(investigation.watched_paths):
                path = Path(path_value)
                key = str(path.resolve())
                try:
                    raw, checkpoint, _count = read_new_records(path, investigation.file_checkpoints.get(key, {}))
                    if not raw:
                        continue
                    temp = Path(temporary) / f"{index}_{secure_filename(path.name)}"
                    temp.write_bytes(raw)
                    detected = infer_profile(temp)
                    if not detected["profile"] or detected["confidence"] < 0.6:
                        message = f"{path.name}: type ambiguous; checkpoint unchanged"
                        outcomes.append(message)
                        errors.append(message)
                        continue
                    record = IngestedFile.create(path.name, detected["profile"], FILE_TYPES[detected["profile"]][0], 0)
                    specs.append(input_from_profile(detected["profile"], temp, display_name=path.name, origin_file_id=record.id))
                    pending.append((key, checkpoint, record))
                except (OSError, ValueError) as exc:
                    message = f"{path.name}: {exc}"
                    outcomes.append(message)
                    errors.append(message)
            if specs:
                events, input_counts = load_inputs(specs)
                completed = []
                for (key, checkpoint, file_record), parsed_count in zip(pending, input_counts):
                    investigation.file_checkpoints[key] = checkpoint
                    completed.append(IngestedFile(filename=file_record.filename, profile=file_record.profile, source=file_record.source,
                                                  event_count=parsed_count, uploaded_at=file_record.uploaded_at, id=file_record.id))
                investigation.events, duplicates = AnalysisWorkspace.merge_events(investigation.events, events)
                investigation.files.extend(completed)
                investigation.alerts = detect_events(investigation.events, Path(app.config["RULES_PATH"]))
                investigation.ai_analysis = ""
                investigation.ai_analyzed_at = None
                investigation.updated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                store.save(investigation)
                changed = True
                outcomes.insert(0, f"Processed {len(events) - duplicates} new events from {len(completed)} watched file(s); {len(investigation.alerts)} alerts in this case.")
        if not changed and not outcomes:
            outcomes.append("No complete new JSONL records found.")
        investigation.watch_last_scan = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        investigation.watch_last_error = "\n".join(errors)[:2000]
        store.save(investigation)
        flash(" ".join(outcomes), "error" if errors and not changed else "success")
        return redirect(url_for("incident_detail", case_id=case_id))

    @app.post("/cases/<case_id>/detect")
    def rerun_case_detections(case_id: str):
        store = case_store()
        investigation = store.get(case_id)
        if investigation is None:
            abort(404)
        if investigation.status != "open":
            abort(409, "Reopen this case before rerunning detections.")
        investigation.alerts = detect_events(investigation.events, Path(app.config["RULES_PATH"]))
        investigation.ai_analysis = ""
        investigation.ai_analyzed_at = None
        investigation.updated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        store.save(investigation)
        flash(f"Current enabled detection rules evaluated against {len(investigation.events)} events in this case.", "success")
        return redirect(url_for("incident_detail", case_id=case_id) + "#alerts")

    @app.post("/cases/<case_id>/clear")
    def clear_case(case_id: str):
        store = case_store()
        investigation = store.get(case_id)
        if investigation is None:
            abort(404)
        investigation.files.clear()
        investigation.events.clear()
        investigation.alerts.clear()
        investigation.alert_reviews.clear()
        analysis_tasks.purge(case_id)
        investigation.ai_analysis = ""
        investigation.ai_analyzed_at = None
        investigation.updated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        store.save(investigation)
        flash(f"Telemetry and alerts cleared from case '{investigation.name}'. The case itself remains.", "success")
        return redirect(url_for("incident_detail", case_id=case_id))

    @app.get("/report")
    def export_report():
        investigations = [item for item in case_store().list() if item.status == "open"]
        alerts = [alert for item in investigations for alert in item.alerts]
        files = [file for item in investigations for file in item.files]
        event_count = sum(len(item.events) for item in investigations)
        response = make_response(render_template(
            "report.html", alerts=alerts, files=files,
            event_count=event_count, generated_at=max((item.updated_at for item in investigations), default=""),
        ))
        response.headers["Content-Disposition"] = "attachment; filename=detection-forge-report.html"
        response.headers["Content-Type"] = "text/html; charset=utf-8"
        return response

    @app.errorhandler(413)
    def upload_too_large(_error):
        flash("Upload rejected: the combined file size exceeds 32 MB.", "error")
        return redirect(url_for("dashboard"))

    @app.get("/alerts/<alert_id>")
    def alert_detail(alert_id: str):
        for investigation in case_store().list():
            if any(item.id == alert_id for item in investigation.alerts):
                return redirect(url_for("case_alert_detail", case_id=investigation.id, alert_id=alert_id))
        abort(404)

    @app.get("/cases/<case_id>/alerts/<alert_id>")
    def case_alert_detail(case_id: str, alert_id: str):
        investigation = case_store().get(case_id)
        if investigation is None:
            abort(404)
        alert = next((item for item in investigation.alerts if item.id == alert_id), None)
        if alert is None:
            abort(404)
        return render_template("alert_detail.html", alert=alert, investigation=investigation)

    @app.get("/cases/<case_id>")
    def incident_detail(case_id: str):
        investigation = case_store().get(case_id)
        if investigation is None:
            abort(404)
        case = summarize_investigation(investigation)
        query = request.args.get('q', '').casefold().strip()
        timeline = [event for event in investigation.events if not query or query in str(event.to_dict()).casefold()]
        timeline.sort(key=lambda event: event.timestamp, reverse=True)
        return render_template("case_detail.html", case=case, investigation=investigation, file_types=FILE_TYPES,
                               analysis_tasks=analysis_state(investigation), timeline=timeline[:200],
                               timeline_total=len(timeline), query=request.args.get('q', ''))

    @app.post('/cases/<case_id>/analysis-tasks/<task_id>/cancel')
    def cancel_case_analysis(case_id, task_id):
        try:
            analysis_tasks.cancel(case_id, task_id)
        except LookupError:
            abort(404)
        return redirect(url_for('incident_detail', case_id=case_id) + '#analysis')

    @app.post("/cases/<case_id>/triage")
    def incident_triage(case_id: str):
        investigation = case_store().get(case_id)
        if investigation is None:
            abort(404)
        case = summarize_investigation(investigation)
        from core.copilot import LocalCopilotError, summarize_case
        try:
            summary = summarize_case(case)
            investigation.ai_analysis = summary
            investigation.ai_analyzed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            case_store().save(investigation)
        except LocalCopilotError as exc:
            flash(str(exc), "error")
            summary = None
        return render_template("case_detail.html", case=case, investigation=investigation,
                               file_types=FILE_TYPES, summary=summary)

    @app.post("/cases/<case_id>/ai-analysis")
    def case_ai_analysis(case_id: str):
        store = case_store()
        investigation = store.get(case_id)
        if investigation is None:
            abort(404)
        try:
            analysis_tasks.submit(case_id)
            flash('Analysis queued. Refresh this case to see progress. Cancellation discards results; an active model call may finish in the background.', 'success')
        except (LookupError, ValueError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("incident_detail", case_id=case_id) + "#analysis")

    @app.get("/cases/<case_id>/report")
    def export_case_report(case_id: str):
        investigation = case_store().get(case_id)
        if investigation is None:
            abort(404)
        report_analysis(investigation)
        response = make_response(render_template(
            "report.html", alerts=investigation.alerts, files=investigation.files,
            event_count=len(investigation.events), generated_at=investigation.updated_at,
            investigation=investigation, ai_analysis=investigation.ai_analysis,
        ))
        response.headers["Content-Disposition"] = f'attachment; filename="detection-forge-{case_id[:8]}.html"'
        response.headers["Content-Type"] = "text/html; charset=utf-8"
        return response

    @app.get("/cases/<case_id>/report.pdf")
    def export_case_pdf(case_id: str):
        investigation = case_store().get(case_id)
        if investigation is None:
            abort(404)
        report_analysis(investigation)
        from core.pdf_report import render_case_pdf
        pdf = render_case_pdf(investigation)
        response = make_response(pdf)
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = f'attachment; filename="detection-forge-{case_id[:8]}.pdf"'
        return response

    @app.get("/rules")
    def rules():
        loaded = RuleEngine.from_directory(app.config["RULES_PATH"]).rules
        loaded.sort(key=lambda rule: (SEVERITY_RANK.get(rule.severity, 99), rule.id))
        selected_source = request.args.get("source", "all").lower()
        if selected_source not in {"all", "entra", "windows", "sysmon"}:
            selected_source = "all"
        source_counts = {
            source: sum(source in rule.sources for rule in loaded)
            for source in ("entra", "windows", "sysmon")
        }
        filtered = loaded if selected_source == "all" else [
            rule for rule in loaded if selected_source in rule.sources
        ]
        return render_template(
            "rules.html", rules=filtered, total_rules=len(loaded),
            selected_source=selected_source, source_counts=source_counts,
        )

    @app.route('/rules/<rule_id>/edit', methods=['GET', 'POST'])
    def edit_detection_rule(rule_id):
        import yaml
        import hashlib
        from core.rule_editor import locate_rule, edit_rule
        directory = app.config['RULES_PATH']
        history = Path(app.config['CASES_PATH']).parent / 'rule_history'
        try:
            _, _, _, document = locate_rule(directory, rule_id)
        except LookupError:
            abort(404)
        error = None
        text = yaml.safe_dump(document, sort_keys=False, allow_unicode=True)
        if request.method == 'POST':
            text = request.form.get('yaml', '')
            try:
                edit_rule(directory, history, rule_id, text)
                flash('Rule updated; previous revision retained. Rerun rules in relevant cases to apply the change.', 'success')
                return redirect(url_for('rules'))
            except (ValueError, OSError, yaml.YAMLError) as exc:
                error = str(exc)
        prefix = hashlib.sha256(rule_id.encode()).hexdigest()[:16]
        revisions = [path.read_text(encoding='utf-8') for path in sorted(history.glob(prefix + '-*.yml'))] if history.exists() else []
        return render_template('rule_edit.html', rule_id=rule_id, text=text, error=error, revisions=revisions), 400 if error else 200

    @app.route("/rules/new", methods=("GET", "POST"))
    def new_rule():
        error = None
        status = 200
        preview = None
        if request.method == "POST":
            try:
                document = build_rule_document(request.form)
                candidate = Rule.from_dict(document, Path('<rule preview>'))
                if request.form.get('intent') == 'preview':
                    investigation = case_store().get(request.form.get('preview_case', ''))
                    if investigation is None:
                        raise RuleFormError('Select an existing case for preview.')
                    alerts = Detector(RuleEngine([candidate])).run(investigation.events)
                    baseline = Detector(RuleEngine([replace(candidate, exclusions=())])).run(investigation.events)
                    preview = {'case_name': investigation.name, 'events': len(investigation.events),
                               'alerts': len(alerts), 'suppressed': len(baseline) - len(alerts),
                               'event_ids': list(dict.fromkeys(event['id'] for alert in alerts for event in alert.events))[:20]}
                else:
                    destination = install_rule_document(document, Path(app.config["RULES_PATH"]))
            except (RuleFormError, RuleError, OSError, ValueError) as exc:
                error = str(exc)
                status = 400
            else:
                if preview is None:
                    flash(f"Detection rule {document['id']} created in {destination.parent.name}.", "success")
                    return redirect(url_for("rules"))
        condition_rows = list(zip(
            request.form.getlist("condition_field"),
            request.form.getlist("condition_operator"),
            request.form.getlist("condition_value"),
        )) or [("action", "equals", "")]
        return render_template(
            "rule_form.html", error=error, form=request.form, condition_rows=condition_rows,
            fields=CONDITION_FIELDS, operators=CONDITION_OPERATORS, sources=SOURCES,
            severities=SEVERITIES, group_fields=GROUP_FIELDS,
            preview=preview, preview_cases=case_store().list(),
        ), status

    @app.template_filter("short_time")
    def short_time(value: str) -> str:
        return value.replace("T", " ").replace("Z", " UTC")

    @app.template_filter("origin_files")
    def origin_files(events: list[dict]) -> list[str]:
        return sorted({
            filename
            for event in events
            for filename in (event.get("origin_files") or [event.get("origin_file") or "Unknown input"])
        })

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
