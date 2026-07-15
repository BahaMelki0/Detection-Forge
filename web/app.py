"""Read-only Flask presentation layer for Detection Forge alerts."""

from __future__ import annotations

from collections import Counter
import os
from pathlib import Path
import secrets
from tempfile import TemporaryDirectory

from flask import Flask, abort, flash, make_response, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

from core.alerter import AlertStore
from core.pipeline import FILE_TYPES, detect_events, input_from_profile, load_inputs
from core.rule_builder import (
    CONDITION_FIELDS, CONDITION_OPERATORS, GROUP_FIELDS, SEVERITIES, SOURCES,
    RuleFormError, build_rule_document,
)
from core.rule_engine import RuleEngine, RuleError
from core.rule_manager import install_rule_document
from core.workspace import AnalysisWorkspace, IngestedFile

ROOT = Path(__file__).resolve().parents[1]
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(
        ALERTS_PATH=ROOT / "data" / "alerts.json",
        WORKSPACE_PATH=ROOT / "data" / "workspace.json",
        RULES_PATH=ROOT / "rules",
        MAX_CONTENT_LENGTH=32 * 1024 * 1024,
        SECRET_KEY=os.environ.get("DETECTION_FORGE_SECRET", secrets.token_hex(32)),
    )
    if config:
        app.config.update(config)

    def load_alerts():
        return AlertStore(app.config["ALERTS_PATH"]).load()

    @app.get("/")
    def dashboard():
        alerts = sorted(
            load_alerts(),
            key=lambda alert: (SEVERITY_RANK.get(alert.severity, 99), alert.timestamp),
        )
        counts = Counter(alert.severity for alert in alerts)
        rule_count = len(RuleEngine.from_directory(app.config["RULES_PATH"]).rules)
        workspace = AnalysisWorkspace(app.config["WORKSPACE_PATH"]).load()
        return render_template(
            "dashboard.html", alerts=alerts, counts=counts, rule_count=rule_count,
            file_types=FILE_TYPES, workspace_files=workspace.files,
            workspace_event_count=len(workspace.events), workspace_updated_at=workspace.updated_at,
        )

    @app.post("/analyze")
    def analyze_upload():
        uploads = request.files.getlist("files")
        profiles = request.form.getlist("types")
        submitted = [(upload, profile) for upload, profile in zip(uploads, profiles) if upload.filename]
        if not submitted:
            flash("Choose at least one JSON or JSONL telemetry file.", "error")
            return redirect(url_for("dashboard"))

        try:
            with TemporaryDirectory(prefix="detection-forge-") as temporary:
                inputs = []
                pending_files = []
                for index, (upload, profile) in enumerate(submitted):
                    if profile not in FILE_TYPES:
                        raise ValueError(f"Unsupported file type: {profile}")
                    filename = secure_filename(upload.filename)
                    if not filename or Path(filename).suffix.lower() not in {".json", ".jsonl", ".ndjson"}:
                        raise ValueError(f"{upload.filename}: expected a .json, .jsonl, or .ndjson file")
                    destination = Path(temporary) / f"{index}_{filename}"
                    upload.save(destination)
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
                workspace_store = AnalysisWorkspace(app.config["WORKSPACE_PATH"])
                existing = workspace_store.load()
                combined_events = existing.events + new_events
                alerts = detect_events(combined_events, Path(app.config["RULES_PATH"]))
                workspace_store.append(completed_files, new_events)
                AlertStore(app.config["ALERTS_PATH"]).save(alerts)
        except (OSError, ValueError) as exc:
            flash(f"Analysis failed: {exc}", "error")
            return redirect(url_for("dashboard"))

        flash(
            f"Added {len(new_events)} events from {len(completed_files)} file(s). "
            f"Workspace analysis generated {len(alerts)} alerts.",
            "success",
        )
        return redirect(url_for("dashboard"))

    @app.post("/workspace/clear")
    def clear_workspace():
        AnalysisWorkspace(app.config["WORKSPACE_PATH"]).clear()
        Path(app.config["ALERTS_PATH"]).unlink(missing_ok=True)
        flash("Workspace cleared. Uploaded-file memory, normalized events, and alerts were removed.", "success")
        return redirect(url_for("dashboard"))

    @app.get("/report")
    def export_report():
        alerts = load_alerts()
        workspace = AnalysisWorkspace(app.config["WORKSPACE_PATH"]).load()
        response = make_response(render_template(
            "report.html", alerts=alerts, files=workspace.files,
            event_count=len(workspace.events), generated_at=workspace.updated_at,
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
        alert = next((item for item in load_alerts() if item.id == alert_id), None)
        if alert is None:
            abort(404)
        return render_template("alert_detail.html", alert=alert)

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

    @app.route("/rules/new", methods=("GET", "POST"))
    def new_rule():
        error = None
        status = 200
        if request.method == "POST":
            try:
                document = build_rule_document(request.form)
                destination = install_rule_document(document, Path(app.config["RULES_PATH"]))
            except (RuleFormError, RuleError, OSError, ValueError) as exc:
                error = str(exc)
                status = 400
            else:
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
        ), status

    @app.template_filter("short_time")
    def short_time(value: str) -> str:
        return value.replace("T", " ").replace("Z", " UTC")

    @app.template_filter("origin_files")
    def origin_files(events: list[dict]) -> list[str]:
        return sorted({event.get("origin_file") or "Unknown input" for event in events})

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
