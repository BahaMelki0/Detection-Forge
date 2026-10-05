# Detection Forge

Recent workflow additions: case-scoped rule previews and exclusions; editable YAML revisions with history; service-principal audit/workload correlation; searchable timeline and analyst dispositions; background local AI snapshots with validated citations, cancellation, restart recovery and stale-evidence markers. HTML/PDF exports include analyst decisions. Synthetic verification scripts are under `examples/`.

Detection Forge is a source-agnostic, detection-as-code engine for Microsoft Entra ID, Windows Security, and Sysmon telemetry. It normalizes vendor events into one schema, evaluates YAML detections, correlates hybrid identity-to-endpoint attacks, and exposes the resulting alerts in a deliberately thin Flask analyst console.

The analyst console shares the **Obsidian Signal** identity used by APK Sentinel and JobForge: graphite surfaces, signal red, and consistent blue, amber, coral, and green state colors.

## Why this architecture matters

The engine and presentation layers are independent. Both `main.py` and the Flask upload route call the shared pipeline in `core/pipeline.py`; connectors normalize telemetry and the detector evaluates rules without depending on either interface. Alerts are written atomically to a JSON artifact. The CLI therefore remains usable in a pipeline, cron job, or CI workflow without the web server.

```text
Entra / Windows / Sysmon JSONL
                |
       connector normalization
                |
         canonical events
                |
       YAML rule evaluation
                |
     case evidence and alerts
                |
        CLI / Flask workspace
```

## Features

- Canonical, typed event schema with access to nested normalized fields
- Three connectors for Entra ID, Windows Security, and Sysmon JSON Lines
- Version-controlled YAML rules with ATT&CK mapping and remediation guidance
- Case-insensitive operators: equality, membership, substring, regex, and numeric comparisons
- Ordered, time-bounded cross-source sequences grouped by identity
- Atomic JSON persistence shared safely between CLI and UI
- Isolated investigation cases that retain uploaded-file metadata, normalized events, and alerts per case
- Downloadable HTML investigation report with per-detection input-file attribution
- Structured web rule builder with event conditions, two-stage correlations, and transactional YAML validation
- Case workspace with separate overview, rule alerts, local AI analysis, evidence, log collection, and report sections
- Stable event and alert fingerprints that prevent repeat uploads from inflating findings
- Duplicate-event provenance merged across every input file that contained the event
- Incident cases grouped by shared identity, endpoint, or source IP within 30 minutes
- Explainable priority heuristic and persisted, case-scoped local-only Ollama analysis
- Content-based log profile detection with manual fallback when confidence is low
- Opt-in polling of explicit local JSONL paths, with per-case offsets and rotation handling
- Case lifecycle controls for close, resolve with notes, reopen, clear, and confirmed deletion
- Full case PDF export
- Synthetic attack data and pytest coverage

## Detection coverage

The active pack contains 18 rules: Entra risky authentication, three sensitive audit-change review rules, a target-based credential-to-workload-sign-in sequence, one hybrid Entra-to-Windows sequence, and 12 Windows/Sysmon detections. Windows coverage includes encoded PowerShell, download cradles, Office child processes, LSASS dumping, Certutil, Regsvr32, Rundll32, Defender impairment, Security log clearing, scheduled tasks, account creation, and privileged-group membership.

These are Sigma-inspired event detections expressed in the project's own YAML schema—not YARA signatures. YARA is designed for file or memory content and would belong in a separate scanning connector so that file inspection does not become coupled to the event engine.

## Quick start

Requires Python 3.10 or newer.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m web.app
```

Open `http://127.0.0.1:5000`. Detection Forge starts with no implicit analysis. Telemetry is processed only when files are explicitly supplied through the UI or CLI.

Create an investigation case from **Cases**, then open it to upload related JSON/JSONL telemetry. The case page separates overview, detection-rule alerts, AI analysis, evidence, log collection, and report. Raw uploads are processed temporarily and discarded; normalized events, file metadata, alert results, collection checkpoints, and the saved AI analysis are retained under `data/cases/`. Later uploads are analyzed with that case's history only, so unrelated investigations cannot correlate with each other. Cases can be closed, resolved with notes, reopened, cleared independently, exported as HTML or PDF, or permanently deleted after typing the exact case name. Deleting a case does not delete any source log files.

For automatic collection, configure up to 20 existing file paths in a case using one JSONL/NDJSON path per line. Choose a 1, 2, 5, or 10 minute interval and enable the watcher. Polling runs only while the Flask app is running; it resumes from saved offsets after app restart. The watcher reads source files without modifying them, waits for complete lines, resets offsets after truncation/replacement, and applies deduplication and detection only inside the configured case. It is intended for append-only JSON Lines logs; whole-file JSON exports should be manually uploaded. The **Scan now** action is available for immediate checks. Each file must stay under 32 MB and the watcher accepts explicit files, not recursive directories or wildcards.

Uploads and watched log chunks default to automatic content-based profile detection across supported Entra sign-in/audit, Windows Security, and Sysmon formats. The UI records the detected profile; if the content is ambiguous or unsupported, choose a type manually rather than accepting a guess. File extensions alone do not determine the profile.

Repeated normalized events are deduplicated by a stable content fingerprint. Their source-file provenance is merged, so evidence keeps pointing to every uploaded file that contained the event. Alert IDs are stable for a rule/evidence combination. Related alerts appear as an incident case when they share an identity, endpoint, or source IP inside 30 minutes; the queue's 0-100 priority is an explainable heuristic, not a probability of compromise.

The case's **AI correlation & analysis** section queues a background evidence-grounded report using local Ollama. By default Detection Forge calls `http://127.0.0.1:11434` with `qwen3.5:9b`; override with `DETECTION_FORGE_OLLAMA_URL` or `DETECTION_FORGE_OLLAMA_MODEL`. It includes bounded normalized evidence from that case, not raw payloads; common secret-like values in event details are redacted. No hosted model fallback is used. Snapshots retain model, prompt version, coverage and validated event/alert references. Earlier results remain available and are marked stale when evidence or analyst decisions change. Exports include the latest successful snapshot with its provenance and stale status. Cancellation prevents publication; active model inference can finish in the background. Treat conclusions as hypotheses and verify them against source evidence.

The **Detection Rules** view includes a rule builder for single-event and two-stage correlation rules. Rules apply to telemetry inside each case; cross-source sequences cannot combine separate cases. The builder validates normalized fields, operators, regular expressions, sources, timeframes, ATT&CK metadata, duplicate IDs, and the complete registry before generating a YAML file. Invalid submissions remain populated in the form and do not modify the rule directory.

Severity labels are colored automatically in interactive terminals. Use `python main.py analyze ... --color always` to force colors or `--color never` to disable them. The standard `NO_COLOR` environment variable is also respected.

## CLI workflows

There is no demo or automatically loaded dataset. Running `python main.py` only displays help. To analyze a file, select a file-type profile; the profile automatically selects the correct source connector and log subtype:

```powershell
python main.py analyze --file .\exports\signins.json --type entra_signin
python main.py analyze --file .\exports\auditLogs.json --type entra_audit
python main.py analyze --file .\exports\Security.jsonl --type windows_security
python main.py analyze --file .\exports\Sysmon.json --type sysmon
```

Available types are `entra_signin`, `entra_audit`, `entra_auto`, `windows_security`, and `sysmon`. JSON Lines, JSON arrays, and export objects containing a `value`, `events`, or `records` array are accepted.

Repeat paired `--file` and `--type` flags when several sources must share the same detection timeline:

```powershell
python main.py analyze `
  --file .\exports\signins.json --type entra_signin `
  --file .\exports\auditLogs.json --type entra_audit `
  --file .\exports\Security.jsonl --type windows_security `
  --file .\exports\Sysmon.jsonl --type sysmon `
  --output .\data\investigation-alerts.json
```

Files and types are paired by their order. This multi-file form is required for Entra-to-Windows correlation rules because every event is normalized into one ordered timeline before detection.

### Rule management

The CLI can inspect and validate the active registry:

```powershell
python main.py rules list
python main.py rules list --json
python main.py rules validate
python main.py rules validate .\candidate-rule.yml
```

Install a new rule after validation with:

```powershell
python main.py rules add .\candidate-rule.yml
```

The destination category is inferred from the rule sources and type. Duplicate IDs and overwrites are rejected. Use `--category entra`, `windows`, or `cross_source` only when an explicit destination is needed.

Run tests with:

```powershell
pytest -q
```

## Detection rule format

Single-event rule:

```yaml
id: DF-WIN-001
title: Encoded PowerShell execution
type: event
sources: [windows, sysmon]
severity: high
match:
  conditions:
    action: process_created
    details.command_line:
      contains_any: [-enc, -encodedcommand]
attack:
  id: T1059.001
  name: PowerShell
  tactic: Execution
  url: https://attack.mitre.org/techniques/T1059/001/
remediation: Isolate and investigate the host.
```

Correlation rules replace `match` with an ordered `sequence`, plus `group_by` and `timeframe_minutes`. Each stage can target a different normalized source.

## Repository map

```text
connectors/       Vendor-specific normalization only
core/             Event model, shared pipeline, rule evaluation, correlation, persistence
rules/            Entra, Windows/Sysmon, and cross-source YAML rules
mappings/         Local ATT&CK reference metadata
web/              Flask analyst workspace, report, and temporary upload adapter
data/             Optional synthetic examples; local case telemetry and workspace state are ignored
tests/            Connector, engine, correlation, and route tests
main.py           Standalone CLI entry point
```

> All bundled telemetry is synthetic and uses documentation-only IP address ranges.


## Investigation guide and validation

See [case investigation workflow](docs/INVESTIGATION_WORKFLOW.md) and [Entra identity coverage](docs/IDENTITY_DETECTIONS.md). The October 5 implementation pass passed 77 tests. Synthetic PDF output was rendered and both pages visually inspected; browser visual review remains a manual release gate.

Rule previews, explicit exclusions, versioned editing/history, searchable recent timeline, analyst decisions and background cited AI snapshots are implemented. Resolving a citation proves provenance, not the correctness of the model's conclusion. Automatic tenant/approval integration and large-scale incremental persistence remain future work.
