# Detection Forge

Detection Forge is a source-agnostic, detection-as-code engine for Microsoft Entra ID, Windows Security, and Sysmon telemetry. It normalizes vendor events into one schema, evaluates YAML detections, correlates hybrid identity-to-endpoint attacks, and exposes the resulting alerts in a deliberately thin Flask analyst console.

## Why this architecture matters

The engine and presentation layers are independent. Both `main.py` and the Flask upload route call the shared pipeline in `core/pipeline.py`; connectors normalize telemetry and the detector evaluates rules without depending on either interface. Alerts are written atomically to a JSON artifact. The CLI therefore remains usable in a pipeline, cron job, or CI workflow without the web server.

```text
Entra / Windows / Sysmon JSONL
              │
              ▼
     connectors/ normalization
              │ canonical Event
              ▼
    rules/*.yml → core/ detector
              │
              ▼
       data/alerts.json
          ▲         ▲
        CLI       Flask UI
```

## Features

- Canonical, typed event schema with access to nested normalized fields
- Three connectors for Entra ID, Windows Security, and Sysmon JSON Lines
- Version-controlled YAML rules with ATT&CK mapping and remediation guidance
- Case-insensitive operators: equality, membership, substring, regex, and numeric comparisons
- Ordered, time-bounded cross-source sequences grouped by identity
- Atomic JSON persistence shared safely between CLI and UI
- Persistent UI workspace that remembers uploaded-file metadata and normalized events across batches
- Downloadable HTML investigation report with per-detection input-file attribution
- Structured web rule builder with event conditions, two-stage correlations, and transactional YAML validation
- Three analyst views: prioritized alert queue, evidence detail, and active rule registry
- Synthetic attack data and pytest coverage

## Detection coverage

The active pack contains 14 rules: Entra risky authentication, one hybrid Entra-to-Windows sequence, and 12 Windows/Sysmon detections. Windows coverage includes encoded PowerShell, download cradles, Office child processes, LSASS dumping, Certutil, Regsvr32, Rundll32, Defender impairment, Security log clearing, scheduled tasks, account creation, and privileged-group membership.

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

The dashboard supports dynamically added typed JSON/JSONL files. Raw uploads are processed temporarily and discarded, while normalized events and file metadata remain in `data/workspace.json`. Later batches are analyzed together with that history, enabling correlations across any number of ingested files. The workspace can be cleared explicitly, and current findings can be exported as a standalone HTML report.

The **Detection rules** view includes a rule builder for single-event and two-stage correlation rules. It validates normalized fields, operators, regular expressions, sources, timeframes, ATT&CK metadata, duplicate IDs, and the complete registry before generating a YAML file. Invalid submissions remain populated in the form and do not modify the rule directory.

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
data/             Optional synthetic examples; generated alerts and workspace state are ignored
tests/            Connector, engine, correlation, and route tests
main.py           Standalone CLI entry point
```

> All bundled telemetry is synthetic and uses documentation-only IP address ranges.
