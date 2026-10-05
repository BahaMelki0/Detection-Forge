# Case investigation workflow

## Collect and review

Create a case before uploading logs. Auto detection recognizes supported Entra sign-in/audit, Windows Security and Sysmon content; choose a profile manually if ambiguous. Repeat events merge provenance rather than increasing counts. Separate tenants/investigations into separate cases.

Timeline search operates on the newest 200 events. Analyst dispositions and notes persist separately from detection evidence. Sensitive identity changes can represent approved administration and are review signals.

Automatic collection watches explicit JSONL/NDJSON files at 1/2/5/10-minute intervals. Saved offsets resume on restart; complete lines are required; truncation/replacement resets checkpoints. Closing a case pauses collection. Source files remain untouched. See the README for file/count limits.

## Rules

Preview event or two-stage rules before saving. Preview does not install YAML or change case state. Explicit exclusions apply to every sequence stage; free-text false-positive notes do not suppress events.

Edit / History increments the version and retains the previous mapping outside the active registry. Stale revisions are rejected. Test positive and negative fixtures; zero preview alerts alone do not establish correctness. History is not automatic rollback.

See [Entra coverage](IDENTITY_DETECTIONS.md) for audit properties, workload sign-ins and target-based sequences.

## Local AI snapshots

Analyze case queues a background Ollama task. Default: `qwen3.5:9b`; override `DETECTION_FORGE_OLLAMA_MODEL` or `DETECTION_FORGE_OLLAMA_URL` before starting. The endpoint must remain loopback; no hosted fallback exists.

Evidence is bounded and prioritized with explicit coverage. Event/alert aliases resolve to validated supplied IDs. Analyst decisions enter the snapshot. New evidence/decisions mark earlier analysis stale rather than erasing it. Cancellation prevents publication; active inference may finish in the background. Interrupted queued/running tasks become failed on restart.

## Report and lifecycle

Export HTML/PDF for current evidence, analyst decisions and the latest successful snapshot, including provenance/stale status. Resolve, reopen, clear or delete disposable cases using UI confirmation. Deletion removes case artifacts, not original logs.

Upload `examples/identity_review.jsonl`: expect three medium review alerts. Use a separate benign case to check isolation. Run `python -m pytest -q`; 77 tests passed in the October 5 implementation pass. Synthetic analysis/PDF scripts are under `examples/`.

Cited-analysis smoke checks took about 6 seconds with 4B and 25 seconds with 9B including switching/loading. Valid citations establish provenance, not correctness. Automatic approval/PIM integration, tenant inference and large-scale incremental storage remain future work.
