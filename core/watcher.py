"""Safe polling of explicitly configured local log files for case-scoped ingestion."""

from __future__ import annotations

import hashlib
from pathlib import Path

ALLOWED_INTERVALS = {60, 120, 300, 600}
MAX_FILE_BYTES = 32 * 1024 * 1024


def validate_paths(raw: str) -> list[str]:
    paths = []
    for value in raw.splitlines():
        value = value.strip().strip('"')
        if not value:
            continue
        candidate = Path(value).expanduser().resolve()
        if not candidate.is_file():
            raise ValueError(f"Watched path must be an existing file: {value}")
        if candidate.suffix.casefold() not in {".json", ".jsonl", ".ndjson"}:
            raise ValueError(f"Only JSON, JSONL, and NDJSON files are supported: {candidate.name}")
        if candidate.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"Watched file exceeds the 32 MB limit: {candidate.name}")
        paths.append(str(candidate))
    if len(paths) > 20:
        raise ValueError("A case can watch at most 20 explicit files.")
    return list(dict.fromkeys(paths))


def read_new_records(path: Path, checkpoint: dict) -> tuple[bytes, dict, int]:
    """Read appended bytes; reset on replacement/truncation and ignore partial last lines."""
    stat = path.stat()
    if stat.st_size > MAX_FILE_BYTES:
        raise ValueError(f"Watched file exceeds the 32 MB per-file processing limit: {path.name}")
    identity = f"{stat.st_dev}:{stat.st_ino}"
    previous_identity = checkpoint.get("identity")
    offset = checkpoint.get("offset", 0)
    head_size = min(offset, 65536)
    with path.open("rb") as stream:
        current_head = hashlib.sha256(stream.read(head_size)).hexdigest() if head_size else ""
    if identity != previous_identity or stat.st_size < offset or (checkpoint.get("head_digest") and checkpoint["head_digest"] != current_head):
        offset = 0
    with path.open("rb") as stream:
        stream.seek(offset)
        payload = stream.read()
    if not payload:
        head_size = min(stat.st_size, 65536)
        with path.open("rb") as stream:
            head_digest = hashlib.sha256(stream.read(head_size)).hexdigest() if head_size else ""
        return b"", {"identity": identity, "offset": stat.st_size, "digest": checkpoint.get("digest", ""), "head_digest": head_digest}, 0
    complete_end = payload.rfind(b"\n") + 1
    if complete_end == 0:
        return b"", {"identity": identity, "offset": offset, "digest": checkpoint.get("digest", ""), "head_digest": checkpoint.get("head_digest", "")}, 0
    complete = payload[:complete_end]
    signature = hashlib.sha256(complete).hexdigest()
    try:
        decoded = complete.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Watched file is not UTF-8 JSON: {path.name}") from exc
    # A whole JSON array/object is not append-friendly; require JSON Lines for live updates.
    lines = [line for line in decoded.splitlines() if line.strip()]
    if not lines:
        new_offset = offset + complete_end
        with path.open("rb") as stream:
            head_digest = hashlib.sha256(stream.read(min(new_offset, 65536))).hexdigest()
        return b"", {"identity": identity, "offset": new_offset, "digest": signature, "head_digest": head_digest}, 0
    import json
    records = []
    for line in lines:
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"New content in {path.name} is not valid JSON Lines: {exc.msg}") from exc
        if isinstance(record, dict):
            records.append(record)
        elif isinstance(record, list):
            records.extend(item for item in record if isinstance(item, dict))
    new_offset = offset + complete_end
    with path.open("rb") as stream:
        head_digest = hashlib.sha256(stream.read(min(new_offset, 65536))).hexdigest()
    new_checkpoint = {"identity": identity, "offset": new_offset, "digest": signature, "head_digest": head_digest}
    return ("\n".join(json.dumps(record, ensure_ascii=False) for record in records).encode("utf-8"), new_checkpoint, len(records))
