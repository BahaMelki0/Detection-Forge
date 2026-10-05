"""Shared input profiles and analysis pipeline used by CLI and Flask."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

from connectors.base import BaseConnector
from connectors.entra_connector import EntraConnector
from connectors.sysmon_connector import SysmonConnector
from connectors.windows_connector import WindowsConnector
from core.alerter import Alert
from core.detector import Detector
from core.event import Event
from core.rule_engine import RuleEngine

LOG_TYPE_ALIASES = {
    "signins": "signin", "signin": "signin", "sign-in": "signin",
    "auditlogs": "audit", "audit": "audit", "audit-log": "audit",
    "security": "security", "security-event": "security",
    "sysmon": "sysmon", "operational": "sysmon", "auto": "auto",
}
VALID_LOG_TYPES = {
    "entra": {"signin", "audit", "auto"},
    "windows": {"security"},
    "sysmon": {"sysmon"},
}
FILE_TYPES = {
    "entra_signin": ("entra", "signin"),
    "entra_audit": ("entra", "audit"),
    "entra_auto": ("entra", "auto"),
    "windows_security": ("windows", "security"),
    "sysmon": ("sysmon", "sysmon"),
}


@dataclass(frozen=True, slots=True)
class InputSpec:
    source: str
    log_type: str
    path: Path
    profile: str | None = None
    display_name: str | None = None
    origin_file_id: str | None = None


def make_input(source: str, log_type: str, path: Path) -> InputSpec:
    normalized_source = source.lower()
    normalized_type = LOG_TYPE_ALIASES.get(log_type.lower(), log_type.lower())
    if normalized_source not in VALID_LOG_TYPES:
        raise ValueError(f"Unsupported source '{source}'. Choose entra, windows, or sysmon")
    if normalized_type not in VALID_LOG_TYPES[normalized_source]:
        allowed = ", ".join(sorted(VALID_LOG_TYPES[normalized_source]))
        raise ValueError(f"Log type '{log_type}' is not valid for {source}; choose {allowed}")
    return InputSpec(normalized_source, normalized_type, Path(path))


def input_from_profile(
    profile: str, path: Path, *, display_name: str | None = None, origin_file_id: str | None = None
) -> InputSpec:
    if profile not in FILE_TYPES:
        raise ValueError(f"Unsupported file type: {profile}")
    source, log_type = FILE_TYPES[profile]
    specification = make_input(source, log_type, path)
    return replace(
        specification, profile=profile, display_name=display_name or Path(path).name,
        origin_file_id=origin_file_id,
    )


def infer_profile(path: str | Path) -> dict:
    """Identify a known JSON telemetry schema from file contents."""
    from core.log_detection import detect_log_type
    return detect_log_type(path)


def connector_for(specification: InputSpec) -> BaseConnector:
    if specification.source == "entra":
        return EntraConnector(specification.log_type)
    if specification.source == "windows":
        return WindowsConnector()
    return SysmonConnector()


def load_inputs(inputs: list[InputSpec]) -> tuple[list[Event], list[int]]:
    events: list[Event] = []
    input_counts: list[int] = []
    for specification in inputs:
        loaded = [
            replace(
                event,
                origin_file=specification.display_name or specification.path.name,
                origin_type=specification.profile or f"{specification.source}_{specification.log_type}",
                origin_file_id=specification.origin_file_id,
            )
            for event in connector_for(specification).read(specification.path)
        ]
        events.extend(loaded)
        input_counts.append(len(loaded))
    return events, input_counts


def detect_events(events: list[Event], rules_path: Path) -> list[Alert]:
    engine = RuleEngine.from_directory(rules_path)
    return Detector(engine).run(events)


def analyze(inputs: list[InputSpec], rules_path: Path) -> tuple[list[Event], list[Alert], list[int]]:
    events, input_counts = load_inputs(inputs)
    return events, detect_events(events, rules_path), input_counts
