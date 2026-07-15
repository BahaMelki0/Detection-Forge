"""Base class for connectors that normalize JSON Lines input."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Iterable

from core.event import Event


class BaseConnector(ABC):
    source: str

    @abstractmethod
    def normalize(self, raw: dict[str, Any]) -> Event:
        """Convert one vendor-specific record into the canonical schema."""

    def read(self, path: str | Path) -> Iterable[Event]:
        """Read JSON Lines, a JSON array, or common export wrappers such as ``value``."""
        input_path = Path(path)
        if not input_path.is_file():
            raise ValueError(f"Input file does not exist: {input_path}")
        content = input_path.read_text(encoding="utf-8-sig")
        if not content.strip():
            raise ValueError(f"Input file is empty: {input_path}")

        records: list[tuple[int, dict[str, Any]]] = []
        try:
            document = json.loads(content)
        except json.JSONDecodeError:
            for line_number, line in enumerate(content.splitlines(), start=1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid JSON at line {line_number} in {input_path}: {exc.msg}") from exc
                if not isinstance(value, dict):
                    raise ValueError(f"Expected an object at line {line_number} in {input_path}")
                records.append((line_number, value))
        else:
            values = self._unwrap_document(document, input_path)
            records = [(index, value) for index, value in enumerate(values, start=1)]

        for record_number, raw in records:
            try:
                yield self.normalize(raw)
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(
                    f"Invalid {self.source} event #{record_number} in {input_path}: {exc}"
                ) from exc

    @staticmethod
    def _unwrap_document(document: Any, path: Path) -> list[dict[str, Any]]:
        if isinstance(document, list):
            values = document
        elif isinstance(document, dict):
            wrapper = next(
                (document[key] for key in ("value", "events", "records") if isinstance(document.get(key), list)),
                None,
            )
            values = wrapper if wrapper is not None else [document]
        else:
            raise ValueError(f"Expected a JSON object or array in {path}")
        if not all(isinstance(value, dict) for value in values):
            raise ValueError(f"Every event in {path} must be a JSON object")
        return values
