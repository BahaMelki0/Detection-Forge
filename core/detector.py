"""Source-agnostic event and temporal correlation detector."""

from __future__ import annotations

from datetime import timedelta
from typing import Iterable

from core.alerter import Alert
from core.event import Event
from core.rule_engine import Rule, RuleEngine


class Detector:
    def __init__(self, engine: RuleEngine):
        self.engine = engine

    def run(self, events: Iterable[Event]) -> list[Alert]:
        timeline = sorted(events, key=lambda event: event.timestamp)
        alerts: list[Alert] = []
        for index, event in enumerate(timeline):
            history = timeline[:index]
            for rule in self.engine.rules:
                if (
                    rule.type == "event" and rule.match
                    and (not rule.sources or event.source in rule.sources)
                    and self.engine.matches(event, rule.match)
                ):
                    alerts.append(Alert.create(rule, [event]))
                elif rule.type == "correlation":
                    correlated = self._correlate(rule, event, history)
                    if correlated:
                        alerts.append(Alert.create(rule, correlated))
        return alerts

    def _correlate(self, rule: Rule, current: Event, history: list[Event]) -> list[Event] | None:
        """Match an ordered sequence ending at current, walking backwards in time."""
        if not self.engine.matches(current, rule.sequence[-1]):
            return None
        matched = [current]
        cursor = current.timestamp
        earliest = current.timestamp - timedelta(minutes=rule.timeframe_minutes)
        group_value = current.get(rule.group_by)
        for stage in reversed(rule.sequence[:-1]):
            candidate = next(
                (
                    prior for prior in reversed(history)
                    if earliest <= prior.timestamp <= cursor
                    and self.engine.matches(prior, stage)
                    and (group_value is None or prior.get(rule.group_by) == group_value)
                ),
                None,
            )
            if candidate is None:
                return None
            matched.append(candidate)
            cursor = candidate.timestamp
        return list(reversed(matched))
