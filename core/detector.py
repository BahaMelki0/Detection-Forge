"""Source-agnostic event and temporal correlation detector."""

from __future__ import annotations

from datetime import timedelta
from collections import deque
from typing import Iterable

from core.alerter import Alert
from core.event import Event
from core.identity import same_entity
from core.rule_engine import Rule, RuleEngine


class Detector:
    def __init__(self, engine: RuleEngine):
        self.engine = engine

    def run(self, events: Iterable[Event]) -> list[Alert]:
        timeline = sorted(events, key=lambda event: event.timestamp)
        alerts: list[Alert] = []
        history = deque()
        window = max((rule.timeframe_minutes for rule in self.engine.rules if rule.type == 'correlation'), default=0)
        for event in timeline:
            earliest = event.timestamp - timedelta(minutes=window)
            while history and history[0].timestamp < earliest:
                history.popleft()
            for rule in self.engine.rules:
                if any(self.engine.matches(event, exclusion) for exclusion in rule.exclusions):
                    continue
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
            history.append(event)
        unique = {alert.id: alert for alert in alerts}
        return list(unique.values())

    def _correlate(self, rule: Rule, current: Event, history: list[Event]) -> list[Event] | None:
        """Match an ordered sequence ending at current, walking backwards in time."""
        if not self.engine.matches(current, rule.sequence[-1]):
            return None
        matched = [current]
        cursor = current.timestamp
        earliest = current.timestamp - timedelta(minutes=rule.timeframe_minutes)
        group_value = current.get(rule.group_by)
        if group_value is None or not str(group_value).strip():
            return None
        for stage in reversed(rule.sequence[:-1]):
            candidate = next(
                (
                    prior for prior in reversed(history)
                    if earliest <= prior.timestamp <= cursor
                    and not any(self.engine.matches(prior, exclusion) for exclusion in rule.exclusions)
                    and self.engine.matches(prior, stage)
                    and (
                        same_entity(rule.group_by, str(prior.get(rule.group_by) or ""), str(group_value))
                    )
                ),
                None,
            )
            if candidate is None:
                return None
            matched.append(candidate)
            cursor = candidate.timestamp
        return list(reversed(matched))
