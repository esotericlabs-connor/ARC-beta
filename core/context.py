"""Cross-domain contextual correlation for ARC."""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Deque, Dict, Iterable, List, Mapping, Sequence

from .state import Signal, TelemetryEvent


@dataclass
class CorrelatedEvent:
    """Summary of a related telemetry event."""

    timestamp: datetime
    node_id: str
    framework: str
    risk_score: float
    verdict: str


@dataclass
class CorrelationResult:
    """Contextual correlation output."""

    actors: Sequence[str]
    aggregated_risk: float
    related_events: Sequence[CorrelatedEvent]

    def as_dict(self) -> dict[str, object]:
        return {
            "actors": list(self.actors),
            "aggregated_risk": self.aggregated_risk,
            "related_events": [
                {
                    "timestamp": event.timestamp.isoformat(),
                    "node_id": event.node_id,
                    "framework": event.framework,
                    "risk_score": event.risk_score,
                    "verdict": event.verdict,
                }
                for event in self.related_events
            ],
        }


class ContextCorrelator:
    """Maintains rolling context for cross-domain incident detection."""

    def __init__(self, *, max_history: int = 256, window: timedelta = timedelta(hours=12)) -> None:
        self._window = window
        self._events_by_actor: Dict[str, Deque[CorrelatedEvent]] = defaultdict(lambda: deque(maxlen=max_history))

    def record(
        self,
        event: TelemetryEvent,
        *,
        risk_score: float,
        verdict: str,
        signals: Iterable[Signal],
    ) -> CorrelationResult | None:
        actors = self._actors_for_event(event)
        if not actors:
            return None

        correlated: List[CorrelatedEvent] = []
        signal_snapshot = list(signals)
        now = event.timestamp

        correlated_event = CorrelatedEvent(
            timestamp=now,
            node_id=event.node_id,
            framework=event.framework,
            risk_score=risk_score,
            verdict=verdict,
        )

        for actor in actors:
            queue = self._events_by_actor[actor]
            self._prune(queue, now)
            correlated.extend(queue)
            queue.append(correlated_event)

        if not correlated:
            return None

        aggregated_risk = sum(item.risk_score for item in correlated) / len(correlated)
        if any(signal.weight >= 0.5 and signal.score >= 70.0 for signal in signal_snapshot):
            aggregated_risk += 5.0
        aggregated_risk = round(min(100.0, aggregated_risk), 2)
        return CorrelationResult(
            actors=tuple(actors),
            aggregated_risk=aggregated_risk,
            related_events=tuple(correlated),
        )

    def snapshot(self) -> Mapping[str, Sequence[CorrelatedEvent]]:
        return {actor: tuple(events) for actor, events in self._events_by_actor.items()}

    def _actors_for_event(self, event: TelemetryEvent) -> Sequence[str]:
        identity = event.identity
        actors: List[str] = []
        user_hash = identity.get("user_hash")
        if isinstance(user_hash, str) and user_hash:
            actors.append(f"user:{user_hash}")
        session_id = identity.get("session_id") or event.metadata.get("session_id")
        if isinstance(session_id, str) and session_id:
            actors.append(f"session:{session_id}")
        from_domain = event.email.get("from_domain")
        if isinstance(from_domain, str) and from_domain:
            actors.append(f"domain:{from_domain.lower()}")
        return actors

    def _prune(self, queue: Deque[CorrelatedEvent], now: datetime) -> None:
        cutoff = now - self._window
        while queue and queue[0].timestamp < cutoff:
            queue.popleft()


__all__ = ["ContextCorrelator", "CorrelationResult", "CorrelatedEvent"]