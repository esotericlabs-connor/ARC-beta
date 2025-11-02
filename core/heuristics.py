"""Heuristic signal extraction for ARC."""
from __future__ import annotations

from dataclasses import dataclass
from statistics import mean
from typing import Iterable, Mapping, Sequence

from .state import Signal, TelemetryEvent


@dataclass
class HeuristicBundle:
    """Grouped heuristic output for downstream fusion."""

    context_signals: Sequence[Signal]
    identity_signals: Sequence[Signal]


class HeuristicEngine:
    """Derives weighted heuristic signals for ARC."""

    def __init__(self, state) -> None:
        self._state = state

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def run(self, event: TelemetryEvent) -> HeuristicBundle:
        context_signals = tuple(self._context_signals(event))
        identity_signals = tuple(self._identity_signals(event))
        return HeuristicBundle(context_signals=context_signals, identity_signals=identity_signals)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _context_signals(self, event: TelemetryEvent) -> Iterable[Signal]:
        metrics = event.metrics
        identity = event.identity

        geo_risk = _coerce_float(metrics.get("geo_risk"), identity.get("geo_risk"), default=20.0)
        if geo_risk is not None:
            yield Signal(
                name="context.geo_risk",
                score=max(0.0, min(100.0, geo_risk * 15.0)),
                weight=0.45,
                context={"geo_risk": geo_risk},
            )

        auth_confidence = _coerce_float(metrics.get("auth_confidence"), identity.get("auth_confidence"), default=80.0)
        if auth_confidence is not None:
            auth_risk = max(0.0, min(100.0, 100.0 - auth_confidence))
            yield Signal(
                name="context.auth_confidence",
                score=auth_risk,
                weight=0.5,
                context={"auth_confidence": auth_confidence},
            )

        session_anomaly = metrics.get("session_anomaly")
        if session_anomaly is None:
            session_anomaly = identity.get("session_anomaly")
        if isinstance(session_anomaly, bool):
            yield Signal(
                name="context.session_anomaly",
                score=75.0 if session_anomaly else 20.0,
                weight=0.35 if session_anomaly else 0.15,
                context={"session_anomaly": session_anomaly},
            )

        trust_index = _coerce_float(metrics.get("trust_delta"))
        if trust_index is not None:
            score = max(0.0, min(100.0, 50.0 - trust_index))
            yield Signal(
                name="context.trust_delta",
                score=score,
                weight=0.25,
                context={"trust_delta": trust_index},
            )

    def _identity_signals(self, event: TelemetryEvent) -> Iterable[Signal]:
        identity = event.identity

        if not identity and event.framework != "AIDA":
            return []

        device_history = identity.get("device_history") or []
        if isinstance(device_history, Sequence) and device_history:
            recent_failures = [entry.get("failures", 0) for entry in device_history if isinstance(entry, Mapping)]
            if recent_failures:
                avg_failures = mean(float(value) for value in recent_failures)
                score = max(0.0, min(100.0, min(90.0, avg_failures * 18.0)))
                yield Signal(
                    name="identity.device_failures",
                    score=score,
                    weight=0.25,
                    context={"average_failures": round(avg_failures, 2)},
                )

        behavior_signature = identity.get("behavior_signature")
        if isinstance(behavior_signature, str) and behavior_signature.startswith("HIST-"):
            # Historical deviation indicated by appended intensity (e.g., HIST-2401)
            try:
                intensity = float(behavior_signature.split("-")[-1]) % 100
            except ValueError:
                intensity = 25.0
            yield Signal(
                name="identity.behavior_deviation",
                score=30.0 + min(70.0, intensity * 0.8),
                weight=0.3,
                context={"behavior_signature": behavior_signature},
            )


def _coerce_float(*values: object, default: float | None = None) -> float | None:
    for value in values:
        if value is None:
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    return default


__all__ = ["HeuristicBundle", "HeuristicEngine"]
