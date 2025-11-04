"""Signal fusion logic for the Adaptive Respond Core."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from .state import ARCState, Signal, TelemetryEvent


@dataclass
class FusionResult:
    """Represents the fused trust decision for a telemetry event."""

    risk_score: float
    ati_score: float
    verdict: str
    context_risk: float
    identity_risk: float
    signals: Sequence[Signal]

    def as_dict(self) -> dict[str, object]:
        return {
            "risk_score": self.risk_score,
            "ati_score": self.ati_score,
            "verdict": self.verdict,
            "context_risk": self.context_risk,
            "identity_risk": self.identity_risk,
            "signals": [signal.__dict__ for signal in self.signals],
        }


class AdaptiveFusion:
    """Combines contextual and identity signals into the Adaptive Trust Index."""

    def __init__(self, state: ARCState) -> None:
        self._state = state

    def fuse(
        self,
        event: TelemetryEvent,
        *,
        context_signals: Sequence[Signal],
        identity_signals: Sequence[Signal],
        node_reputation: float,
    ) -> FusionResult:
        weights = self._state.weights
        weights.normalize()

        context_risk = _aggregate(context_signals)
        identity_risk = _aggregate(identity_signals)

        context_factor, identity_factor = self._adaptive_factors(event)
        weighted_risk = (
            context_risk * weights.context_weight * context_factor
            + identity_risk * weights.identity_weight * identity_factor
        )

        reputation_penalty = (1.0 - node_reputation) * 100.0 * weights.reputation_bias
        baseline = self._state.average_global_risk()
        stabilization = (baseline - 50.0) * 0.1

        risk_score = max(0.0, min(100.0, weighted_risk + reputation_penalty + stabilization))
        ati_score = round(max(0.0, min(100.0, 100.0 - risk_score)), 2)
        risk_score = round(risk_score, 2)

        verdict = self._verdict_for(risk_score)

        all_signals = tuple(context_signals) + tuple(identity_signals)
        return FusionResult(
            risk_score=risk_score,
            ati_score=ati_score,
            verdict=verdict,
            context_risk=context_risk,
            identity_risk=identity_risk,
            signals=all_signals,
        )

    def _adaptive_factors(self, event: TelemetryEvent) -> tuple[float, float]:
        framework = event.framework.upper()
        if framework == "AIDA":
            return 0.9, 1.1
        return 1.0, 1.0

    def _verdict_for(self, risk_score: float) -> str:
        if risk_score >= 70.0:
            return "malicious"
        if risk_score >= 45.0:
            return "review"
        return "trusted"


def _aggregate(signals: Iterable[Signal]) -> float:
    total_weight = 0.0
    weighted_sum = 0.0
    for signal in signals:
        total_weight += signal.weight
        weighted_sum += signal.weighted_score()
    if not total_weight:
        return 30.0
    return max(0.0, min(100.0, weighted_sum / total_weight))


__all__ = ["AdaptiveFusion", "FusionResult"]
