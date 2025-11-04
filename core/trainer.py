"""Online reinforcement utilities for ARC."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Deque, Optional

from .state import ARCState, TelemetryEvent


@dataclass
class TrainingFeedback:
    """Represents analyst or automated feedback for adaptive learning."""

    verdict: str
    confidence: float
    expected_risk: float


class AdaptiveTrainer:
    """Lightweight reinforcement learning harness for ARC weights."""

    def __init__(self, state: ARCState, *, learning_rate: float = 0.08) -> None:
        self._state = state
        self._learning_rate = learning_rate
        self._feedback: Deque[TrainingFeedback] = deque(maxlen=512)

    def register_feedback(self, feedback: TrainingFeedback) -> None:
        self._feedback.append(feedback)

    def update_from_event(
        self,
        event: TelemetryEvent,
        *,
        risk_score: float,
        verdict: str,
    ) -> None:
        feedback = self._feedback_from_metadata(event)
        if feedback is None:
            return

        error = feedback.expected_risk - risk_score
        adjustment = self._learning_rate * (error / 100.0) * feedback.confidence

        weights = self._state.weights
        if verdict == "malicious":
            weights.context_weight += adjustment * 0.4
            weights.identity_weight += adjustment * 0.6
        elif verdict == "trusted":
            weights.context_weight -= adjustment * 0.3
            weights.identity_weight -= adjustment * 0.7
        else:  # review
            weights.context_weight += adjustment * 0.2
            weights.identity_weight += adjustment * 0.4

        weights.normalize()

    def _feedback_from_metadata(self, event: TelemetryEvent) -> Optional[TrainingFeedback]:
        metadata = event.metadata
        verdict = metadata.get("feedback_verdict") or metadata.get("verdict")
        if not isinstance(verdict, str):
            return None

        verdict_normalized = verdict.lower()
        if verdict_normalized not in {"malicious", "benign", "trusted", "review"}:
            return None

        confidence_raw = metadata.get("feedback_confidence", 0.6)
        try:
            confidence = max(0.0, min(1.0, float(confidence_raw)))
        except (TypeError, ValueError):
            confidence = 0.5

        expected_risk = {
            "malicious": 90.0,
            "benign": 15.0,
            "trusted": 20.0,
            "review": 50.0,
        }[verdict_normalized]

        feedback = TrainingFeedback(
            verdict=verdict_normalized,
            confidence=confidence,
            expected_risk=expected_risk,
        )
        self.register_feedback(feedback)
        return feedback
    def export_weights(self) -> dict[str, float]:
        weights = self._state.weights
        return {
            "context_weight": round(weights.context_weight, 6),
            "identity_weight": round(weights.identity_weight, 6),
            "reputation_bias": round(weights.reputation_bias, 6),
        }


__all__ = ["AdaptiveTrainer", "TrainingFeedback"]
