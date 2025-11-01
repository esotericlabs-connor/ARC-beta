"""Node reputation tracking for ARC."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from .state import ARCState, NodeState, TelemetryEvent


@dataclass
class ReputationResult:
    """Summarised reputation metrics for a node."""

    node_id: str
    reputation: float
    reliability: float
    anomaly_rate: float

    def as_dict(self) -> dict[str, float | str]:
        return {
            "node_id": self.node_id,
            "reputation": self.reputation,
            "reliability": self.reliability,
            "anomaly_rate": self.anomaly_rate,
        }


class NodeReputationTracker:
    """Maintains rolling reputation scores for contributing nodes."""

    def __init__(self, state: ARCState) -> None:
        self._state = state

    def update(
        self,
        event: TelemetryEvent,
        *,
        risk_score: float,
        verdict: str,
    ) -> ReputationResult:
        node_state = self._state.get_node(event.node_id, event.framework)
        node_state.record_observation(risk_score, verdict)

        reputation = self._compute_reputation(node_state)
        node_state.reputation = reputation

        return ReputationResult(
            node_id=event.node_id,
            reputation=round(reputation, 3),
            reliability=round(node_state.reliability, 3),
            anomaly_rate=round(node_state.anomaly_rate, 3),
        )

    def snapshot(self) -> Dict[str, ReputationResult]:
        return {
            node_id: ReputationResult(
                node_id=node_id,
                reputation=state.reputation,
                reliability=state.reliability,
                anomaly_rate=state.anomaly_rate,
            )
            for node_id, state in self._state.nodes.items()
        }

    def _compute_reputation(self, node_state: NodeState) -> float:
        stability = max(0.0, 1.0 - node_state.anomaly_rate)
        return max(0.0, min(1.0, (node_state.reliability * 0.7) + (stability * 0.3)))


__all__ = ["NodeReputationTracker", "ReputationResult"]