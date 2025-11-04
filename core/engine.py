"""ARC orchestration engine."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional

from .context import ContextCorrelator, CorrelationResult
from .failsafe import FailsafeDirective, FailsafeManager
from .fusion import AdaptiveFusion, FusionResult
from .heuristics import HeuristicEngine
from .reputation import NodeReputationTracker, ReputationResult
from .state import ARCState, TelemetryEvent
from .trainer import AdaptiveTrainer


@dataclass
class ARCDecision:
    """Full decision artifact returned by :class:`ARCEngine`."""

    event: TelemetryEvent
    fusion: FusionResult
    reputation: ReputationResult
    correlation: Optional[CorrelationResult]
    failsafe: FailsafeDirective

    def as_dict(self) -> dict[str, object]:
        payload = {
            "event": {
                "timestamp": self.event.timestamp.isoformat(),
                "node_id": self.event.node_id,
                "framework": self.event.framework,
            },
            "fusion": self.fusion.as_dict(),
            "reputation": self.reputation.as_dict(),
            "failsafe": self.failsafe.as_dict(),
        }
        if self.correlation is not None:
            payload["correlation"] = self.correlation.as_dict()
        return payload


class ARCEngine:
    """High-level adaptive pipeline orchestrating ARC core logic."""

    def __init__(self, *, state: Optional[ARCState] = None) -> None:
        self.state = state or ARCState()
        self.heuristics = HeuristicEngine(self.state)
        self.fusion = AdaptiveFusion(self.state)
        self.reputation = NodeReputationTracker(self.state)
        self.context = ContextCorrelator()
        self.trainer = AdaptiveTrainer(self.state)
        self.failsafe = FailsafeManager()

    def process(self, payload: Mapping[str, object]) -> ARCDecision:
        event = TelemetryEvent.from_payload(payload)
        node_state = self.state.get_node(event.node_id, event.framework)

        bundle = self.heuristics.run(event)
        fusion_result = self.fusion.fuse(
            event,
            context_signals=bundle.context_signals,
            identity_signals=bundle.identity_signals,
            node_reputation=node_state.reputation,
        )

        self.state.record_risk(fusion_result.risk_score)

        reputation_result = self.reputation.update(
            event,
            risk_score=fusion_result.risk_score,
            verdict=fusion_result.verdict,
        )

        correlation = self.context.record(
            event,
            risk_score=fusion_result.risk_score,
            verdict=fusion_result.verdict,
            signals=fusion_result.signals,
        )

        self.trainer.update_from_event(
            event,
            risk_score=fusion_result.risk_score,
            verdict=fusion_result.verdict,
        )

        failsafe_directive = self.failsafe.evaluate(
            event,
            risk_score=fusion_result.risk_score,
            verdict=fusion_result.verdict,
        )

        return ARCDecision(
            event=event,
            fusion=fusion_result,
            reputation=reputation_result,
            correlation=correlation,
            failsafe=failsafe_directive,
        )
    
    
__all__ = ["ARCEngine", "ARCDecision"]