"""Core state definitions for the Adaptive Respond Core (ARC)."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Deque, Dict, Iterable, Mapping


@dataclass
class Signal:
    """Represents the contribution of a heuristic signal to the risk model."""

    name: str
    score: float
    weight: float
    context: Dict[str, float | int | str | bool] = field(default_factory=dict)

    def weighted_score(self) -> float:
        """Return the weighted score used for fusion."""

        return self.score * self.weight


@dataclass
class TelemetryEvent:
    """Normalized telemetry payload consumed by ARC."""

    timestamp: datetime
    node_id: str
    framework: str
    metrics: Mapping[str, float | int | bool]
    email: Mapping[str, object]
    identity: Mapping[str, object]
    metadata: Mapping[str, object]

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> "TelemetryEvent":
        """Build a :class:`TelemetryEvent` from heterogeneous payload formats."""

        timestamp_raw = payload.get("timestamp")
        if isinstance(timestamp_raw, datetime):
            timestamp = timestamp_raw
        elif isinstance(timestamp_raw, str):
            timestamp = datetime.fromisoformat(timestamp_raw.replace("Z", "+00:00"))
        else:
            timestamp = datetime.utcnow()

        node_id = str(payload.get("node_id") or payload.get("node") or "unknown")
        framework = str(payload.get("framework") or payload.get("source") or "unknown").upper()

        metrics = _ensure_mapping(payload.get("metrics"))
        email = _ensure_mapping(payload.get("email"))
        identity = _ensure_mapping(payload.get("identity"))
        metadata = _ensure_mapping(payload.get("metadata"))

        return cls(
            timestamp=timestamp,
            node_id=node_id,
            framework=framework,
            metrics=metrics,
            email=email,
            identity=identity,
            metadata=metadata,
        )


def _ensure_mapping(value: object) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return value
    if value is None:
        return {}
    if isinstance(value, list):
        # Accept legacy key/value list structures
        return {str(item[0]): item[1] for item in value if isinstance(item, Iterable) and len(item) == 2}
    return {}


@dataclass
class AdaptiveWeights:
    """Mutable weighting strategy shared across ARC components."""

    email_weight: float = 0.55
    identity_weight: float = 0.45
    reputation_bias: float = 0.1

    def normalize(self) -> None:
        total = max(self.email_weight + self.identity_weight, 1e-9)
        self.email_weight /= total
        self.identity_weight /= total


@dataclass
class NodeState:
    """State tracked per contributing node."""

    node_id: str
    framework: str
    last_seen: datetime
    reputation: float = 0.5
    reliability: float = 0.5
    anomaly_rate: float = 0.0
    history: Deque[float] = field(default_factory=lambda: deque(maxlen=100))

    def record_observation(self, risk_score: float, verdict: str) -> None:
        self.last_seen = datetime.utcnow()
        self.history.append(risk_score)
        deviation = abs(risk_score - self.average_risk())
        self.anomaly_rate = min(1.0, (self.anomaly_rate * 0.9) + (deviation / 100.0) * 0.1)
        confidence = 1.0 if verdict == "malicious" else 0.75 if verdict == "review" else 0.5
        self.reliability = max(0.0, min(1.0, (self.reliability * 0.85) + (confidence * 0.15)))

    def average_risk(self) -> float:
        if not self.history:
            return 50.0
        return sum(self.history) / len(self.history)


@dataclass
class ARCState:
    """Global mutable state for the ARC engine."""

    weights: AdaptiveWeights = field(default_factory=AdaptiveWeights)
    nodes: Dict[str, NodeState] = field(default_factory=dict)
    global_risk_history: Deque[float] = field(default_factory=lambda: deque(maxlen=500))

    def get_node(self, node_id: str, framework: str) -> NodeState:
        if node_id not in self.nodes:
            self.nodes[node_id] = NodeState(node_id=node_id, framework=framework, last_seen=datetime.utcnow())
        return self.nodes[node_id]

    def record_risk(self, risk_score: float) -> None:
        self.global_risk_history.append(risk_score)

    def average_global_risk(self) -> float:
        if not self.global_risk_history:
            return 50.0
        return sum(self.global_risk_history) / len(self.global_risk_history)


__all__ = [
    "Signal",
    "TelemetryEvent",
    "AdaptiveWeights",
    "NodeState",
    "ARCState",
]