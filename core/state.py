from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from datetime import datetime
from typing import Deque, Dict, Iterable, Mapping


__all__ = [
    "Signal",
    "TelemetryEvent",
    "AdaptiveWeights",
    "NodeState",
    "ARCState",
]

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
        identity = _ensure_mapping(payload.get("identity"))
        metadata = _ensure_mapping(payload.get("metadata"))

        return cls(
            timestamp=timestamp,
            node_id=node_id,
            framework=framework,
            metrics=metrics,
            identity=identity,
            metadata=metadata,
        )

    def to_payload(self) -> Dict[str, object]:
        """Serialize the telemetry event back into a normalized mapping."""

        return {
            "timestamp": self.timestamp.isoformat(),
            "node_id": self.node_id,
            "framework": self.framework,
            "metrics": dict(self.metrics),
            "identity": dict(self.identity),
            "metadata": dict(self.metadata),
        }



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

    context_weight: float = 0.4
    identity_weight: float = 0.6
    reputation_bias: float = 0.1

    def normalize(self) -> None:
        total = max(self.context_weight + self.identity_weight, 1e-9)
        self.context_weight /= total
        self.identity_weight /= total

    def copy(self) -> "AdaptiveWeights":
        return AdaptiveWeights(
            context_weight=self.context_weight,
            identity_weight=self.identity_weight,
            reputation_bias=self.reputation_bias,
        )



@dataclass
class NodeState:
    """State tracked per contributing node."""

    node_id: str
    framework: str
    last_seen: datetime
    reputation: float = 0.5
    reliability: float = 0.5
    data_fidelity: float = 1.0
    uptime_hours: float = 0.0
    total_events: int = 0
    anomaly_rate: float = 0.0
    history: Deque[float] = field(default_factory=lambda: deque(maxlen=100))

    def record_observation(self, event_time: datetime, risk_score: float, verdict: str) -> None:
        event_dt = event_time if event_time.tzinfo else event_time.replace(tzinfo=timezone.utc)
        last_seen = self.last_seen if self.last_seen.tzinfo else self.last_seen.replace(tzinfo=timezone.utc)
        delta = max(0.0, (event_dt - last_seen).total_seconds() / 3600.0)
        if delta:
            self.uptime_hours += delta
        self.last_seen = event_dt
        previous_average = self.average_risk()
    def record_observation(self, risk_score: float, verdict: str) -> None:
        self.last_seen = datetime.utcnow()
        self.history.append(risk_score)
        self.total_events += 1
        deviation = abs(risk_score - self.average_risk())
        self.anomaly_rate = min(1.0, (self.anomaly_rate * 0.88) + (deviation / 100.0) * 0.12)
        if verdict == "malicious":
            confidence = 1.0
        elif verdict == "review":
            confidence = 0.75
        else:
            confidence = 0.55
        self.reliability = max(0.0, min(1.0, (self.reliability * 0.84) + (confidence * 0.16)))

        fidelity_penalty = min(0.6, deviation / 140.0)

        self.data_fidelity = max(
            0.0,
            min(1.0, (self.data_fidelity * 0.9) + (1.0 - fidelity_penalty) * 0.1),
        )

    def average_risk(self) -> float:
        if not self.history:
            return 0.0
        return sum(self.history) / len(self.history)
    
    def snapshot(self) -> Dict[str, object]:
        return {
            "node_id": self.node_id,
            "framework": self.framework,
            "last_seen": self.last_seen,
            "reputation": self.reputation,
            "reliability": self.reliability,
            "anomaly_rate": self.anomaly_rate,
            "data_fidelity": self.data_fidelity,
            "uptime_hours": self.uptime_hours,
            "total_events": self.total_events,
            "history": tuple(self.history),
        }

    @classmethod
    def from_snapshot(cls, snapshot: Mapping[str, object]) -> "NodeState":
        history_values = snapshot.get("history")
        history_deque: Deque[float]
        if isinstance(history_values, Iterable):
            history_deque = deque(float(value) for value in history_values)
            history_deque = deque(history_deque, maxlen=100)
        else:
            history_deque = deque(maxlen=100)

        last_seen = snapshot.get("last_seen")
        if isinstance(last_seen, datetime):
            timestamp = last_seen if last_seen.tzinfo else last_seen.replace(tzinfo=timezone.utc)
        elif isinstance(last_seen, str):
            timestamp = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
        else:
            timestamp = datetime.now(tz=timezone.utc)

        return cls(
            node_id=str(snapshot.get("node_id", "unknown")),
            framework=str(snapshot.get("framework", "unknown")),
            last_seen=timestamp,
            reputation=float(snapshot.get("reputation", 0.5)),
            reliability=float(snapshot.get("reliability", 0.5)),
            anomaly_rate=float(snapshot.get("anomaly_rate", 0.0)),
            data_fidelity=float(snapshot.get("data_fidelity", 1.0)),
            uptime_hours=float(snapshot.get("uptime_hours", 0.0)),
            total_events=int(snapshot.get("total_events", 0)),
            history=history_deque,
        )


@dataclass
class ARCState:
    """Global coordinator state shared across ARC components."""

    weights: AdaptiveWeights = field(default_factory=AdaptiveWeights)
    nodes: Dict[str, NodeState] = field(default_factory=dict)
    global_risk_history: Deque[float] = field(default_factory=lambda: deque(maxlen=500))
    trust_index_history: Deque[float] = field(default_factory=lambda: deque(maxlen=500))

    def get_node(self, node_id: str, framework: str) -> NodeState:
        if node_id not in self.nodes:
            self.nodes[node_id] = NodeState(
                node_id=node_id,
                framework=framework,
                last_seen=datetime.now(tz=timezone.utc),
            )
        return self.nodes[node_id]

    def record_risk(self, risk_score: float) -> None:
        self.global_risk_history.append(risk_score)

    def record_trust(self, ati_score: float) -> None:
        self.trust_index_history.append(ati_score)

    def average_global_risk(self) -> float:
        if not self.global_risk_history:
            return 50.0
        return sum(self.global_risk_history) / len(self.global_risk_history)
    
    def trust_trend(self) -> float:
        if len(self.trust_index_history) < 2:
            return 0.0
        recent = list(self.trust_index_history)[-10:]
        delta = recent[-1] - recent[0]
        return delta / max(len(recent) - 1, 1)




__all__ = [
    "Signal",
    "TelemetryEvent",
    "AdaptiveWeights",
    "NodeState",
    "ARCState",
]