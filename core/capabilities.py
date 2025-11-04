"""ARC capability implementations."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from statistics import mean, pstdev
from typing import Dict, Iterable, Iterator, List, Mapping, Optional, Protocol, Sequence

from .engine import ARCDecision, ARCEngine
from .state import ARCState, AdaptiveWeights, NodeState, TelemetryEvent
from .trainer import AdaptiveTrainer, TrainingFeedback


# ---------------------------------------------------------------------------
# Stateless intelligence engine
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NodeStateSnapshot:
    """Serializable representation of :class:`NodeState`."""

    data: Mapping[str, object]

    def restore(self) -> NodeState:
        return NodeState.from_snapshot(self.data)


@dataclass(frozen=True)
class ExternalStateSnapshot:
    """Snapshot returned by :class:`ExternalStateReference`."""

    weights: AdaptiveWeights
    nodes: Mapping[str, NodeStateSnapshot] = field(default_factory=dict)
    version: Optional[str] = None


class ExternalStateReference(Protocol):
    """Interface used by :class:`StatelessIntelligenceEngine`."""

    def snapshot_for(self, event: TelemetryEvent) -> ExternalStateSnapshot:
        ...

    def commit(self, event: TelemetryEvent, decision: ARCDecision, state: ARCState) -> None:
        ...


@dataclass(frozen=True)
class DeterministicDecision:
    """Deterministic result returned by the stateless engine."""

    decision: ARCDecision
    digest: str
    snapshot_version: Optional[str]

    def as_dict(self) -> Dict[str, object]:
        payload = self.decision.as_dict()
        payload["deterministic_digest"] = self.digest
        if self.snapshot_version is not None:
            payload["snapshot_version"] = self.snapshot_version
        return payload


class InMemoryStateReference:
    """Simple state reference used for testing and local execution."""

    def __init__(
        self,
        *,
        weights: Optional[AdaptiveWeights] = None,
        nodes: Optional[Mapping[str, Mapping[str, object]]] = None,
        version: str = "in-memory",
    ) -> None:
        self._weights = weights.copy() if isinstance(weights, AdaptiveWeights) else AdaptiveWeights()
        self._nodes: Dict[str, Mapping[str, object]] = {}
        if nodes:
            for node_id, snapshot in nodes.items():
                self._nodes[node_id] = dict(snapshot)
        self._version = version

    def snapshot_for(self, event: TelemetryEvent) -> ExternalStateSnapshot:
        nodes = {key: NodeStateSnapshot(data=value) for key, value in self._nodes.items()}
        return ExternalStateSnapshot(weights=self._weights.copy(), nodes=nodes, version=self._version)

    def commit(self, event: TelemetryEvent, decision: ARCDecision, state: ARCState) -> None:
        node_state = state.get_node(event.node_id, event.framework)
        self._nodes[event.node_id] = node_state.snapshot()
        self._weights = state.weights.copy()
        # Track versioning by hashing weights for reproducibility
        serialized = json.dumps(self._weights.__dict__, sort_keys=True).encode("utf-8")
        self._version = hashlib.sha256(serialized).hexdigest()


class StatelessIntelligenceEngine:
    """Executes the ARC pipeline deterministically for each event."""

    def evaluate(
        self,
        normalized_event_stream: Iterable[Mapping[str, object] | TelemetryEvent],
        *,
        external_state_reference: ExternalStateReference,
    ) -> List[DeterministicDecision]:
        decisions: List[DeterministicDecision] = []
        for raw_event in normalized_event_stream:
            if isinstance(raw_event, TelemetryEvent):
                telemetry = raw_event
                payload = telemetry.to_payload()
            else:
                payload = dict(raw_event)
                telemetry = TelemetryEvent.from_payload(payload)

            snapshot = external_state_reference.snapshot_for(telemetry)
            state = self._state_from_snapshot(snapshot)
            engine = ARCEngine(state=state)
            arc_decision = engine.process(payload)
            decision = self._wrap_decision(arc_decision, snapshot)
            decisions.append(decision)
            external_state_reference.commit(telemetry, arc_decision, state)
        return decisions

    def _state_from_snapshot(self, snapshot: ExternalStateSnapshot) -> ARCState:
        state = ARCState()
        state.weights = snapshot.weights.copy()
        for node_id, node_snapshot in snapshot.nodes.items():
            state.nodes[node_id] = node_snapshot.restore()
        return state

    def _wrap_decision(self, decision: ARCDecision, snapshot: ExternalStateSnapshot) -> DeterministicDecision:
        canonical = decision.as_dict()
        failsafe = canonical.get("failsafe")
        if isinstance(failsafe, dict):
            failsafe["issued_at"] = decision.event.timestamp.isoformat()
        serialized = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        digest = hashlib.sha256(serialized).hexdigest()
        return DeterministicDecision(
            decision=decision,
            digest=digest,
            snapshot_version=snapshot.version,
        )


# ---------------------------------------------------------------------------
# Dynamic scaling
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AgentMetric:
    """Normalized metric for an ARC agent."""

    agent_id: str
    role: str
    health: str
    cpu: float
    memory: float
    queue_depth: float
    replicas: int
    priority: int


class DynamicScaler:
    """Evaluates system telemetry to produce scaling directives."""

    def __init__(self, *, minimum_scaling_agents: int = 2) -> None:
        self._minimum_scaling_agents = minimum_scaling_agents

    def generate(
        self,
        agent_health_metrics: Iterable[Mapping[str, object]],
        system_load_telemetry: Mapping[str, object],
    ) -> Mapping[str, object]:
        agents = list(self._normalize_agent_metrics(agent_health_metrics))
        cluster_utilization = self._cluster_utilization(system_load_telemetry)
        cluster_action, reasons = self._cluster_action(cluster_utilization, system_load_telemetry)

        directives: Dict[str, Mapping[str, object]] = {}
        scaling_agents_active = 0
        for metric in agents:
            desired_state, target_replicas, note = self._agent_directive(metric, cluster_action, cluster_utilization)
            if metric.role == "scaling" and desired_state == "active":
                scaling_agents_active += max(1, target_replicas)
            directives[metric.agent_id] = {
                "desired_state": desired_state,
                "target_replicas": target_replicas,
                "current_health": metric.health,
                "notes": note,
            }

        if scaling_agents_active < self._minimum_scaling_agents:
            deficit = self._minimum_scaling_agents - scaling_agents_active
            for metric in sorted(agents, key=lambda item: (-item.priority, item.cpu)):
                if deficit <= 0:
                    break
                if metric.role != "scaling":
                    continue
                directive = directives[metric.agent_id]
                if directive["desired_state"] != "active":
                    directive["desired_state"] = "active"
                    directive["target_replicas"] = max(1, directive["target_replicas"])
                    directive["notes"] = "promoted to maintain redundancy"
                    deficit -= directive["target_replicas"]

        return {
            "cluster": {
                "action": cluster_action,
                "utilization": round(cluster_utilization, 3),
                "reasons": reasons,
            },
            "agents": directives,
        }

    def _normalize_agent_metrics(self, metrics: Iterable[Mapping[str, object]]) -> Iterator[AgentMetric]:
        for item in metrics:
            if not isinstance(item, Mapping):
                continue
            agent_id = str(item.get("agent_id") or item.get("id") or "unknown")
            role = str(item.get("role") or item.get("type") or "generic").lower()
            health = str(item.get("health") or "degraded").lower()
            cpu = float(item.get("cpu", 0.0)) / 100.0 if item.get("cpu", 1.0) > 1 else float(item.get("cpu", 0.0))
            memory = float(item.get("memory", 0.0)) / 100.0 if item.get("memory", 1.0) > 1 else float(item.get("memory", 0.0))
            queue_depth = float(item.get("queue_depth", item.get("pending", 0.0)))
            replicas = int(item.get("replicas", 1) or 1)
            priority = int(item.get("priority", 1) or 1)
            yield AgentMetric(
                agent_id=agent_id,
                role=role,
                health=health,
                cpu=max(0.0, min(cpu, 1.0)),
                memory=max(0.0, min(memory, 1.0)),
                queue_depth=max(0.0, queue_depth),
                replicas=max(1, replicas),
                priority=max(1, priority),
            )

    def _cluster_utilization(self, telemetry: Mapping[str, object]) -> float:
        cpu = float(telemetry.get("cpu", 0.0))
        memory = float(telemetry.get("memory", 0.0))
        requests = float(telemetry.get("requests_per_second", 0.0))
        capacity = float(telemetry.get("capacity", 1.0))
        load = max(cpu, memory)
        if capacity > 0:
            load = max(load, min(1.0, requests / capacity))
        return max(0.0, min(1.0, load))

    def _cluster_action(self, utilization: float, telemetry: Mapping[str, object]) -> tuple[str, Sequence[str]]:
        reasons: List[str] = []
        pending = float(telemetry.get("pending_tasks", 0.0))
        if utilization >= 0.78 or pending >= 50:
            reasons.append("high utilization")
            if pending:
                reasons.append(f"pending_tasks={int(pending)}")
            return "scale_up", reasons
        if utilization <= 0.32 and pending < 5:
            reasons.append("low utilization")
            return "scale_down", reasons
        reasons.append("balanced load")
        return "hold", reasons

    def _agent_directive(
        self,
        metric: AgentMetric,
        cluster_action: str,
        cluster_utilization: float,
    ) -> tuple[str, int, str]:
        if metric.health in {"failed", "offline"}:
            return "suspended", 0, "agent reported failure"

        desired_state = "active"
        note = "within operating range"
        target_replicas = metric.replicas

        if metric.health in {"warning", "degraded"}:
            note = "health degraded; limit workload"
            desired_state = "passive"

        if metric.role == "scaling" and cluster_action == "scale_up":
            target_replicas = max(metric.replicas, 2)
            note = "elevated to absorb load"
        elif cluster_action == "scale_down" and metric.queue_depth < 1:
            desired_state = "passive"
            target_replicas = 1
            note = "scaled down due to low demand"
        elif metric.role != "scaling" and cluster_utilization < 0.35:
            desired_state = "passive"
            note = "cluster underutilized"

        if metric.queue_depth > 15:
            desired_state = "active"
            target_replicas = max(metric.replicas + 1, target_replicas)
            note = "queue backlog detected"

        return desired_state, target_replicas, note


# ---------------------------------------------------------------------------
# Telemetry normalization
# ---------------------------------------------------------------------------


class TelemetryNormalizer:
    """Normalizes AETA and AIDA payloads into ARC's canonical event format."""

    def normalize(
        self,
        aeta_payloads: Iterable[Mapping[str, object]],
        aida_payloads: Iterable[Mapping[str, object]],
    ) -> List[Dict[str, object]]:
        normalized: List[Dict[str, object]] = []
        for payload in aeta_payloads:
            event = self._normalize_aeta(payload)
            if event:
                normalized.append(event)
        for payload in aida_payloads:
            event = self._normalize_aida(payload)
            if event:
                normalized.append(event)
        normalized.sort(key=lambda item: item["timestamp"])
        return normalized

    def _normalize_aeta(self, payload: Mapping[str, object]) -> Optional[Dict[str, object]]:
        if not isinstance(payload, Mapping):
            return None

        timestamp = self._parse_timestamp(
            payload.get("timestamp")
            or payload.get("received_at")
            or payload.get("created_at")
        )
        node_id = str(payload.get("node_id") or payload.get("sensor_id") or "AETA-node")
        scores = payload.get("scores") if isinstance(payload.get("scores"), Mapping) else {}
        auth = payload.get("authentication") if isinstance(payload.get("authentication"), Mapping) else {}
        envelope = payload.get("envelope") if isinstance(payload.get("envelope"), Mapping) else {}
        domain = payload.get("domain_reputation") if isinstance(payload.get("domain_reputation"), Mapping) else {}

        metrics = {
            "heuristic_score": float(scores.get("heuristic", 0.0)),
            "dkim_spf_confidence": float(auth.get("dkim_spf_confidence", 0.0)),
            "phishing_risk": float(scores.get("phishing", domain.get("risk", 0.0))),
            "spoofing_likelihood": float(scores.get("spoof", 0.0)),
        }

        identity = {
            "sender_domain": envelope.get("from_domain") or payload.get("sender_domain"),
            "recipient_domain": envelope.get("to_domain") or payload.get("recipient_domain"),
            "session_anomaly": bool(payload.get("session_anomaly", False)),
            "user_hash": payload.get("user_hash"),
        }

        metadata = {
            "message_id": payload.get("message_id"),
            "subject": payload.get("subject"),
            "headers": payload.get("headers", {}),
            "threat_tags": payload.get("threat_tags", []),
        }

        return {
            "timestamp": timestamp.isoformat(),
            "node_id": node_id,
            "framework": "AETA",
            "metrics": metrics,
            "identity": identity,
            "metadata": metadata,
        }

    def _normalize_aida(self, payload: Mapping[str, object]) -> Optional[Dict[str, object]]:
        if not isinstance(payload, Mapping):
            return None

        timestamp = self._parse_timestamp(payload.get("timestamp") or payload.get("event_time"))
        node_id = str(payload.get("node_id") or payload.get("device_id") or "AIDA-node")
        metrics = {
            "geo_risk": float(payload.get("geo_risk", payload.get("location_risk", 0.0))),
            "auth_confidence": float(payload.get("auth_confidence", payload.get("mfa_confidence", 0.0))),
            "session_anomaly": bool(payload.get("session_anomaly", False)),
            "device_reputation": float(payload.get("device_reputation", 0.0)),
        }
        identity_payload = payload.get("identity") if isinstance(payload.get("identity"), Mapping) else {}
        identity = {
            "user_hash": identity_payload.get("user_hash") or payload.get("user_hash"),
            "session_id": identity_payload.get("session_id") or payload.get("session_id"),
            "behavior_signature": identity_payload.get("behavior_signature") or payload.get("behavior_signature"),
            "device_history": identity_payload.get("device_history") or payload.get("device_history", []),
        }
        metadata = {
            "tenant_id": payload.get("tenant_id"),
            "provider": payload.get("provider"),
            "signals": payload.get("signals", {}),
        }
        return {
            "timestamp": timestamp.isoformat(),
            "node_id": node_id,
            "framework": "AIDA",
            "metrics": metrics,
            "identity": identity,
            "metadata": metadata,
        }

    def _parse_timestamp(self, value: object) -> datetime:
        if isinstance(value, datetime):
            return value
        if isinstance(value, (int, float)):
            return datetime.utcfromtimestamp(float(value))
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                pass
        return datetime.utcnow()


# ---------------------------------------------------------------------------
# Threat intelligence enrichment
# ---------------------------------------------------------------------------


class ThreatIntelEnricher:
    """Enriches telemetry with threat intelligence overlays."""

    def enrich(
        self,
        normalized_event_stream: Iterable[Mapping[str, object]],
        threat_intel_feeds: Iterable[Mapping[str, object]],
    ) -> Mapping[str, object]:
        feed_index = self._index_feeds(threat_intel_feeds)
        enriched_events: List[Mapping[str, object]] = []
        for event in normalized_event_stream:
            matches = self._match_event(event, feed_index)
            base_score = float(event.get("metrics", {}).get("heuristic_score", 0.0))
            boost = sum(match["confidence"] * match["severity"] for match in matches)
            enriched_events.append(
                {
                    "event": event,
                    "matched_indicators": matches,
                    "enrichment_score": round(min(100.0, base_score + boost), 2),
                }
            )
        return {
            "feeds_indexed": len(feed_index["indicators"]),
            "feeds_version": feed_index["version"],
            "events": enriched_events,
        }

    def _index_feeds(self, feeds: Iterable[Mapping[str, object]]) -> Mapping[str, object]:
        indicators: List[Mapping[str, object]] = []
        version_digest = hashlib.sha256()
        for feed in feeds:
            if not isinstance(feed, Mapping):
                continue
            for indicator in feed.get("indicators", []):
                if isinstance(indicator, Mapping) and indicator.get("value"):
                    indicators.append(indicator)
                    version_digest.update(str(indicator).encode("utf-8"))
        return {"indicators": indicators, "version": version_digest.hexdigest()}

    def _match_event(self, event: Mapping[str, object], feed_index: Mapping[str, object]) -> List[Mapping[str, object]]:
        matches: List[Mapping[str, object]] = []
        metadata = event.get("metadata", {}) if isinstance(event.get("metadata"), Mapping) else {}
        identity = event.get("identity", {}) if isinstance(event.get("identity"), Mapping) else {}
        candidate_values = {
            str(metadata.get("message_id")),
            str(metadata.get("subject")),
            str(identity.get("sender_domain")),
            str(identity.get("user_hash")),
        }
        for indicator in feed_index.get("indicators", []):
            value = str(indicator.get("value"))
            if value in candidate_values:
                matches.append(
                    {
                        "value": value,
                        "type": indicator.get("type", "unknown"),
                        "severity": float(indicator.get("severity", 1.0)),
                        "confidence": float(indicator.get("confidence", 0.5)),
                        "source": indicator.get("source", "unknown"),
                    }
                )
        return matches


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------


class AnomalyDetector:
    """Performs unsupervised anomaly detection across telemetry."""

    def detect(
        self,
        normalized_event_stream: Iterable[Mapping[str, object]],
        node_reputation_scores: Mapping[str, float],
    ) -> List[Mapping[str, object]]:
        signals: List[float] = []
        events: List[Mapping[str, object]] = []
        for event in normalized_event_stream:
            metrics = event.get("metrics", {}) if isinstance(event.get("metrics"), Mapping) else {}
            signal = float(metrics.get("heuristic_score") or metrics.get("geo_risk") or 0.0)
            signals.append(signal)
            events.append(event)
        if not signals:
            return []
        average = mean(signals)
        deviation = pstdev(signals) if len(signals) > 1 else 0.0
        anomalies: List[Mapping[str, object]] = []
        for event, signal in zip(events, signals):
            node_id = str(event.get("node_id", "unknown"))
            reputation = float(node_reputation_scores.get(node_id, 0.5))
            if deviation == 0.0:
                z_score = 0.0
            else:
                z_score = (signal - average) / deviation
            if abs(z_score) > 2.5 or reputation < 0.35:
                anomalies.append(
                    {
                        "event": event,
                        "z_score": round(z_score, 4),
                        "node_reputation": round(reputation, 3),
                    }
                )
        return anomalies


# ---------------------------------------------------------------------------
# Policy enforcement
# ---------------------------------------------------------------------------


class PolicyEnforcer:
    """Applies policy directives against master configuration."""

    def apply(self, incident_policy: Mapping[str, object], master_config: Mapping[str, object]) -> Mapping[str, object]:
        evaluated: List[Mapping[str, object]] = []
        active_actions: List[str] = []
        rules = incident_policy.get("rules", []) if isinstance(incident_policy.get("rules"), Sequence) else []
        thresholds = master_config.get("thresholds", {}) if isinstance(master_config.get("thresholds"), Mapping) else {}
        for rule in rules:
            if not isinstance(rule, Mapping) or not rule.get("enabled", True):
                continue
            metric = str(rule.get("metric"))
            operator = str(rule.get("operator", ">=")).strip()
            value = float(rule.get("value", thresholds.get(metric, 0.0)))
            default = float(thresholds.get(metric, value))
            actual = float(rule.get("current", default))
            satisfied = self._evaluate(operator, actual, value)
            evaluated.append(
                {
                    "metric": metric,
                    "operator": operator,
                    "expected": value,
                    "observed": actual,
                    "satisfied": satisfied,
                }
            )
            if satisfied and rule.get("action"):
                active_actions.append(str(rule["action"]))
        return {
            "effective_version": incident_policy.get("version"),
            "rules_evaluated": evaluated,
            "actions": active_actions,
        }

    def _evaluate(self, operator: str, actual: float, expected: float) -> bool:
        match operator:
            case ">=" | "=>":
                return actual >= expected
            case "<=" | "=<":
                return actual <= expected
            case ">":
                return actual > expected
            case "<":
                return actual < expected
            case "==" | "=":
                return actual == expected
        return False


# ---------------------------------------------------------------------------
# Data integrity verification
# ---------------------------------------------------------------------------


class DataIntegrityVerifier:
    """Validates integrity of inter-agent payloads using cryptographic hashes."""

    def verify(self, all_agent_streams: Iterable[Mapping[str, object]]) -> List[Mapping[str, object]]:
        verified: List[Mapping[str, object]] = []
        for message in all_agent_streams:
            if not isinstance(message, Mapping):
                continue
            payload = message.get("payload") if isinstance(message.get("payload"), Mapping) else message
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            digest = hashlib.sha256(canonical).hexdigest()
            expected = str(message.get("integrity_hash") or message.get("hash") or "")
            verified.append(
                {
                    "payload": payload,
                    "calculated_hash": digest,
                    "verified": bool(expected) and digest == expected,
                }
            )
        return verified


# ---------------------------------------------------------------------------
# Situational awareness
# ---------------------------------------------------------------------------


class SituationalAwareness:
    """Synthesizes agent and system telemetry into an environmental map."""

    def build(
        self,
        agent_health_metrics: Iterable[Mapping[str, object]],
        system_telemetry: Mapping[str, object],
    ) -> Mapping[str, object]:
        agents = list(agent_health_metrics)
        degraded = [agent for agent in agents if str(agent.get("health", "")).lower() in {"warning", "degraded"}]
        offline = [agent for agent in agents if str(agent.get("health", "")).lower() in {"offline", "failed"}]
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "system": {
                "cpu": system_telemetry.get("cpu", 0.0),
                "memory": system_telemetry.get("memory", 0.0),
                "latency_ms": system_telemetry.get("latency_ms", 0.0),
                "network_health": system_telemetry.get("network_health", "stable"),
            },
            "agents": {
                "total": len(agents),
                "degraded": [agent.get("agent_id") or agent.get("id") for agent in degraded],
                "offline": [agent.get("agent_id") or agent.get("id") for agent in offline],
            },
        }


# ---------------------------------------------------------------------------
# Adaptive response orchestration
# ---------------------------------------------------------------------------


class AdaptiveResponseOrchestrator:
    """Coordinates response actions using threat context and policy outputs."""

    def orchestrate(
        self,
        enriched_threat_context: Mapping[str, object],
        policy_enforcement_result: Mapping[str, object],
    ) -> Mapping[str, object]:
        events = enriched_threat_context.get("events", [])
        policy_actions = policy_enforcement_result.get("actions", [])
        severity = 0.0
        triggers: List[str] = []
        for event in events:
            enrichment = float(event.get("enrichment_score", 0.0))
            severity = max(severity, enrichment)
            for indicator in event.get("matched_indicators", []):
                triggers.append(f"indicator:{indicator.get('value')}")
        if severity >= 80.0:
            response = "isolate"
        elif severity >= 50.0:
            response = "contain"
        else:
            response = "monitor"
        if "force_isolation" in policy_actions:
            response = "isolate"
        elif "open_case" in policy_actions and response == "monitor":
            response = "investigate"
        return {
            "recommended_action": response,
            "severity": round(severity, 2),
            "triggers": triggers,
            "policy_actions": policy_actions,
        }


# ---------------------------------------------------------------------------
# Feedback reinforcement
# ---------------------------------------------------------------------------


class FeedbackReinforcement:
    """Incorporates analyst feedback into ARC training weights."""

    def __init__(self, trainer: AdaptiveTrainer) -> None:
        self._trainer = trainer

    def apply(
        self,
        user_feedback: Iterable[Mapping[str, object]],
        validated_incidents: Iterable[Mapping[str, object]],
    ) -> Mapping[str, float]:
        validated = {incident.get("id") for incident in validated_incidents if incident.get("validated", True)}
        for feedback in user_feedback:
            if not isinstance(feedback, Mapping):
                continue
            incident_id = feedback.get("incident_id")
            if incident_id not in validated:
                continue
            verdict = str(feedback.get("verdict", "review")).lower()
            confidence = float(feedback.get("confidence", 0.5))
            expected = {
                "malicious": 90.0,
                "benign": 15.0,
                "trusted": 20.0,
                "review": 50.0,
            }.get(verdict, 50.0)
            self._trainer.register_feedback(
                TrainingFeedback(verdict=verdict, confidence=max(0.0, min(confidence, 1.0)), expected_risk=expected)
            )
        return self._trainer.export_weights()


__all__ = [
    "AdaptiveResponseOrchestrator",
    "AdaptiveTrainer",
    "AnomalyDetector",
    "DataIntegrityVerifier",
    "DeterministicDecision",
    "DynamicScaler",
    "ExternalStateReference",
    "FeedbackReinforcement",
    "InMemoryStateReference",
    "PolicyEnforcer",
    "SituationalAwareness",
    "StatelessIntelligenceEngine",
    "TelemetryNormalizer",
    "ThreatIntelEnricher",
]