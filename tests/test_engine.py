from __future__ import annotations
from copy import deepcopy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.engine import ARCEngine


def build_payload(**overrides):
    payload = {
        "timestamp": "2025-01-01T00:00:00Z",
        "node_id": "AIDA-0001",
        "framework": "AIDA",
        "metrics": {
            "geo_risk": 3,
            "session_anomaly": True,
            "auth_confidence": 65,
            "trust_delta": -5,
        },
        "identity": {
            "user_hash": "abc123",
            "session_id": "session-1",
            "behavior_signature": "HIST-2401",
            "device_history": [
                {"device": "ios", "failures": 2},
                {"device": "mac", "failures": 1},
            ],
            "session_anomaly": True,
        },
        "metadata": {},
    }
    payload.update(overrides)
    return payload


def test_engine_process_generates_decision():
    engine = ARCEngine()
    decision = engine.process(build_payload())

    assert 0.0 <= decision.fusion.risk_score <= 100.0
    assert decision.fusion.verdict in {"trusted", "review", "malicious"}
    assert 0.0 <= decision.fusion.context_risk <= 100.0
    assert decision.reputation.node_id == "AIDA-0001"
    assert decision.correlation is None
    assert decision.failsafe.action == "monitor"

    # Second event with same actor triggers correlation window
    follow_up = build_payload(timestamp="2025-01-01T00:05:00Z")
    second_decision = engine.process(follow_up)
    assert second_decision.correlation is not None
    assert "user:abc123" in second_decision.correlation.actors


def test_feedback_updates_weights():
    engine = ARCEngine()
    initial_weights = deepcopy(engine.state.weights)

    payload = build_payload(
        metadata={
            "feedback_verdict": "benign",
            "feedback_confidence": 0.9,
        },
        metrics={
            "geo_risk": 1,
            "session_anomaly": False,
            "auth_confidence": 92,
        },
    )
    engine.process(payload)

    updated = engine.state.weights
    # We expect identity weight to shift slightly towards benign feedback
    assert abs(updated.identity_weight - initial_weights.identity_weight) > 0
    assert round(updated.context_weight + updated.identity_weight, 5) == 1.0


def test_failsafe_triggers_self_destruct_for_intrusion():
    engine = ARCEngine()
    payload = build_payload(
        metrics={
            "geo_risk": 7,
            "session_anomaly": True,
            "auth_confidence": 12,
            "trust_delta": -35,
            "intrusion_detected": True,
            "ssh_bruteforce_count": 12,
        },
        identity={
            "user_hash": "threat-actor",
            "session_id": "malicious-session",
            "behavior_signature": "HIST-9999",
            "device_history": [{"device": "unknown", "failures": 9}],
            "tamper_detected": True,
        },
        metadata={
            "intrusion_type": "ssh_bruteforce",
            "cluster_name": "cluster-alpha",
            "protected_resources": [
                {"id": "container-api-1", "type": "docker", "location": "gke-edge"},
                {"id": "cluster-alpha", "type": "kubernetes-cluster", "location": "us-east1"},
            ],
        },
    )

    decision = engine.process(payload)

    assert decision.failsafe.action == "self_destruct"
    assert decision.failsafe.triggered is True
    assert decision.failsafe.severity >= decision.fusion.risk_score
    assert any(
        resource.identifier == "container-api-1" for resource in decision.failsafe.resources
    )
    assert "ssh_bruteforce" in decision.failsafe.reason.lower()