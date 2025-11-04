from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.capabilities import (  # noqa: E402
    AdaptiveResponseOrchestrator,
    AnomalyDetector,
    DataIntegrityVerifier,
    DynamicScaler,
    FeedbackReinforcement,
    InMemoryStateReference,
    PolicyEnforcer,
    SituationalAwareness,
    StatelessIntelligenceEngine,
    TelemetryNormalizer,
    ThreatIntelEnricher,
)
from core.state import ARCState
from core.trainer import AdaptiveTrainer


def normalized_identity_event() -> dict[str, object]:
    return {
        "timestamp": "2025-02-01T00:00:00Z",
        "node_id": "AIDA-node-1",
        "framework": "AIDA",
        "metrics": {
            "geo_risk": 2.5,
            "auth_confidence": 88.0,
            "session_anomaly": False,
            "device_reputation": 0.2,
        },
        "identity": {
            "user_hash": "user-1",
            "session_id": "sess-1",
            "behavior_signature": "HIST-1100",
            "device_history": [{"failures": 1}],
        },
        "metadata": {"provider": "okta"},
    }


def normalized_email_event() -> dict[str, object]:
    return {
        "timestamp": "2025-02-01T00:05:00Z",
        "node_id": "AETA-node-9",
        "framework": "AETA",
        "metrics": {
            "heuristic_score": 72.0,
            "dkim_spf_confidence": 0.4,
            "phishing_risk": 80.0,
            "spoofing_likelihood": 0.9,
        },
        "identity": {
            "sender_domain": "malicious.example",
            "recipient_domain": "victim.example",
            "session_anomaly": True,
            "user_hash": "user-1",
        },
        "metadata": {
            "message_id": "msg-1",
            "subject": "Reset password",
        },
    }


def test_stateless_engine_produces_deterministic_digest() -> None:
    engine = StatelessIntelligenceEngine()
    payload = normalized_identity_event()

    first = engine.evaluate([payload], external_state_reference=InMemoryStateReference())[0]
    second = engine.evaluate([payload], external_state_reference=InMemoryStateReference())[0]

    assert first.digest == second.digest
    assert first.snapshot_version is not None
    assert first.decision.fusion.ati_score >= 0.0


def test_dynamic_scaler_maintains_minimum_scaling_agents() -> None:
    scaler = DynamicScaler(minimum_scaling_agents=2)
    directives = scaler.generate(
        [
            {"agent_id": "scale-1", "role": "scaling", "health": "healthy", "cpu": 0.7, "replicas": 1},
            {"agent_id": "scale-2", "role": "scaling", "health": "healthy", "cpu": 0.2, "replicas": 1},
            {"agent_id": "ingest-1", "role": "ingest", "health": "healthy", "cpu": 0.4, "queue_depth": 2},
        ],
        {"cpu": 0.65, "memory": 0.6, "requests_per_second": 850, "capacity": 1000},
    )

    scaling_agents = [
        agent
        for agent_id, agent in directives["agents"].items()
        if agent_id.startswith("scale") and agent["desired_state"] == "active"
    ]
    assert len(scaling_agents) >= 2
    assert directives["cluster"]["action"] in {"scale_up", "hold", "scale_down"}


def test_telemetry_normalization_merges_payloads() -> None:
    normalizer = TelemetryNormalizer()
    normalized = normalizer.normalize(
        [
            {
                "timestamp": "2025-02-02T12:01:00Z",
                "scores": {"heuristic": 65, "phishing": 70},
                "authentication": {"dkim_spf_confidence": 0.5},
                "envelope": {"from_domain": "sender.example", "to_domain": "victim.example"},
                "message_id": "m-123",
            }
        ],
        [
            {
                "timestamp": "2025-02-02T12:01:00Z",
                "auth_confidence": 92,
                "geo_risk": 1.2,
                "identity": {"user_hash": "user-1", "session_id": "s-1"},
            }
        ],
    )

    assert len(normalized) == 2
    frameworks = {entry["framework"] for entry in normalized}
    assert frameworks == {"AETA", "AIDA"}


def test_threat_enrichment_and_response() -> None:
    enricher = ThreatIntelEnricher()
    events = [normalized_email_event()]
    context = enricher.enrich(
        events,
        threat_intel_feeds=[
            {
                "indicators": [
                    {"value": "malicious.example", "severity": 0.8, "confidence": 0.9, "source": "OSINT"}
                ]
            }
        ],
    )

    policy = PolicyEnforcer().apply(
        {"rules": [{"metric": "enrichment_score", "operator": ">=", "value": 60, "action": "force_isolation", "current": context["events"][0]["enrichment_score"]}]},
        {"thresholds": {"enrichment_score": 60}},
    )
    orchestrator = AdaptiveResponseOrchestrator()
    response = orchestrator.orchestrate(context, policy)

    assert response["recommended_action"] == "isolate"
    assert response["severity"] >= 60


def test_anomaly_detector_flags_outliers() -> None:
    detector = AnomalyDetector()
    events = [normalized_identity_event(), normalized_email_event()]
    anomalies = detector.detect(events, {"AETA-node-9": 0.2, "AIDA-node-1": 0.8})
    assert any(entry["node_reputation"] < 0.4 for entry in anomalies)


def test_data_integrity_verifier_computes_hash() -> None:
    verifier = DataIntegrityVerifier()
    messages = [
        {"payload": {"foo": "bar"}},
        {"payload": {"foo": "bar"}, "integrity_hash": "invalid"},
    ]
    results = verifier.verify(messages)
    assert results[0]["verified"] is False
    assert len({entry["calculated_hash"] for entry in results}) == 1


def test_feedback_reinforcement_updates_weights() -> None:
    trainer = AdaptiveTrainer(ARCState())
    reinforcement = FeedbackReinforcement(trainer)
    weights = reinforcement.apply(
        [{"incident_id": "1", "verdict": "benign", "confidence": 0.8}],
        [{"id": "1", "validated": True}],
    )
    assert pytest.approx(weights["identity_weight"] + weights["context_weight"], rel=1e-6) == 1.0


def test_situational_awareness_tracks_degraded_agents() -> None:
    awareness = SituationalAwareness()
    snapshot = awareness.build(
        [
            {"agent_id": "ingest-1", "health": "degraded"},
            {"agent_id": "scale-1", "health": "healthy"},
            {"agent_id": "scale-2", "health": "failed"},
        ],
        {"cpu": 0.45, "memory": 0.5, "network_health": "stable"},
    )
    assert set(snapshot["agents"]["degraded"]) == {"ingest-1"}
    assert "scale-2" in snapshot["agents"]["offline"]