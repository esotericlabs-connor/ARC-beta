# AGENT MANIFEST TEMPLATE — ARC LOGIC AGENTS  
*(Internal Intelligence & Correlation Layer)*

This template defines how **ARC logic agents** operate within the **AETA/AIDA intelligence fabric**.  
These agents don’t live at the edge like SentryID sensors — they exist *inside ARC* to perform cross-domain analysis, pattern correlation, and global model updates.  

ARC agents are responsible for synthesizing data from thousands of external telemetry points and turning it into actionable intelligence.

---

## 1. Metadata

```yaml
agent_name: "CorrelationFusion"
agent_id: "ARC-CORE-001"
framework: "ARC"
version: "0.0.1"
maintainer: "Exoterik Labs"
description: "Performs correlation and confidence weighting between AETA/AIDA telemetry streams for adaptive trust scoring between SentryID and SentryMX. This is pending until both products are working."
language: "Python 3.11"
license: "BSL - Exoterik Labs"
created: "2025-11-01"
```

---

## 2. Core Capabilities

```yaml
capabilities:
  - name: "telemetry_normalization"
    description: >
      Normalizes and merges telemetry from both SentryMX (AETA) and SentryID (AIDA) nodes
      into a unified intelligence schema. Ensures cross-compatibility between message metadata
      (headers, heuristics, domains) and identity data (device, session, credential context).
    input: ["AETA_payloads", "AIDA_payloads"]
    output: "normalized_event_stream"
    mode: "passive"

  - name: "adaptive_trust_fusion"
    description: >
      Dynamically fuses email-based threat data (AETA) and identity-based behavioral data (AIDA)
      to form a comprehensive Adaptive Trust Index (ATI). ARC adjusts the weighting of both
      models in real time based on environment context and global trust trends.
    output: "ati_score (0–100)"
    mode: "analytical"
    adaptive_sources:
      - "SentryMX: heuristic_score, DKIM/SPF confidence"
      - "SentryID: auth_confidence, geo_risk, session_anomaly"

  - name: "node_reputation_analysis"
    description: >
      Calculates trustworthiness and signal consistency across both SentryMX and SentryID agents.
      ARC tracks data fidelity, uptime, and deviation patterns to assign each node a
      dynamic reputation score. High-confidence nodes are prioritized during federated learning
      and model propagation.
    output: "node_reputation_score (0–1)"
    mode: "passive"

  - name: "model_reinforcement"
    description: >
      Continuously retrains shared AETA/AIDA heuristic weights using verified ARC outcomes.
      This allows ARC to adapt to evolving identity patterns (AIDA) and communication tactics (AETA)
      simultaneously. Reinforced weights are redistributed back to agents to maintain alignment.
    output: "updated_model_weights"
    mode: "active"

  - name: "contextual_signal_correlation"
    description: >
      Correlates suspicious login behaviors with concurrent message anomalies to detect
      coordinated account compromise attempts. Enables ARC to link events across both frameworks,
      turning individual anomalies into contextual incidents.
    output: "cross_domain_correlation_map"
    mode: "analytical"

---

## 3. Communication

```yaml
communication:
  protocol: "ZeroMQ over TLS 1.3"
  encryption: "AES-256-GCM + PQC hybrid key exchange READY"
  internal_bus: "arc_core_bus"
  message_format: "protobuf/json hybrid"
  max_latency_ms: 300
```

---

## 4. Data Schema (Internal Telemetry)
```yaml
{
  "timestamp": "2025-11-01T19:45:00Z",
  "node_id": "AIDA-0004",
  "framework": "AIDA",
  "metrics": {
    "geo_risk": 4,
    "session_anomaly": true,
    "auth_confidence": 91
  },
  "email": {
    "spf_result": "pass",
    "dkim_result": "fail",
    "heuristic_score": 74
  },
  "identity": {
    "user_hash": "b7f12f8d1a...",
    "device_id": "WIN-10X-02",
    "asn": "AS13335",
    "geo": "US-WA",
    "login_method": "SAML-OAuth2",
    "session_id": "e8a9c1d2f1...",
    "identity_risk": 0.07,
    "behavior_signature": "HIST-2401"
  },
  "correlation": {
    "combined_ati": 82.4,
    "node_reputation": 0.98,
    "confidence_class": "low-risk",
    "arc_decision_id": "ARC-EVAL-5502"
  }
}
```
---

## 5. Learning Pipeline

```yaml
learning_pipeline:
  model_type: "hybrid heuristic + gradient model"
  update_interval_hours: 3
  weight_aggregation: "federated_average"
  retrain_conditions:
    - "incident_threshold_exceeded"
    - "node_reputation_change > 0.2"
  explainable_ai_enabled: true
```

---

## 6. Internal Security

```yaml
security:
  signature_validation: true
  signed_model_weights: true
  integrity_check_interval_hours: 4
  sandbox_execution: true
  audit_log_retention_days: 30
```

---

## 7. Health States

```yaml
states:
  - READY: "Agent loaded and idle."
  - ANALYZING: "Processing telemetry correlation."
  - TRAINING: "Updating adaptive model weights."
  - DEGRADED: "Data throughput or trust deviation detected."
  - ERROR: "Fault or invalid input; awaiting reset."
```

---

## 8. Example Runtime Stub (Python)

```python
import time, json, random

def correlate(aeta, aida):
    # Example adaptive trust calculation
    return (aeta["heuristic_score"] * 0.6) + (aida["auth_confidence"] * 0.4)

while True:
    sample = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "node_id": "ARC-CORE-001",
        "combined_ati": correlate(
            {"heuristic_score": random.randint(60,95)},
            {"auth_confidence": random.randint(80,99)}
        )
    }
    print(json.dumps(sample, indent=2))
    time.sleep(30)
```

---

## 9. Internal Agents You Can Build

| Agent | Role | Function |
|--------|------|----------|
| **CorrelationFusion** | Analytics | Merges AETA + AIDA signals for global scoring. |
| **ThreatCluster** | Discovery | Identifies repeating attack infrastructure and timing patterns. |
| **NodeTrustKeeper** | Policy | Rates and validates reliability of inbound node data. |
| **ModelTrainer** | Intelligence | Retrains and pushes heuristic weight deltas to edge nodes. |
| **ARCHealthMonitor** | Internal Ops | Tracks node uptime, latency, and packet trust ratios. |

---

## 10. Compliance
All ARC agents must remain **data-agnostic** — they handle telemetry, NEVER content.  
No PII, credentials, or message payloads are processed directly.  
Only derived signals and anonymized vectors are permitted.

---

**Template Version:** 0.1  
**Framework:** ARC (AETA/AIDA Unified)  
**Maintained by:** Exoterik Labs LLC
**Last Updated:** 2025-11-01

## 11. Planned folder structure

ARC/
│
├── README.md
├── LICENSE
├── requirements.txt
├── .env.example
│
├── /core/
│   ├── __init__.py
│   ├── engine.py              # Main adaptive logic loop
│   ├── fusion.py              # Combines AETA + AIDA signals into ATI
│   ├── heuristics.py          # Static + behavioral heuristic models
│   ├── reputation.py          # Node trust and signal fidelity calculations
│   ├── trainer.py             # Model retraining, weight aggregation
│   ├── context.py             # Cross-domain correlation logic
│   └── state.py               # Health, error, and readiness tracking
│
├── /models/
│   ├── __init__.py
│   ├── weights/
│   │   ├── aeta_weights.json
│   │   ├── aida_weights.json
│   │   └── unified_model.json
│   ├── registry.py            # Model version tracking
│   └── reinforcement.py       # Incremental learning and updates
│
├── /telemetry/
│   ├── __init__.py
│   ├── ingestion.py           # Handles inbound JSON payloads
│   ├── normalizer.py          # Converts mixed AETA/AIDA data into common schema
│   ├── schema/
│   │   ├── aeta_schema.json
│   │   ├── aida_schema.json
│   │   └── unified_schema.json
│   └── dispatcher.py          # Sends enriched telemetry to storage or APIs
│
├── /api/
│   ├── __init__.py
│   ├── server.py              # Flask/FastAPI endpoints
│   ├── auth.py                # Token + key management
│   ├── routes/
│   │   ├── health.py
│   │   ├── telemetry.py
│   │   ├── intelligence.py
│   │   └── model.py
│   └── middleware.py          # Rate limits, audit hooks, and encryption
│
├── /agents/
│   ├── __init__.py
│   ├── manifests/
│   │   ├── arc_correlation_agent.yaml
│   │   ├── node_trustkeeper.yaml
│   │   └── model_trainer.yaml
│   └── runners/
│       ├── correlation_fusion.py
│       ├── model_trainer.py
│       └── reputation_monitor.py
│
├── /data/
│   ├── incoming/              # Raw telemetry snapshots
│   ├── processed/             # Normalized and enriched signals
│   ├── logs/
│   │   ├── arc_core.log
│   │   ├── trainer.log
│   │   └── ingestion.log
│   ├── cache/
│   │   ├── temp_vectors/
│   │   └── correlation_maps/
│   └── output/
│       └── adaptive_trust_index.json
│
├── /config/
│   ├── arc.yaml               # Main configuration (ports, tokens, etc.)
│   ├── security.yaml          # Encryption, keys, auth policies
│   ├── telemetry.yaml         # Input source definitions
│   └── learning.yaml          # ML tuning, retrain thresholds
│
├── /scripts/
│   ├── build_docker.sh
│   ├── run_local.sh
│   ├── reset_weights.py
│   └── migrate_schema.py
│
├── /tests/
│   ├── __init__.py
│   ├── test_fusion.py
│   ├── test_ingestion.py
│   ├── test_reputation.py
│   └── test_trainer.py
│
└── /docs/
    ├── AGENTS.md
    ├── API_REFERENCE.md
    ├── SYSTEM_ARCHITECTURE.md
    ├── SECURITY_MODEL.md
    └── ROADMAP.md

