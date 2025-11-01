# ARC Method — Development Reference

## Overview
The **ARC Method** defines how Exoterik Labs’ Adaptive Relay Core functions as the unified intelligence framework that connects and powers both **AETA** and **AIDA**.  
ARC isn’t just a system — it’s a living method of trust determination.  

**AETA (Adaptive Email Threat Analysis)** governs message-level authenticity, mailflow behavior, and network context.  
**AIDA (Adaptive ID Analysis)** governs user identity, behavioral integrity, and authentication context.  
ARC fuses them into one adaptive model that learns across both disciplines — communication and identity — under a single process.

> **AETA + AIDA = The ARC Method.**

---

## Purpose
The ARC Method’s goal is to interpret **intent through context**.  
It doesn’t just look for malicious patterns — it studies *why* a signal deviates, *who* it connects to, and *how* those deviations correlate across systems.  

By merging AETA and AIDA telemetry, ARC learns the rhythm of trust — continuously adapting to both human and system behavior in real time.

---

## Core Philosophy
- **Privacy-First:** ARC never consumes raw data, only encrypted or anonymized telemetry vectors.  
- **Adaptive by Design:** Every signal influences a shared model — self-correcting with each new learning cycle.  
- **Explainable:** Every verdict is logged, reasoned, and reproducible.  
- **Zero-Trust Core:** ARC itself authenticates every node before accepting telemetry or applying model updates.  
- **Cross-Domain Awareness:** Identity and communication are treated as two halves of one behavioral landscape.  

---

## Method Steps

### 1. Telemetry Normalization
ARC ingests telemetry streams from SentryMX (AETA) and SentryID (AIDA).  
Each input is normalized into a unified schema containing:
- **Email Context** – SPF/DKIM/DMARC, header fingerprinting, heuristic confidence, and domain entropy.  
- **Identity Context** – login source, session integrity, device fingerprint, geo drift, and credential freshness.  
- **Node Context** – node reputation, environment ID, and signal trust weighting.

Output → `normalized_event_stream`

---

### 2. Adaptive Trust Fusion
ARC calculates the **Adaptive Trust Index (ATI)** — the central numeric representation of context-driven trust.  
It fuses AETA and AIDA confidence vectors using a weighted model:

```
ATI = (AETA_confidence * w_aeta) + (AIDA_confidence * w_aida) ± context_delta
```

- `w_aeta` and `w_aida` are adaptive weights determined by signal reliability.
- `context_delta` adjusts for anomalies like login-to-message timing or geo variance.

ARC continuously recalibrates these weights as new intelligence and verified incidents emerge.

---

### 3. Node Reputation Analysis
Each node — whether SentryMX (email) or SentryID (identity) — is given a **Node Reputation Score (NRS)** from 0 to 1.  
This score determines the influence of its data on global learning.

ARC evaluates nodes based on:
- Telemetry accuracy and consistency
- Reported data latency
- Correlation reliability (alignment with other nodes)
- False-positive history

High-trust nodes accelerate learning. Low-trust nodes are quarantined or retrained.

---

### 4. Contextual Signal Correlation
ARC continuously cross-references events across AETA and AIDA to detect linked behaviors.

Examples:
- AIDA reports a login from a new device; AETA sees outbound mail from that identity within five minutes.  
- SPF passes, but the sender’s identity fingerprint fails — likely compromised credentials.  
- AIDA geo-trust declines; AETA registers abnormal message timing or volume.  

Output → `cross_domain_correlation_map`  
This map represents how identity and message events co-relate through time and behavior.

---

### 5. Model Reinforcement
ARC retrains its heuristic and adaptive models using confirmed incident data.  
Once ARC validates patterns or responses as correct, it reinforces those weightings.  

Adjustments include:
- Updating trust decay thresholds  
- Reweighting correlations between AETA and AIDA signals  
- Expanding edge heuristics for unseen patterns  

Model updates are signed, versioned, and securely redistributed to connected nodes.

---

### 6. Federated Learning Layer
ARC learns globally, but teaches locally.  
Nodes (AETA and AIDA) train their local heuristics and send anonymized learning deltas back to ARC.  
ARC aggregates and harmonizes those deltas — forming a stronger, adaptive base model that is then pushed to all connected systems.

This ensures that ARC grows more intelligent with each networked deployment — without ever collecting private data.

---

## Output Artifacts

| Artifact | Description |
|-----------|-------------|
| **adaptive_trust_index.json** | Unified AETA/AIDA confidence model output |
| **cross_domain_correlation_map.json** | Relationships between identity and communication anomalies |
| **node_reputation_table.json** | Dynamic trust weights per node |
| **model_weights/** | Signed and versioned heuristic/ML model parameters |
| **arc_decision_log.json** | Full context and reasoning trail for each adaptive decision |

---

## Example Flow
1. AIDA detects anomalous login from a non-standard device.  
2. AETA observes outbound messages from that same identity with altered tone and timing.  
3. Both events reach ARC simultaneously.  
4. ARC normalizes both, detects correlation, and lowers the global trust weight for that sender.  
5. Reinforcement logic updates the model, learning that this behavior pattern represents compromise.  
6. Future signals from similar sources trigger early defensive actions at the node level.

---

## Directory Philosophy
ARC’s architecture is intentionally modular and transparent:

```
/core        → adaptive fusion, correlation, and reasoning logic  
/telemetry   → data normalization, ingestion, and signal validation  
/models      → learning weight storage and model versioning  
/api         → telemetry intake, intelligence queries, and updates  
/agents      → internal correlation and training daemons  
/data        → encrypted local cache and decision logs  
/config      → all runtime and security policies  
/scripts     → devops and testing utilities  
/docs        → architecture, API, and method references  
```

Each layer operates under zero-trust isolation — no direct dependency between telemetry, learning, and control loops.

---

## Summary
The **ARC Method** is a continuously learning, privacy-first framework for behavioral trust analytics.  
It blends the adaptive strengths of **AETA** and **AIDA** into a single process that interprets context, evolves over time, and documents every decision transparently.

ARC is the unifying brain that enables:
- SentryMX to *understand message integrity*  
- SentryID to *understand identity integrity*  
- Both to *understand intent together*

> **AETA + AIDA = ARC Method**  
> *The unified path from signal to context. From context to trust.*
