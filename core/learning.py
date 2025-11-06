"""Learning pipeline configuration for ARC."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Mapping, Tuple


@dataclass(frozen=True)
class RetrainCondition:
    """Discrete trigger that prompts a retraining cycle."""

    description: str
    trigger: str
    value: str

    def as_dict(self) -> Dict[str, str]:
        return {
            "description": self.description,
            "trigger": self.trigger,
            "value": self.value,
        }


@dataclass(frozen=True)
class LearningPipelineConfig:
    """Top-level configuration for the adaptive learning pipeline."""

    model_type: str
    update_interval_hours: int
    weight_aggregation: str
    retrain_conditions: Mapping[str, RetrainCondition] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, object]:
        return {
            "model_type": self.model_type,
            "update_interval_hours": self.update_interval_hours,
            "weight_aggregation": self.weight_aggregation,
            "retrain_conditions": {
                key: condition.as_dict() for key, condition in self.retrain_conditions.items()
            },
        }


@dataclass(frozen=True)
class RetrainParameters:
    """Global parameters controlling the retraining process."""

    sensitivity_threshold: str
    retrain_delay_window: str
    confidence_weighting: str
    model_snapshot_retention: int
    auto_commit_after_retrain: bool
    advanced_capabilities: Tuple[str, ...] = ()

    def as_dict(self) -> Dict[str, object]:
        return {
            "sensitivity_threshold": self.sensitivity_threshold,
            "retrain_delay_window": self.retrain_delay_window,
            "confidence_weighting": self.confidence_weighting,
            "model_snapshot_retention": self.model_snapshot_retention,
            "auto_commit_after_retrain": self.auto_commit_after_retrain,
            "advanced_capabilities": list(self.advanced_capabilities),
        }


@dataclass(frozen=True)
class LearningConfiguration:
    """Aggregates pipeline configuration and retraining parameters."""

    pipeline: LearningPipelineConfig
    retrain: RetrainParameters

    def as_dict(self) -> Dict[str, object]:
        return {
            "learning_pipeline": self.pipeline.as_dict(),
            "retrain_parameters": self.retrain.as_dict(),
        }


def default_learning_configuration() -> LearningConfiguration:
    """Return the default ARC learning configuration."""

    retrain_conditions = {
        "interval_update": RetrainCondition(
            description="Retrain after scheduled time interval",
            trigger="time_elapsed",
            value="3h",
        ),
        "incident_threshold": RetrainCondition(
            description="Retrain when number of incidents exceeds defined threshold",
            trigger="IncidentThresholdExceeded",
            value=">=50",
        ),
        "reported_false_positives": RetrainCondition(
            description="Retrain when system receives multiple reported false positives globally",
            trigger="ReportedFalsePositives",
            value=">=10_reports_24h",
        ),
        "user_false_positives": RetrainCondition(
            description="Retrain when user flags a detection as false positive",
            trigger="UserFalsePositives",
            value="single_event",
        ),
        "travel_notice": RetrainCondition(
            description="Retrain or adjust heuristics when user alerts they are traveling",
            trigger="TravelNotice",
            value="travel_notice_received",
        ),
        "impossible_travel": RetrainCondition(
            description=(
                "Retrain or adjust heuristics when user travel pattern changes outside their state, country, "
                "geolocation or just unusual login detected"
            ),
            trigger="ImpossibleTravel",
            value="geo_anomaly_detected",
        ),
        "prediction_trust_low": RetrainCondition(
            description="Retrain when model confidence (PredictionTrust) falls below threshold",
            trigger="PredictionTrust",
            value="<0.2",
        ),
        "node_reputation_low": RetrainCondition(
            description="Retrain when node reputation score drops below minimum threshold",
            trigger="NodeReputationChange",
            value="<0.2",
        ),
        "alert_spike": RetrainCondition(
            description="Retrain when alert frequency spikes above normal baseline",
            trigger="alert_rate_anomaly",
            value="x5_baseline",
        ),
        "novel_incident_type": RetrainCondition(
            description="Retrain when new or unclassified incident type is detected",
            trigger="unrecognized_category",
            value="new_type_detected",
        ),
        "osint_threat_update": RetrainCondition(
            description="Retrain when external OSINT threat feeds update with new high-risk indicators",
            trigger="OSINTThreatUpdate",
            value="feed_version_change",
        ),
        "data_drift": RetrainCondition(
            description="Retrain when incoming data distribution changes significantly over time",
            trigger="DataDrift",
            value="p_value<0.05",
        ),
        "model_performance_drop": RetrainCondition(
            description="Retrain when model performance metrics degrade below defined thresholds",
            trigger="metric_drop",
            value="accuracy<0.9",
        ),
        "regulatory_update": RetrainCondition(
            description="Retrain when compliance, regulation, or policy standards are updated",
            trigger="compliance_change",
            value="policy_revision",
        ),
        "anomalous_model_behavior": RetrainCondition(
            description="Retrain when model outputs deviate significantly from expected results",
            trigger="model_outlier_behavior",
            value="deviation>2σ",
        ),
        "temporal_drift": RetrainCondition(
            description="Retrain periodically or when time-based drift accumulates beyond threshold",
            trigger="time_decay",
            value="30d",
        ),
    }

    pipeline = LearningPipelineConfig(
        model_type="hybrid heuristic + gradient model",
        update_interval_hours=24,
        weight_aggregation="federated_average",
        retrain_conditions=retrain_conditions,
    )

    retrain_parameters = RetrainParameters(
        sensitivity_threshold="medium",
        retrain_delay_window="15m",
        confidence_weighting="verified_reports>unverified",
        model_snapshot_retention=5,
        auto_commit_after_retrain=True,
        advanced_capabilities=(
            "Retrain Audit Trails",
            "Dynamic Retrain Thresholds",
            "Model Drift Anomaly Detection",
            "End-User Feedback Loop",
            "Adaptive Confidence Scaling",
            "Version Comparison Testing",
            "Resource-Aware Retraining",
            "Contextual Retrain Prioritization",
            "Compliance Event Triggers",
            "Snapshot Delta Analysis",
        ),
    )

    return LearningConfiguration(pipeline=pipeline, retrain=retrain_parameters)


__all__ = [
    "RetrainCondition",
    "LearningPipelineConfig",
    "RetrainParameters",
    "LearningConfiguration",
    "default_learning_configuration",
]