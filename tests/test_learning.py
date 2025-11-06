import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.learning import (
    LearningConfiguration,
    LearningPipelineConfig,
    RetrainCondition,
    RetrainParameters,
    default_learning_configuration,
)


def test_default_learning_configuration_shape():
    config = default_learning_configuration()

    assert isinstance(config, LearningConfiguration)
    assert isinstance(config.pipeline, LearningPipelineConfig)
    assert isinstance(config.retrain, RetrainParameters)

    pipeline = config.pipeline
    assert pipeline.model_type == "hybrid heuristic + gradient model"
    assert pipeline.update_interval_hours == 24
    assert pipeline.weight_aggregation == "federated_average"
    assert set(pipeline.retrain_conditions.keys()) == {
        "interval_update",
        "incident_threshold",
        "reported_false_positives",
        "user_false_positives",
        "travel_notice",
        "impossible_travel",
        "prediction_trust_low",
        "node_reputation_low",
        "alert_spike",
        "novel_incident_type",
        "osint_threat_update",
        "data_drift",
        "model_performance_drop",
        "regulatory_update",
        "anomalous_model_behavior",
        "temporal_drift",
    }

    drift_condition = pipeline.retrain_conditions["data_drift"]
    assert isinstance(drift_condition, RetrainCondition)
    assert drift_condition.trigger == "DataDrift"
    assert drift_condition.value == "p_value<0.05"

    retrain = config.retrain
    assert retrain.sensitivity_threshold == "medium"
    assert retrain.retrain_delay_window == "15m"
    assert retrain.confidence_weighting == "verified_reports>unverified"
    assert retrain.model_snapshot_retention == 5
    assert retrain.auto_commit_after_retrain is True
    assert set(retrain.advanced_capabilities) == {
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
    }


@pytest.mark.parametrize("key, expected_trigger", [
    ("interval_update", "time_elapsed"),
    ("incident_threshold", "IncidentThresholdExceeded"),
    ("alert_spike", "alert_rate_anomaly"),
    ("temporal_drift", "time_decay"),
])
def test_retrain_condition_triggers(key, expected_trigger):
    config = default_learning_configuration()
    condition = config.pipeline.retrain_conditions[key]
    assert condition.trigger == expected_trigger


def test_configuration_serializes_to_mapping():
    config = default_learning_configuration()
    as_dict = config.as_dict()

    assert set(as_dict.keys()) == {"learning_pipeline", "retrain_parameters"}
    assert as_dict["learning_pipeline"]["model_type"] == "hybrid heuristic + gradient model"
    assert as_dict["retrain_parameters"]["auto_commit_after_retrain"] is True
    assert "advanced_capabilities" in as_dict["retrain_parameters"]