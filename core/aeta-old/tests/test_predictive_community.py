from __future__ import annotations

from pathlib import Path

import pytest

from aeta.heuristics.attachments import analyze_attachments
from aeta.heuristics.ip_geolocation import analyze_ip_geolocation
from aeta.heuristics.predictive import analyze_predictive_signals
from aeta.heuristics.sender_behavior import analyze_sender_behavior
from aeta.heuristics.url_reputation import analyze_url_reputation
from aeta.heuristics.whois_data import analyze_whois
from aeta.heuristics.sandbox import analyze_with_sandbox
from aeta.utils import indicator_store
from aeta.utils import community_intel, predictive_analytics
from aeta.utils.community_intel import get_community_hub, reset_community_hub
from aeta.utils.predictive_analytics import reset_predictive_model


@pytest.fixture(autouse=True)
def predictive_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    original_runtime = indicator_store.DEFAULT_RUNTIME_PATH
    original_intel_path = community_intel.DEFAULT_INTEL_PATH
    original_predictive_path = predictive_analytics.DEFAULT_STATE_PATH
    indicator_store.DEFAULT_RUNTIME_PATH = tmp_path / "dynamic_indicators.json"
    community_intel.DEFAULT_INTEL_PATH = tmp_path / "community_intel.json"
    predictive_analytics.DEFAULT_STATE_PATH = tmp_path / "predictive_state.json"
    indicator_store.reset_indicator_manager()
    reset_predictive_model()
    reset_community_hub()
    monkeypatch.setenv("AETA_PREDICTIVE_STATE", str(predictive_analytics.DEFAULT_STATE_PATH))
    monkeypatch.setenv("AETA_COMMUNITY_INTEL", str(community_intel.DEFAULT_INTEL_PATH))
    yield
    indicator_store.reset_indicator_manager()
    reset_predictive_model()
    reset_community_hub()
    indicator_store.DEFAULT_RUNTIME_PATH = original_runtime
    community_intel.DEFAULT_INTEL_PATH = original_intel_path
    predictive_analytics.DEFAULT_STATE_PATH = original_predictive_path


def _base_contributions(metadata: dict[str, object]):
    body_texts = [
        "Click https://phish.evil to resolve urgent invoice",
        "Please wire funds now",
    ]
    attachments = [
        {
            "filename": "payload.exe",
            "content_type": "application/octet-stream",
            "payload": b"evil",
        }
    ]
    contributions = [
        analyze_url_reputation(body_texts),
        analyze_attachments(attachments),
        analyze_sender_behavior(metadata),
        analyze_ip_geolocation(metadata),
        analyze_whois(metadata),
        analyze_with_sandbox(metadata),
    ]
    return contributions


def test_predictive_forecast_enriches_contributions():
    metadata = {
        "from": "Chris <sender@dangerous.example>",
        "from_display_name": "sender@dangerous.example",
        "reply_to": "Sender <alias@example.org>",
        "from_domain": "dangerous.example",
        "subject": "Urgent wire transfer request",
        "source_ip": "45.155.205.12",
        "source_ip_isp": "Example Hosting VPN",
        "source_ip_hostname": "dynamic.example.net",
        "source_ip_asn": "AS65432 Example Hosting",
        "source_ip_country": "US",
    }

    contributions = _base_contributions(metadata)
    predictive = analyze_predictive_signals(metadata, contributions)

    assert predictive.name == "predictive_analytics"
    assert predictive.details["predicted_risk"] >= predictive.details["base_risk"]
    assert "rationale" in predictive.details


def test_community_hub_collects_heatmap_data():
    metadata = {
        "from": "Chris <sender@dangerous.example>",
        "from_display_name": "sender@dangerous.example",
        "reply_to": "Sender <alias@example.org>",
        "from_domain": "dangerous.example",
        "subject": "Urgent wire transfer request",
        "source_ip": "45.155.205.12",
        "source_ip_isp": "Example Hosting VPN",
        "source_ip_hostname": "dynamic.example.net",
        "source_ip_asn": "AS65432 Example Hosting",
        "source_ip_country": "US",
    }

    contributions = _base_contributions(metadata)
    predictive = analyze_predictive_signals(metadata, contributions)
    full_contributions = contributions + [predictive]

    hub = get_community_hub()
    hub.record_observation(metadata, full_contributions, verdict="malicious", risk_score=82.5)

    snapshot = hub.snapshot()
    assert snapshot.totals["events"] == 1
    assert snapshot.top_domains[0]["value"] == "dangerous.example"
    assert snapshot.top_networks[0]["value"].startswith("45.155.205")
    assert snapshot.recent_events[0]["risk"] == 82.5
