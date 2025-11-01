from __future__ import annotations

from pathlib import Path
import pytest

from aeta.heuristics.sender_behavior import analyze_sender_behavior
from aeta.heuristics.url_reputation import analyze_url_reputation
from aeta.heuristics.ip_geolocation import analyze_ip_geolocation
from aeta.heuristics.attachments import analyze_attachments
from aeta.heuristics.audit import reset_audit_logger
from aeta.utils import indicator_store


@pytest.fixture(autouse=True)
def indicator_runtime(tmp_path: Path):
    runtime_path = tmp_path / "dynamic_indicators.json"
    indicator_store.DEFAULT_RUNTIME_PATH = runtime_path
    indicator_store.reset_indicator_manager()
    reset_audit_logger()
    yield
    indicator_store.reset_indicator_manager()
    reset_audit_logger()


def test_indicator_manager_persistence():
    manager = indicator_store.get_indicator_manager()
    assert "microsoft" in {value.lower() for value in manager.keywords("reputable_isps")}

    manager.add_keyword("reputable_isps", "ExampleISP", source="test", confidence=0.9)
    indicator_store.reset_indicator_manager()
    manager = indicator_store.get_indicator_manager()
    assert "exampleisp" in {value.lower() for value in manager.keywords("reputable_isps")}


def test_sender_behavior_dynamic_lists():
    metadata = {
        "from": "Chris <sender@dangerous.example>",
        "from_display_name": "sender@dangerous.example",
        "reply_to": "Sender <alias@example.org>",
        "from_domain": "dangerous.example",
        "subject": "Invoice wire transfer request",
        "source_ip": "10.5.5.5",
        "osint_disposable_domains": ["dangerous.example"],
    }
    contribution = analyze_sender_behavior(metadata)
    details = contribution.details

    assert contribution.score > 0
    assert any(container["type"] == "identity" for container in details["analysis_containers"])
    assert "disposable_domain" in details["rule_hits"]
    assert details["audit"]["statistics"]["count"] >= 1

    manager = indicator_store.get_indicator_manager()
    assert "dangerous.example" in {value.lower() for value in manager.keywords("disposable_domains")}


def test_url_reputation_dynamic_lists():
    manager = indicator_store.get_indicator_manager()
    manager.add_keyword("suspicious_tlds", "evil", source="test", confidence=0.9)

    contribution = analyze_url_reputation(["Click https://phish.evil now"])
    details = contribution.details

    assert details["urls"], "expected parsed URL details"
    first_url = details["urls"][0]
    assert any(flag.startswith("suspicious_tld") for flag in first_url.get("flags", []))
    assert any(container["type"] == "url" for container in details["containers"])
    assert "suspicious_tld" in details["rule_hits"]
    assert details["audit"]["statistics"]["count"] >= 1


def test_ip_geolocation_dynamic_updates():
    metadata = {
        "source_ip": "45.155.205.12",
        "source_ip_isp": "Example Hosting VPN",
        "source_ip_hostname": "dynamic.example.net",
        "source_ip_asn": "AS65432 Example Hosting",
        "source_ip_country": "US",
    }
    contribution = analyze_ip_geolocation(metadata)
    details = contribution.details

    assert "network_matches" in details
    assert details.get("risky_isp") == "Example Hosting VPN"
    assert "hostname_flags" in details
    assert "risky_asn_keywords" in details

    manager = indicator_store.get_indicator_manager()
    assert "dynamic.example.net" in {value.lower() for value in manager.keywords("risky_hostnames")}
    assert "example hosting vpn" in {value.lower() for value in manager.keywords("suspicious_isps")}


def test_attachment_container_annotation():
    attachments = [
        {
            "filename": "payload.exe",
            "content_type": "application/octet-stream",
            "payload": b"malicious",
        }
    ]
    contribution = analyze_attachments(attachments)
    details = contribution.details
    assert details["attachments"][0]["flag"] == "dangerous_extension"
    assert "analysis_container" in details["attachments"][0]
    assert any(container["type"] == "file" for container in details["containers"])

