"""Sender behavior heuristics."""
from __future__ import annotations

import re
from typing import Dict, List, Optional

from ..models import SignalContribution
from ..utils.containerization import mark_analysis_container
from ..utils.indicator_store import get_indicator_manager
from .audit import get_audit_logger


def analyze_sender_behavior(metadata: Dict[str, Optional[str]]) -> SignalContribution:
    """Score sender anomalies using dynamic indicator lists."""

    indicator_store = get_indicator_manager()
    indicator_store.ingest_metadata(
        metadata,
        {
            "spoofing_keywords": {
                "keys": [
                    "spoofing_keywords",
                    "osint_spoofing_keywords",
                    "subject_spoofing_keywords",
                ],
                "kind": "keyword",
                "confidence": 0.85,
            },
            "disposable_domains": {
                "keys": [
                    "disposable_domains",
                    "osint_disposable_domains",
                    "known_disposable_domains",
                ],
                "kind": "keyword",
                "confidence": 0.9,
            },
            "display_name_pattern": {
                "keys": ["display_name_pattern_override", "osint_display_name_pattern"],
                "kind": "pattern",
                "confidence": 0.9,
            },
        },
        source_prefix="sender_behavior",
    )

    pattern_override = indicator_store.pattern("display_name_pattern")
    try:
        display_name_pattern = re.compile(pattern_override.value)
    except re.error:
        display_name_pattern = re.compile(r'^([^"\s<>]+?)\s*<(.+@.+)>$')
        pattern_override = type(pattern_override)(
            value=display_name_pattern.pattern,
            source="fallback",
            confidence=pattern_override.confidence,
            first_seen=pattern_override.first_seen,
        )
    spoofing_keywords = indicator_store.keywords("spoofing_keywords")
    disposable_domains = indicator_store.keywords("disposable_domains")

    from_address = metadata.get("from") or ""
    reply_to = metadata.get("reply_to") or ""
    display_name = metadata.get("from_display_name") or ""
    domain = metadata.get("from_domain") or ""

    score = 0.0
    weight = 1.0
    details: Dict[str, object] = {
        "display_name_pattern_source": pattern_override.source,
        "display_name_pattern_confidence": pattern_override.confidence,
        "display_name_pattern_first_seen": pattern_override.first_seen,
    }
    rule_hits: List[str] = []

    if display_name_pattern.match(from_address) and "@" in display_name:
        score += 20
        details["display_name_flag"] = "email_in_display_name"
        rule_hits.append("display_name_email")

    if reply_to and domain and reply_to.lower().split("@")[-1] != domain.lower():
        score += 25
        details["reply_to_mismatch"] = True
        rule_hits.append("reply_to_domain_mismatch")

    lowered_domain = domain.lower()
    if lowered_domain and lowered_domain in {entry.lower() for entry in disposable_domains}:
        score += 30
        details["disposable_domain"] = lowered_domain
        rule_hits.append("disposable_domain")

    lowered_subject = (metadata.get("subject") or "").lower()
    matching_keywords = [keyword for keyword in spoofing_keywords if keyword in lowered_subject]
    if matching_keywords:
        score += 10
        details["subject_keywords"] = matching_keywords
        rule_hits.append("subject_spoofing_keyword")

    sender_ip = metadata.get("source_ip") or ""
    if sender_ip.startswith("10.") or sender_ip.startswith("192.168"):
        score += 5
        details["private_ip_sender"] = sender_ip
        rule_hits.append("private_ip_sender")

    details["analysis_containers"] = []
    if from_address:
        container = mark_analysis_container(
            {"from": from_address},
            "identity",
            from_address,
            metadata={"domain": domain},
            confidence=0.75,
        )
        details["analysis_containers"].append(container)

    score = min(score, 100.0)

    audit_logger = get_audit_logger()
    audit_summary = audit_logger.assess("sender_behavior", score, rule_hits)
    details["rule_hits"] = rule_hits
    details["audit"] = audit_summary

    return SignalContribution(name="sender_behavior", score=score, weight=weight, details=details)
