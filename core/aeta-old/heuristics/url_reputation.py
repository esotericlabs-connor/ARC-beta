"""URL reputation heuristics."""
from __future__ import annotations

import re
from typing import Dict, Iterable, List
from urllib.parse import urlparse

from ..models import SignalContribution
from ..utils.containerization import mark_analysis_container
from ..utils.indicator_store import get_indicator_manager
from .audit import get_audit_logger

IP_URL_PATTERN = re.compile(r"https?://\d+\.\d+\.\d+\.\d+")
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+")


def extract_urls(texts: Iterable[str]) -> List[str]:
    urls: List[str] = []
    for text in texts:
        if not text:
            continue
        matches = URL_PATTERN.findall(text)
        urls.extend(matches)
    return urls


def analyze_url_reputation(texts: Iterable[str]) -> SignalContribution:
    """Score URLs based on dynamic reputation checks."""

    indicator_store = get_indicator_manager()
    suspicious_tlds = indicator_store.keywords("suspicious_tlds")

    urls = extract_urls(texts)
    details: List[Dict[str, object]] = []
    containers: List[Dict[str, object]] = []
    score = 0.0
    weight = 1.2
    rule_hits: List[str] = []

    for url in urls:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        url_details: Dict[str, object] = {"url": url, "netloc": netloc}
        container = mark_analysis_container(url_details, "url", url, metadata={"netloc": netloc}, confidence=0.8)
        containers.append(container)
        if IP_URL_PATTERN.match(url):
            score += 25
            url_details.setdefault("flags", []).append("ip_literal")
            rule_hits.append("ip_literal")
        if netloc.endswith(".onion"):
            score += 35
            url_details.setdefault("flags", []).append("tor_hidden_service")
            rule_hits.append("tor_hidden_service")
        if "." in netloc:
            tld = netloc.split(".")[-1]
            if tld.lower() in {entry.lower() for entry in suspicious_tlds}:
                score += 15
                url_details.setdefault("flags", []).append(f"suspicious_tld:{tld}")
                rule_hits.append("suspicious_tld")
        if parsed.scheme == "http":
            score += 10
            url_details.setdefault("flags", []).append("http_scheme")
            rule_hits.append("http_scheme")
        details.append(url_details)

    if urls and score == 0:
        score = 5

    score = min(score, 100.0)

    audit_logger = get_audit_logger()
    audit_summary = audit_logger.assess("url_reputation", score, rule_hits)

    return SignalContribution(
        name="url_reputation",
        score=score,
        weight=weight,
        details={
            "urls": details,
            "containers": containers,
            "rule_hits": rule_hits,
            "audit": audit_summary,
        },
    )
