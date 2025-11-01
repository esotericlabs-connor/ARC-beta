"""Heuristic signal generators for Adaptive Email Threat Analysis (AETA)."""

from .attachments import analyze_attachments
from .ip_geolocation import analyze_ip_geolocation
from .predictive import analyze_predictive_signals
from .sender_behavior import analyze_sender_behavior
from .url_reputation import analyze_url_reputation
from .whois_data import analyze_whois

__all__ = [
    "analyze_attachments",
    "analyze_ip_geolocation",
    "analyze_predictive_signals",
    "analyze_sender_behavior",
    "analyze_url_reputation",
    "analyze_whois",
]