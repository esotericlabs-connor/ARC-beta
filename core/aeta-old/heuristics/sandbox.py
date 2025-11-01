"""Sandbox integration placeholders."""
from __future__ import annotations

from typing import Dict

from ..models import SignalContribution


def analyze_with_sandbox(metadata: Dict[str, object]) -> SignalContribution:
    """Placeholder for future sandbox integrations.

    Currently returns a neutral contribution while exposing hooks for
    specialized malware detonation pipelines.
    """

    return SignalContribution(
        name="sandbox",
        score=0.0,
        weight=0.5,
        details={"status": "sandbox_not_configured", "metadata_keys": list(metadata.keys())},
    )