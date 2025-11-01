"""Helpers for annotating analysis containers."""
from __future__ import annotations

from typing import Dict, Optional


def mark_analysis_container(
    target: Dict[str, object],
    container_type: str,
    identifier: str,
    *,
    metadata: Optional[Dict[str, object]] = None,
    confidence: float = 1.0,
) -> Dict[str, object]:
    """Attach container metadata to the provided detail dictionary."""

    container: Dict[str, object] = {
        "type": container_type,
        "identifier": identifier,
        "confidence": round(confidence, 3),
    }
    if metadata:
        container["metadata"] = metadata
    target["analysis_container"] = container
    return container
