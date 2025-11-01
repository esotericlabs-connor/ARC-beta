"""Predictive analytics heuristic leveraging the shared predictive model."""
from __future__ import annotations

from typing import Iterable, Sequence

from ..models import SignalContribution
from ..utils.predictive_analytics import get_predictive_model


def analyze_predictive_signals(
    metadata: Sequence[tuple[str, object]] | dict[str, object],
    base_contributions: Iterable[SignalContribution],
) -> SignalContribution:
    """Generate a predictive forecast signal."""

    if isinstance(metadata, dict):
        metadata_view = metadata
    else:
        metadata_view = {key: value for key, value in metadata}

    contributions = list(base_contributions)
    model = get_predictive_model()
    forecast = model.forecast(metadata_view, contributions)

    details = {
        "predicted_risk": forecast.predicted_risk,
        "base_risk": forecast.base_risk,
        "severity_boost": forecast.severity_boost,
        "trend_boost": forecast.trend_boost,
        "signals_considered": list(forecast.signals_considered),
        "hotspots": dict(forecast.hotspots),
        "rationale": forecast.rationale,
    }

    # Weight slightly below 1 to avoid overshadowing discrete heuristics while still
    # influencing the aggregate verdict.
    return SignalContribution(
        name="predictive_analytics",
        score=forecast.predicted_risk,
        weight=0.8,
        details=details,
    )


__all__ = ["analyze_predictive_signals"]

