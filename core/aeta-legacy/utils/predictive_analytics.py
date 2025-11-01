"""Lightweight predictive analytics helpers for adaptive threat scoring."""
from __future__ import annotations

import json
import os
import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Deque, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence

from ..models import SignalContribution

DEFAULT_STATE_PATH = Path(os.getenv("AETA_PREDICTIVE_STATE", "")).expanduser()
if not DEFAULT_STATE_PATH:
    DEFAULT_STATE_PATH = Path.home() / ".aeta" / "predictive_state.json"

MAX_HISTORY = 1024
RECENT_WINDOW = timedelta(hours=48)


@dataclass
class ForecastResult:
    """Structured forecast output."""

    predicted_risk: float
    base_risk: float
    severity_boost: float
    trend_boost: float
    signals_considered: Sequence[str]
    hotspots: Mapping[str, int]
    rationale: str


class PredictiveThreatModel:
    """Maintains lightweight predictive state for the analyzer."""

    def __init__(self, state_path: Optional[Path] = None) -> None:
        self._path = Path(state_path) if state_path else DEFAULT_STATE_PATH
        self._lock = threading.RLock()
        self._state: Dict[str, object] = {
            "history": [],
            "domain_counts": {},
            "network_counts": {},
            "signal_counts": {},
        }
        self._ensure_parent()
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def forecast(
        self,
        metadata: Mapping[str, object],
        contributions: Sequence[SignalContribution],
    ) -> ForecastResult:
        """Generate a predictive risk estimate from observed signals."""

        with self._lock:
            signals = [contribution.name for contribution in contributions]
            base_risk = self._baseline_risk(contributions)
            severity_boost = self._severity_boost(contributions)
            trend_boost, hotspots = self._trend_boost(metadata)

            predicted = max(0.0, min(100.0, base_risk + severity_boost + trend_boost))
            rationale = self._build_rationale(base_risk, severity_boost, trend_boost, hotspots)

            return ForecastResult(
                predicted_risk=round(predicted, 2),
                base_risk=round(base_risk, 2),
                severity_boost=round(severity_boost, 2),
                trend_boost=round(trend_boost, 2),
                signals_considered=tuple(signals),
                hotspots=hotspots,
                rationale=rationale,
            )

    def record(
        self,
        metadata: Mapping[str, object],
        contributions: Sequence[SignalContribution],
        *,
        verdict: str,
        risk_score: float,
    ) -> None:
        """Persist the latest observation for trend analysis."""

        with self._lock:
            timestamp = datetime.now(tz=timezone.utc).isoformat()
            domain = _normalize_domain(metadata.get("from_domain"))
            ip_prefix = _normalize_prefix(metadata.get("source_ip"))
            high_signals = [
                contribution.name
                for contribution in contributions
                if contribution.score >= 50.0
            ]

            history: List[MutableMapping[str, object]] = self._state.setdefault("history", [])  # type: ignore[assignment]
            history.append(
                {
                    "timestamp": timestamp,
                    "verdict": verdict,
                    "risk": round(risk_score, 2),
                    "domain": domain,
                    "ip_prefix": ip_prefix,
                    "signals": high_signals,
                }
            )
            if len(history) > MAX_HISTORY:
                del history[: len(history) - MAX_HISTORY]

            if domain:
                domain_counts: Dict[str, int] = self._state.setdefault("domain_counts", {})  # type: ignore[assignment]
                domain_counts[domain] = domain_counts.get(domain, 0) + 1
            if ip_prefix:
                network_counts: Dict[str, int] = self._state.setdefault("network_counts", {})  # type: ignore[assignment]
                network_counts[ip_prefix] = network_counts.get(ip_prefix, 0) + 1
            if high_signals:
                signal_counts: Dict[str, int] = self._state.setdefault("signal_counts", {})  # type: ignore[assignment]
                for signal in high_signals:
                    signal_counts[signal] = signal_counts.get(signal, 0) + 1

            self._save()

    def snapshot(self) -> Dict[str, object]:
        """Expose raw predictive state (useful for debugging/tests)."""

        with self._lock:
            return json.loads(json.dumps(self._state))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _baseline_risk(self, contributions: Sequence[SignalContribution]) -> float:
        if not contributions:
            return 0.0
        total = sum(contribution.score for contribution in contributions)
        return total / float(len(contributions))

    def _severity_boost(self, contributions: Sequence[SignalContribution]) -> float:
        significant = [contribution for contribution in contributions if contribution.score >= 65.0]
        if not significant:
            return 0.0
        # Scale severity boost with diminishing returns
        boost = sum(min(20.0, contribution.score / 5.0) for contribution in significant)
        return min(boost, 40.0)

    def _trend_boost(self, metadata: Mapping[str, object]) -> tuple[float, Dict[str, int]]:
        history = self._state.get("history", [])
        if not isinstance(history, list) or not history:
            return 0.0, {}

        cutoff = datetime.now(tz=timezone.utc) - RECENT_WINDOW
        recent_events: Deque[Mapping[str, object]] = deque()
        for entry in reversed(history):
            timestamp = _parse_timestamp(entry.get("timestamp"))
            if timestamp is None or timestamp < cutoff:
                break
            recent_events.appendleft(entry)  # maintain chronological order

        if not recent_events:
            return 0.0, {}

        domain = _normalize_domain(metadata.get("from_domain"))
        ip_prefix = _normalize_prefix(metadata.get("source_ip"))

        domain_hits = 0
        network_hits = 0
        for entry in recent_events:
            if domain and entry.get("domain") == domain:
                domain_hits += 1
            if ip_prefix and entry.get("ip_prefix") == ip_prefix:
                network_hits += 1

        hotspots: Dict[str, int] = {}
        trend_boost = 0.0

        if domain_hits:
            hotspots["domain"] = domain_hits
            trend_boost += min(25.0, domain_hits * 5.0)
        if network_hits:
            hotspots["network"] = network_hits
            trend_boost += min(20.0, network_hits * 4.0)

        return trend_boost, hotspots

    def _build_rationale(
        self,
        base: float,
        severity: float,
        trend: float,
        hotspots: Mapping[str, int],
    ) -> str:
        components: List[str] = [f"Baseline heuristics indicate {base:.1f} risk."]
        if severity:
            components.append(
                f"High-impact signals contributed an additional {severity:.1f} points."
            )
        if trend and hotspots:
            hotspot_text = ", ".join(f"{key}:{count}" for key, count in hotspots.items())
            components.append(
                f"Recent trend hotspots ({hotspot_text}) added {trend:.1f} predictive weight."
            )
        if len(components) == 1:
            components.append("No additional severity or trend adjustments were applied.")
        return " ".join(components)

    def _ensure_parent(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> None:
        try:
            with self._path.open("r", encoding="utf-8") as handle:
                state = json.load(handle)
        except FileNotFoundError:
            return
        except json.JSONDecodeError:
            return
        if isinstance(state, dict):
            self._state.update(state)

    def _save(self) -> None:
        temp_path = self._path.with_suffix(".tmp")
        with temp_path.open("w", encoding="utf-8") as handle:
            json.dump(self._state, handle, indent=2, sort_keys=True)
        temp_path.replace(self._path)


_predictive_model: Optional[PredictiveThreatModel] = None
_predictive_lock = threading.Lock()


def get_predictive_model() -> PredictiveThreatModel:
    """Return the shared predictive model instance."""

    global _predictive_model
    with _predictive_lock:
        if _predictive_model is None:
            _predictive_model = PredictiveThreatModel()
        return _predictive_model


def reset_predictive_model() -> None:
    """Reset the shared predictive model (used in tests)."""

    global _predictive_model
    with _predictive_lock:
        _predictive_model = None


def _normalize_domain(value: object) -> str:
    if not value:
        return ""
    return str(value).strip().lower()


def _normalize_prefix(value: object) -> str:
    if not value:
        return ""
    try:
        addr = ip_address(str(value))
    except ValueError:
        return ""
    if addr.version == 4:
        network = ip_network(f"{addr}/24", strict=False)
    else:
        network = ip_network(f"{addr}/48", strict=False)
    return str(network)


def _parse_timestamp(value: object) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


__all__ = [
    "ForecastResult",
    "PredictiveThreatModel",
    "get_predictive_model",
    "reset_predictive_model",
]

