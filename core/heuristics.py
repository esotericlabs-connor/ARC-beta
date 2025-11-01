"""Heuristic signal extraction for ARC."""
from __future__ import annotations

from dataclasses import dataclass
from statistics import mean
from typing import Iterable, Mapping, Sequence

from .state import Signal, TelemetryEvent


@dataclass
class HeuristicBundle:
    """Grouped heuristic output for downstream fusion."""

    email_signals: Sequence[Signal]
    identity_signals: Sequence[Signal]


class HeuristicEngine:
    """Derives weighted heuristic signals for ARC."""

    def __init__(self, state) -> None:
        self._state = state

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def run(self, event: TelemetryEvent) -> HeuristicBundle:
        email_signals = tuple(self._email_signals(event))
        identity_signals = tuple(self._identity_signals(event))
        return HeuristicBundle(email_signals=email_signals, identity_signals=identity_signals)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _email_signals(self, event: TelemetryEvent) -> Iterable[Signal]:
        email = event.email
        metrics = event.metrics

        if not email and event.framework != "AETA":
            return []

        heuristic_score = _coerce_float(
            email.get("heuristic_score"),
            metrics.get("heuristic_score"),
            default=45.0,
        )
        heuristic_score = max(0.0, min(100.0, heuristic_score))
        yield Signal(
            name="email.heuristic_model",
            score=heuristic_score,
            weight=0.65,
            context={"source": "legacy_aeta" if "heuristic_score" in email else "arc_estimate"},
        )

        auth_context = self._authentication_context(email)
        if auth_context:
            failures = auth_context.get("failures", 0)
            risk = min(100.0, 40.0 + failures * 15.0)
            yield Signal(
                name="email.authentication",
                score=risk,
                weight=0.45,
                context=auth_context,
            )

        link_risk = _coerce_float(email.get("link_risk"), default=35.0)
        attachment_risk = _coerce_float(email.get("attachment_risk"), default=35.0)
        if link_risk:
            yield Signal(
                name="email.links",
                score=min(100.0, link_risk),
                weight=0.35,
                context={"link_risk": link_risk},
            )
        if attachment_risk:
            weight = 0.4 if attachment_risk >= 50.0 else 0.25
            yield Signal(
                name="email.attachments",
                score=min(100.0, attachment_risk),
                weight=weight,
                context={"attachment_risk": attachment_risk},
            )

        domain_age = _coerce_float(email.get("domain_age_days"))
        if domain_age is not None:
            freshness = max(0.0, min(1.0, (90.0 - domain_age) / 90.0))
            yield Signal(
                name="email.domain_freshness",
                score=30.0 + freshness * 50.0,
                weight=0.2,
                context={"domain_age_days": domain_age},
            )

    def _identity_signals(self, event: TelemetryEvent) -> Iterable[Signal]:
        identity = event.identity
        metrics = event.metrics

        if not identity and event.framework != "AIDA":
            return []

        geo_risk = _coerce_float(metrics.get("geo_risk"), identity.get("geo_risk"), default=20.0)
        geo_signal = Signal(
            name="identity.geo_risk",
            score=max(0.0, min(100.0, geo_risk * 15.0)),
            weight=0.4,
            context={"geo_risk": geo_risk},
        )
        yield geo_signal

        auth_confidence = _coerce_float(metrics.get("auth_confidence"), identity.get("auth_confidence"), default=80.0)
        auth_risk = max(0.0, min(100.0, 100.0 - auth_confidence))
        yield Signal(
            name="identity.auth_confidence",
            score=auth_risk,
            weight=0.5,
            context={"auth_confidence": auth_confidence},
        )

        session_anomaly = identity.get("session_anomaly") or metrics.get("session_anomaly")
        if isinstance(session_anomaly, bool):
            yield Signal(
                name="identity.session_anomaly",
                score=75.0 if session_anomaly else 25.0,
                weight=0.35 if session_anomaly else 0.2,
                context={"session_anomaly": session_anomaly},
            )

        device_history = identity.get("device_history") or []
        if isinstance(device_history, Sequence) and device_history:
            recent_failures = [entry.get("failures", 0) for entry in device_history if isinstance(entry, Mapping)]
            if recent_failures:
                avg_failures = mean(float(value) for value in recent_failures)
                score = max(0.0, min(100.0, min(90.0, avg_failures * 18.0)))
                yield Signal(
                    name="identity.device_failures",
                    score=score,
                    weight=0.25,
                    context={"average_failures": round(avg_failures, 2)},
                )

        behavior_signature = identity.get("behavior_signature")
        if isinstance(behavior_signature, str) and behavior_signature.startswith("HIST-"):
            # Historical deviation indicated by appended intensity (e.g., HIST-2401)
            try:
                intensity = float(behavior_signature.split("-")[-1]) % 100
            except ValueError:
                intensity = 25.0
            yield Signal(
                name="identity.behavior_deviation",
                score=30.0 + min(70.0, intensity * 0.8),
                weight=0.3,
                context={"behavior_signature": behavior_signature},
            )

    def _authentication_context(self, email: Mapping[str, object]) -> Mapping[str, int | str]:
        results = []
        failures = 0
        for proto in ("spf_result", "dkim_result", "dmarc_result"):
            result = email.get(proto)
            if not isinstance(result, str):
                continue
            normalized = result.lower()
            results.append((proto.split("_")[0], normalized))
            if normalized in {"fail", "softfail", "permerror"}:
                failures += 1
        if not results:
            return {}
        return {"protocols": tuple(results), "failures": failures}


def _coerce_float(*values: object, default: float | None = None) -> float | None:
    for value in values:
        if value is None:
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    return default


__all__ = ["HeuristicBundle", "HeuristicEngine"]