"""Fail-safe logic for zero-trust ARC infrastructure guardianship."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Mapping, Sequence

from .state import TelemetryEvent


@dataclass(frozen=True)
class ProtectedResource:
    """Descriptor for a resource safeguarded by ARC."""

    identifier: str
    kind: str
    location: str | None = None

    def as_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {"id": self.identifier, "type": self.kind}
        if self.location is not None:
            payload["location"] = self.location
        return payload


@dataclass(frozen=True)
class FailsafeDirective:
    """Actionable directive emitted by :class:`FailsafeManager`."""

    action: str
    triggered: bool
    reason: str
    severity: float
    resources: Sequence[ProtectedResource]
    issued_at: datetime

    def as_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "triggered": self.triggered,
            "reason": self.reason,
            "severity": self.severity,
            "issued_at": self.issued_at.isoformat(),
            "resources": [resource.as_dict() for resource in self.resources],
        }


class FailsafeManager:
    """Evaluates telemetry for tamper signals and issues containment commands."""

    _BOOLEAN_KEYWORDS = ("intrusion", "tamper", "breach", "compromise", "failsafe")
    _VALUE_KEYWORDS = (
        "ssh",
        "rootkit",
        "privilege escalation",
        "lateral movement",
        "exfiltration",
        "backdoor",
    )
    _NUMERIC_THRESHOLDS = {
        "ssh_bruteforce": 5,
        "ssh_attempts": 15,
        "privilege_escalation_attempts": 1,
    }

    def __init__(self, *, risk_threshold: float = 75.0) -> None:
        self._risk_threshold = risk_threshold

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def evaluate(
        self,
        event: TelemetryEvent,
        *,
        risk_score: float,
        verdict: str,
    ) -> FailsafeDirective:
        """Return a :class:`FailsafeDirective` for the supplied event."""

        issued_at = datetime.now(tz=timezone.utc)
        metadata = _ensure_mapping(event.metadata)
        identity = _ensure_mapping(event.identity)
        metrics = _ensure_mapping(event.metrics)

        reasons: list[str] = []
        triggered = False

        override = str(metadata.get("failsafe_override") or "").strip().lower()

        if verdict == "malicious" or risk_score >= self._risk_threshold:
            triggered = True
            reasons.append(
                f"ARC fusion classified event as {verdict} with risk {risk_score:.2f}"
            )

        reason_flags = list(self._collect_trigger_reasons(metrics, prefix="metrics"))
        reason_flags.extend(self._collect_trigger_reasons(metadata, prefix="metadata"))
        reason_flags.extend(self._collect_trigger_reasons(identity, prefix="identity"))
        if reason_flags:
            triggered = True
            reasons.extend(reason_flags)

        if override in {"monitor", "safe"}:
            triggered = False
            reasons.append("Failsafe override requested monitor state")
        elif override in {"self_destruct", "destroy", "purge"}:
            triggered = True
            reasons.append("Failsafe override forced self-destruct")

        resources = tuple(self._extract_resources(event, metadata))
        if not resources:
            resources = (
                ProtectedResource(
                    identifier=event.node_id,
                    kind=event.framework,
                    location=str(metadata.get("location") or "edge"),
                ),
            )

        action = "self_destruct" if triggered else "monitor"
        reason_text = "; ".join(reasons) if reasons else "No fail-safe triggers detected"
        severity = round(max(risk_score, 0.0), 2)

        return FailsafeDirective(
            action=action,
            triggered=triggered,
            reason=reason_text,
            severity=severity,
            resources=resources,
            issued_at=issued_at,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _collect_trigger_reasons(
        self,
        mapping: Mapping[str, object],
        *,
        prefix: str,
    ) -> Iterable[str]:
        for key, value in mapping.items():
            if value is None:
                continue
            key_text = str(key).lower()

            if isinstance(value, bool):
                if value and any(token in key_text for token in self._BOOLEAN_KEYWORDS):
                    yield f"{prefix}.{key} asserted compromise flag"
            elif isinstance(value, (int, float)):
                threshold = self._numeric_threshold_for(key_text)
                if threshold is not None and float(value) >= threshold:
                    yield f"{prefix}.{key} exceeded threshold {threshold}"
            else:
                text_value = str(value).lower()
                if any(keyword in text_value for keyword in self._VALUE_KEYWORDS):
                    yield f"{prefix}.{key} reported {value}"

    def _numeric_threshold_for(self, key: str) -> float | None:
        for candidate, threshold in self._NUMERIC_THRESHOLDS.items():
            if candidate in key:
                return threshold
        return None

    def _extract_resources(
        self,
        event: TelemetryEvent,
        metadata: Mapping[str, object],
    ) -> Iterable[ProtectedResource]:
        resources: list[ProtectedResource] = []

        entries = metadata.get("protected_resources")
        if isinstance(entries, Sequence):
            for entry in entries:
                if not isinstance(entry, Mapping):
                    continue
                identifier = str(entry.get("id") or entry.get("identifier") or "").strip()
                kind = str(entry.get("type") or entry.get("kind") or "unknown").strip() or "unknown"
                location = entry.get("location")
                if identifier:
                    resources.append(
                        ProtectedResource(
                            identifier=identifier,
                            kind=kind,
                            location=str(location) if location is not None else None,
                        )
                    )

        container_id = metadata.get("container_id")
        if container_id:
            resources.append(
                ProtectedResource(
                    identifier=str(container_id),
                    kind=str(metadata.get("container_type") or "container"),
                    location=str(metadata.get("cluster") or metadata.get("location") or "edge"),
                )
            )

        cluster_name = metadata.get("cluster_name") or metadata.get("kubernetes_cluster")
        if cluster_name:
            resources.append(
                ProtectedResource(
                    identifier=str(cluster_name),
                    kind="kubernetes-cluster",
                    location=str(metadata.get("region") or metadata.get("location") or "edge"),
                )
            )

        unique = {}
        for resource in resources:
            unique_key = (resource.identifier, resource.kind, resource.location)
            unique[unique_key] = resource
        return unique.values()

def _ensure_mapping(value: object) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return value
    return {}

__all__ = [
    "FailsafeDirective",
    "FailsafeManager",
    "ProtectedResource",
]
