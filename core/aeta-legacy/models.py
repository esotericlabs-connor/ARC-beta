"""Data models for Adaptive Email Threat Analysis (AETA)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class VerificationResult:
    """Represents the outcome of an e-mail authentication check."""

    protocol: str
    passed: Optional[bool]
    result: str
    details: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol,
            "passed": self.passed,
            "result": self.result,
            "details": self.details,
        }


@dataclass
class SignalContribution:
    """Represents the contribution of a single heuristic signal."""

    name: str
    score: float
    weight: float
    details: Dict[str, Any] = field(default_factory=dict)

    def weighted_score(self) -> float:
        return self.score * self.weight

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "score": self.score,
            "weight": self.weight,
            "details": self.details,
        }


@dataclass
class SentryReport:
    """Aggregate report produced by :func:`analyze_email`."""

    score: float
    verdict: str
    risk_score: float
    contributions: List[SignalContribution]
    authentication: List[VerificationResult]
    metadata: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "contributions": [contribution.as_dict() for contribution in self.contributions],
            "authentication": [result.as_dict() for result in self.authentication],
            "metadata": self.metadata,
        }

    def to_json(self) -> Dict[str, Any]:
        """JSON-friendly serialization alias."""

        return self.as_dict()