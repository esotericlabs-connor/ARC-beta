"""Top-level package for Adaptive Email Threat Analysis (AETA)."""

from .core import analyze_email
from .models import SentryReport, VerificationResult

__all__ = ["analyze_email", "SentryReport", "VerificationResult"]