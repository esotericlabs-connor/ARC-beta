"""WHOIS metadata heuristics."""
from __future__ import annotations

import datetime as dt
import importlib
import importlib.util
from typing import Dict, Optional

from ..models import SignalContribution


def _load_optional_module(name: str):
    if importlib.util.find_spec(name) is None:
        return None
    return importlib.import_module(name)


def analyze_whois(metadata: Dict[str, Optional[str]]) -> SignalContribution:
    """Score WHOIS data such as domain age and provider."""

    domain = metadata.get("from_domain")
    weight = 1.1
    score = 0.0
    details: Dict[str, object] = {}

    if not domain:
        return SignalContribution(name="whois", score=score, weight=weight, details=details)

    whois_module = _load_optional_module("whois")
    if whois_module is None:
        details["warning"] = "python-whois not installed"
        return SignalContribution(name="whois", score=score, weight=weight, details=details)

    try:
        record = whois_module.whois(domain)
    except Exception as exc:  # noqa: BLE001 - library specific
        details["error"] = str(exc)
        return SignalContribution(name="whois", score=score, weight=weight, details=details)

    creation_date = record.creation_date if hasattr(record, "creation_date") else None
    registrar = record.registrar if hasattr(record, "registrar") else None
    if isinstance(creation_date, list):  # some libraries return lists
        creation_date = creation_date[0]

    if isinstance(creation_date, dt.datetime):
        age_days = (dt.datetime.utcnow() - creation_date.replace(tzinfo=None)).days
        details["domain_age_days"] = age_days
        if age_days < 30:
            score += 40
        elif age_days < 365:
            score += 15
    else:
        details["domain_age_days"] = None

    if registrar:
        details["registrar"] = registrar
        if "privacy" in registrar.lower():
            score += 10

    score = min(score, 100.0)
    return SignalContribution(name="whois", score=score, weight=weight, details=details)