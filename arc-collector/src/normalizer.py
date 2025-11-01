"""Normalization helpers for Microsoft and Google events."""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from .models import GeoContext, NormalizedEvent, SignalVector
from .utils.geo import GeoResolver


def hash_user(identifier: Optional[str]) -> str:
    if not identifier:
        return "anonymous"
    return hashlib.sha256(identifier.lower().encode("utf-8")).hexdigest()


def _geo_from_ms(raw: Dict[str, Any], resolver: GeoResolver) -> GeoContext:
    ip = raw.get("ipAddress")
    geo = resolver.resolve(ip)
    location = raw.get("location", {}) or {}
    coords = location.get("geoCoordinates") or {}
    return GeoContext(
        ip=ip,
        country=location.get("countryOrRegion") or geo.country,
        region=location.get("state") or geo.region,
        city=location.get("city") or geo.city,
        latitude=coords.get("latitude") or geo.latitude,
        longitude=coords.get("longitude") or geo.longitude,
        asn=geo.asn,
    )


def _geo_from_google(raw: Dict[str, Any], resolver: GeoResolver) -> GeoContext:
    ip = None
    if "ipAddress" in raw:
        ip = raw.get("ipAddress")
    else:
        parameters = raw.get("parameters", [])
        for param in parameters:
            if param.get("name") == "ipAddress":
                ip = param.get("value")
                break
    geo = resolver.resolve(ip)
    location = raw.get("location", {}) or {}
    return GeoContext(
        ip=ip,
        country=location.get("country") or geo.country,
        region=location.get("region") or geo.region,
        city=location.get("city") or geo.city,
        latitude=location.get("latitude") or geo.latitude,
        longitude=location.get("longitude") or geo.longitude,
        asn=geo.asn,
    )


def ms_confidence(raw: Dict[str, Any]) -> float:
    detail = raw.get("riskDetail") or "none"
    level = raw.get("riskLevel") or "low"
    base = {"low": 85, "medium": 60, "high": 30}.get(level.lower(), 50)
    if detail.lower().startswith("mfa"):
        base += 5
    if raw.get("conditionalAccessStatus") == "success":
        base += 5
    return max(0, min(100, base))


def ms_geo_risk(raw: Dict[str, Any]) -> float:
    state = raw.get("riskState") or "none"
    mapping = {"none": 5, "remediated": 10, "atRisk": 60, "confirmedCompromised": 90}
    return mapping.get(state, 25)


def ms_session_anomaly(raw: Dict[str, Any]) -> bool:
    return raw.get("riskState") not in {"none", "remediated"}


def google_confidence(raw: Dict[str, Any]) -> float:
    if raw.get("type") == "login_failure":
        return 25
    parameters = {param.get("name"): param.get("boolValue") or param.get("value") for param in raw.get("parameters", [])}
    mfa = parameters.get("isSecondFactor")
    base = 70 if mfa else 55
    if raw.get("name") == "login_success":
        base += 10
    return max(0, min(100, base))


def google_geo_risk(raw: Dict[str, Any]) -> float:
    parameters = {param.get("name"): param.get("value") for param in raw.get("parameters", [])}
    risk = parameters.get("login_challenge")
    if risk:
        return 65
    return 15


def google_session_anomaly(raw: Dict[str, Any]) -> bool:
    return raw.get("type") == "login_challenge"


def _risk_level(score: float, anomaly: bool) -> str:
    if score >= 75 and not anomaly:
        return "low"
    if score >= 50:
        return "medium" if anomaly else "moderate"
    return "high"


def normalize_ms(event: Dict[str, Any], account_id: str, resolver: GeoResolver) -> NormalizedEvent:
    timestamp = event.get("createdDateTime") or event.get("riskEventDateTime")
    ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00")) if isinstance(timestamp, str) else datetime.utcnow()
    username = event.get("userPrincipalName") or event.get("userDisplayName")
    geo = _geo_from_ms(event, resolver)
    auth_score = ms_confidence(event)
    anomaly = ms_session_anomaly(event)
    risk_level = _risk_level(auth_score, anomaly)
    risk_tags: List[str] = []
    if event.get("riskLevel") in {"medium", "high"}:
        risk_tags.append("risky_sign_in")
    if event.get("riskDetail") and "mfa" not in (event.get("authenticationRequirement") or "").lower():
        risk_tags.append("missing_mfa")
    signals = SignalVector(
        auth_confidence=auth_score,
        geo_risk=ms_geo_risk(event),
        session_anomaly=anomaly,
        risk_level=risk_level,
    )
    return NormalizedEvent(
        id=event.get("id") or f"ms:{event.get('correlationId')}",
        provider="microsoft",
        account_id=account_id,
        timestamp=ts,
        user_hash=hash_user(username or event.get("userId")),
        username=username,
        geo=geo,
        signals=signals,
        raw=event,
        risk_tags=risk_tags,
        insights={
            "authenticationRequirement": event.get("authenticationRequirement"),
            "clientAppUsed": event.get("clientAppUsed"),
        },
    )


def normalize_google(event: Dict[str, Any], account_id: str, resolver: GeoResolver) -> NormalizedEvent:
    timestamp = None
    if isinstance(event.get("id"), dict):
        timestamp = event["id"].get("time")
    if not timestamp:
        timestamp = event.get("eventTime")
    ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00")) if isinstance(timestamp, str) else datetime.utcnow()
    actor = event.get("actor", {})
    email = actor.get("email")
    geo = _geo_from_google(event, resolver)
    auth_score = google_confidence(event)
    anomaly = google_session_anomaly(event)
    risk_level = _risk_level(auth_score, anomaly)
    signals = SignalVector(
        auth_confidence=auth_score,
        geo_risk=google_geo_risk(event),
        session_anomaly=anomaly,
        risk_level=risk_level,
    )
    risk_tags: List[str] = []
    if event.get("type") == "login_challenge":
        risk_tags.append("risky_sign_in")
    return NormalizedEvent(
        id=event.get("id", {}).get("uniqueQualifier") or f"google:{timestamp}:{email}",
        provider="google",
        account_id=account_id,
        timestamp=ts,
        user_hash=hash_user(email),
        username=email,
        geo=geo,
        signals=signals,
        raw=event,
        risk_tags=risk_tags,
        insights={
            "eventName": event.get("name"),
            "twoFactor": any(param.get("name") == "isSecondFactor" for param in event.get("parameters", [])),
        },
    )


def compute_ati(events: Iterable[NormalizedEvent]) -> float:
    scores = []
    for event in events:
        score = event.signals.auth_confidence or 50
        if event.signals.session_anomaly:
            score -= 20
        scores.append(score)
    if not scores:
        return 0.0
    return sum(scores) / len(scores)