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


def _geo_from_dropbox(raw: Dict[str, Any], resolver: GeoResolver) -> GeoContext:
    origin = raw.get("origin", {}) or {}
    ip = origin.get("ip_address") or raw.get("ip_address")
    location = origin.get("geo_location") or {}
    geo = resolver.resolve(ip)
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


def dropbox_confidence(raw: Dict[str, Any]) -> float:
    event_type = raw.get("event_type", {}) or {}
    primary_tag = (event_type.get(".tag") or "").lower()
    nested = event_type.get(primary_tag, {}) if isinstance(event_type.get(primary_tag), dict) else {}
    nested_tag = (nested.get(".tag") or "").lower()
    if "fail" in primary_tag or "fail" in nested_tag or "denied" in nested_tag:
        return 35.0
    if "logout" in primary_tag or "log_out" in nested_tag:
        return 75.0
    if "suspicious" in primary_tag or "suspicious" in nested_tag:
        return 45.0
    return 65.0


def dropbox_geo_risk(raw: Dict[str, Any]) -> float:
    origin = raw.get("origin", {}) or {}
    location = origin.get("geo_location") or {}
    if not location:
        return 55.0
    if location.get("country") in {"US", "CA", "GB", "AU", "NZ"}:
        return 25.0
    return 40.0


def dropbox_session_anomaly(raw: Dict[str, Any]) -> bool:
    event_type = raw.get("event_type", {}) or {}
    primary_tag = (event_type.get(".tag") or "").lower()
    nested = event_type.get(primary_tag, {}) if isinstance(event_type.get(primary_tag), dict) else {}
    nested_tag = (nested.get(".tag") or "").lower()
    return any(keyword in (primary_tag, nested_tag) for keyword in ("fail", "denied", "suspicious"))


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
@@ -162,35 +210,94 @@ def normalize_google(event: Dict[str, Any], account_id: str, resolver: GeoResolv
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


def normalize_dropbox(event: Dict[str, Any], account_id: str, resolver: GeoResolver) -> NormalizedEvent:
    timestamp = event.get("timestamp") or event.get("time")
    ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00")) if isinstance(timestamp, str) else datetime.utcnow()

    actor = event.get("actor", {}) or {}
    username = None
    if actor.get(".tag") == "user":
        user_info = actor.get("user", {}) or {}
        username = user_info.get("email") or user_info.get("display_name")
    elif actor.get(".tag") == "admin":
        admin_info = actor.get("admin", {}) or {}
        username = admin_info.get("email") or admin_info.get("display_name")

    geo = _geo_from_dropbox(event, resolver)
    auth_score = dropbox_confidence(event)
    anomaly = dropbox_session_anomaly(event)
    risk_level = _risk_level(auth_score, anomaly)
    signals = SignalVector(
        auth_confidence=auth_score,
        geo_risk=dropbox_geo_risk(event),
        session_anomaly=anomaly,
        risk_level=risk_level,
    )

    event_type = event.get("event_type", {}) or {}
    primary_tag = event_type.get(".tag") or ""
    nested = event_type.get(primary_tag, {}) if isinstance(event_type.get(primary_tag), dict) else {}
    nested_tag = nested.get(".tag") if isinstance(nested, dict) else None
    description = (
        nested.get("description")
        if isinstance(nested, dict) and nested.get("description")
        else event_type.get("description")
    )

    risk_tags: List[str] = []
    if anomaly:
        risk_tags.append("risky_sign_in")
    if nested_tag and "fail" in nested_tag.lower():
        risk_tags.append("failed_login")

    return NormalizedEvent(
        id=event.get("event_uuid") or event.get("event_id") or f"dropbox:{ts.isoformat()}",
        provider="dropbox",
        account_id=account_id,
        timestamp=ts,
        user_hash=hash_user(username),
        username=username,
        geo=geo,
        signals=signals,
        raw=event,
        risk_tags=risk_tags,
        insights={
            "event_type": primary_tag,
            "event_subtype": nested_tag,
            "description": description,
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