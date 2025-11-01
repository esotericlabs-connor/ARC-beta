"""IP geolocation heuristics."""
from __future__ import annotations

import ipaddress
import math
import re
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Dict, Iterable as TypingIterable, List, Optional, Sequence, Union

from ..models import SignalContribution
from ..utils.indicator_store import get_indicator_manager

TRUSTED_IP_METADATA_KEYS: Sequence[str] = (
    "trusted_ip_ranges",
    "allowlisted_ip_ranges",
    "user_trusted_ips",
)

TRUSTED_ASN_METADATA_KEYS: Sequence[str] = (
    "trusted_asns",
    "allowlisted_asns",
    "user_trusted_asns",
)

IMPOSSIBLE_TRAVEL_SPEED_KMH = 900.0
TZ_OFFSET_RE = re.compile(r"^(?:UTC|GMT)?\s*([+-])(\d{1,2})(?::?(\d{2}))?$")


def analyze_ip_geolocation(metadata: Dict[str, Optional[str]]) -> SignalContribution:
    """Identify geolocation anomalies based on sender IP."""

    indicator_store = get_indicator_manager()
    indicator_store.ingest_metadata(
        metadata,
        {
            "reputable_isps": {
                "keys": ["trusted_isps", "osint_trusted_isps", "isp_allowlist"],
                "kind": "keyword",
                "confidence": 0.95,
            },
            "suspicious_isps": {
                "keys": ["suspicious_isps", "osint_suspicious_isps", "isp_watchlist"],
                "kind": "keyword",
                "confidence": 0.8,
            },
            "trusted_hostnames": {
                "keys": ["trusted_hostnames", "osint_trusted_hostnames"],
                "kind": "keyword",
                "confidence": 0.9,
            },
            "risky_hostnames": {
                "keys": ["risky_hostnames", "osint_risky_hostnames"],
                "kind": "keyword",
                "confidence": 0.8,
            },
            "trusted_asn_prefixes": {
                "keys": ["trusted_asns", "osint_trusted_asns"],
                "kind": "keyword",
                "confidence": 0.95,
            },
            "suspicious_asn_keywords": {
                "keys": ["suspicious_asn_keywords", "osint_suspicious_asn_keywords"],
                "kind": "keyword",
                "confidence": 0.8,
            },
            "blacklisted_networks": {
                "keys": ["blacklisted_networks", "osint_blacklisted_networks", "ip_blacklist_networks"],
                "kind": "network",
                "confidence": 0.9,
            },
        },
        source_prefix="ip_geolocation",
    )

    reputable_isps = indicator_store.keywords("reputable_isps")
    suspicious_isps = indicator_store.keywords("suspicious_isps")
    trusted_hostnames = indicator_store.keywords("trusted_hostnames")
    risky_hostnames = indicator_store.keywords("risky_hostnames")
    trusted_asn_prefixes = indicator_store.keywords("trusted_asn_prefixes", case="upper")
    suspicious_asn_keywords = indicator_store.keywords("suspicious_asn_keywords")
    blacklisted_networks = indicator_store.networks("blacklisted_networks")

    ip_text = metadata.get("source_ip") or ""
    weight = 0.9
    score = 0.0
    trust_offset = 0.0
    details: Dict[str, object] = {}

    if not ip_text:
        return SignalContribution(name="ip_geolocation", score=score, weight=weight, details=details)

    try:
        ip_obj = ipaddress.ip_address(ip_text)
    except ValueError:
        details["invalid_ip"] = ip_text
        return SignalContribution(name="ip_geolocation", score=65.0, weight=weight, details=details)

    details["ip_version"] = ip_obj.version

    if ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_loopback:
        score += 35
        details["network_flag"] = "non_routable"
    elif ip_obj.is_global:
        details["network_flag"] = "global"

    blacklists = _extract_blacklist_hits(metadata)
    if blacklists:
        score += 60
        details["blacklist_matches"] = blacklists

    matched_networks = _matched_networks(ip_obj, blacklisted_networks)
    if matched_networks:
        score += 45
        details["network_matches"] = matched_networks

    trusted_networks = _trusted_networks(ip_obj, metadata)
    if trusted_networks:
        trust_offset += 35
        details["trusted_networks"] = trusted_networks

    isp = (metadata.get("source_ip_isp") or metadata.get("source_isp") or "").strip()
    if isp:
        details["isp"] = isp
        lowered = isp.lower()
        reputable_keywords = {keyword.lower() for keyword in reputable_isps}
        suspicious_keywords = {keyword.lower() for keyword in suspicious_isps}
        if any(keyword in lowered for keyword in reputable_keywords):
            details["trusted_isp"] = True
            indicator_store.add_keyword(
                "reputable_isps",
                isp,
                source="ip_geolocation:observed_isp",
                confidence=0.7,
            )
        elif any(keyword in lowered for keyword in suspicious_keywords):
            score += 40
            details["risky_isp"] = isp
            indicator_store.add_keyword(
                "suspicious_isps",
                isp,
                source="ip_geolocation:observed_isp",
                confidence=0.75,
            )
        else:
            score += 15
            details["unrecognized_isp"] = True
    else:
        score += 10
        details["missing_isp"] = True

    hostname = (metadata.get("source_ip_hostname") or metadata.get("reverse_dns") or "").strip()
    if hostname:
        details["hostname"] = hostname
        hostname_assessment = _evaluate_hostname(hostname, risky_hostnames, trusted_hostnames)
        if hostname_assessment["risk"]:
            score += hostname_assessment["risk"]
            indicator_store.add_keyword(
                "risky_hostnames",
                hostname.lower(),
                source="ip_geolocation:observed_hostname",
                confidence=0.75,
            )
        if hostname_assessment["trust"]:
            trust_offset += hostname_assessment["trust"]
            indicator_store.add_keyword(
                "trusted_hostnames",
                hostname.lower(),
                source="ip_geolocation:observed_hostname",
                confidence=0.7,
            )
        if hostname_assessment["reasons"]:
            details["hostname_flags"] = hostname_assessment["reasons"]

    asn = str(metadata.get("source_ip_asn") or metadata.get("asn") or "").strip()
    if asn:
        details["asn"] = asn
        asn_upper = asn.upper()
        trusted_asn_hits = [prefix for prefix in trusted_asn_prefixes if prefix in asn_upper]
        if trusted_asn_hits:
            trust_offset += 30
            details.setdefault("trusted_asn_matches", []).extend(sorted(set(trusted_asn_hits)))
            indicator_store.add_keyword(
                "trusted_asn_prefixes",
                asn_upper,
                source="ip_geolocation:observed_asn",
                confidence=0.8,
            )

        risky_asn_hits = [
            keyword
            for keyword in suspicious_asn_keywords
            if keyword.lower() in asn_upper.lower()
        ]
        if risky_asn_hits:
            score += 35
            details["risky_asn_keywords"] = risky_asn_hits
            indicator_store.add_keyword(
                "suspicious_asn_keywords",
                asn_upper,
                source="ip_geolocation:observed_asn",
                confidence=0.8,
            )

        metadata_asn_hits = _trusted_asn_matches(asn_upper, metadata)
        if metadata_asn_hits:
            trust_offset += 25
            details.setdefault("trusted_asn_matches", []).extend(metadata_asn_hits)

    reputation_score = _as_float(
        metadata.get("source_ip_reputation")
        or metadata.get("ip_reputation_score")
        or metadata.get("source_ip_risk_score")
    )
    if reputation_score is not None:
        details["reputation_score"] = reputation_score
        if reputation_score >= 80:
            score += 45
        elif reputation_score >= 60:
            score += 25
        elif reputation_score <= 20:
            trust_offset += 20

    geo_details = _collect_geolocation(metadata)
    if geo_details:
        details["geo"] = geo_details

    confidence = _geo_confidence(metadata, geo_details)
    if confidence:
        details["geo_confidence"] = confidence

    profile_context = _profile_context(metadata)
    impossible = _detect_impossible_travel(metadata, geo_details)
    if impossible:
        score += 40
        details["impossible_travel"] = impossible

    unexpected_geo = _geo_mismatch(profile_context, geo_details)
    if unexpected_geo:
        score += 25
        details["geo_mismatch"] = unexpected_geo

    timezone_gap = _timezone_gap(metadata, geo_details)
    if timezone_gap is not None:
        score += 20
        details["timezone_gap_hours"] = timezone_gap

    if ip_obj.version == 6:
        score += 5
        details["ipv6"] = True

    if trust_offset:
        score = max(score - trust_offset, 0.0)
        details["trust_offset"] = round(trust_offset, 2)

    score = min(score, 100.0)
    details["risk_level"] = _score_to_risk_level(score)
    return SignalContribution(name="ip_geolocation", score=score, weight=weight, details=details)


def _extract_blacklist_hits(metadata: Dict[str, Optional[str]]) -> List[str]:
    hits = metadata.get("source_ip_blacklists") or metadata.get("ip_blacklist_hits")
    if isinstance(hits, str):
        return [entry.strip() for entry in hits.split(",") if entry.strip()]
    if isinstance(hits, Iterable):
        return [str(entry) for entry in hits]
    return []


def _matched_networks(
    ip_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
    networks: Sequence[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]],
) -> List[str]:
    matches = []
    for network in networks:
        if ip_obj in network:
            matches.append(str(network))
    return matches


def _trusted_networks(
    ip_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
    metadata: Dict[str, Optional[str]],
) -> List[str]:
    matches: List[str] = []
    for key in TRUSTED_IP_METADATA_KEYS:
        networks = _networks_from_metadata(metadata.get(key))
        for network in networks:
            if ip_obj in network:
                matches.append(str(network))
    return sorted(set(matches))


def _collect_geolocation(metadata: Dict[str, Optional[str]]) -> Dict[str, object]:
    geo_keys = {
        "country": ["source_ip_country", "geoip_country", "source_country"],
        "region": ["source_ip_region", "geoip_region", "source_region"],
        "city": ["source_ip_city", "geoip_city", "source_city"],
        "latitude": ["source_ip_lat", "source_ip_latitude", "geoip_lat"],
        "longitude": ["source_ip_lon", "source_ip_longitude", "geoip_lon"],
        "timestamp": ["source_ip_timestamp", "received_at", "timestamp"],
        "timezone": ["source_ip_timezone", "geoip_timezone", "timezone"],
        "accuracy": ["source_ip_accuracy_km", "geoip_accuracy", "accuracy"],
        "provider": ["geo_provider", "geoip_source", "ip_locator"],
    }

    geo: Dict[str, object] = {}
    for key, options in geo_keys.items():
        for option in options:
            value = metadata.get(option)
            if value is not None:
                geo[key] = value
                break
    return geo


def _profile_context(metadata: Dict[str, Optional[str]]) -> Dict[str, object]:
    profile = metadata.get("user_profile")
    if isinstance(profile, dict):
        return profile

    context: Dict[str, object] = {}
    for key in ("user_timezone", "user_country", "user_region", "home_country", "home_region"):
        if metadata.get(key) is not None:
            context[key] = metadata[key]
    return context


def _geo_mismatch(profile: Dict[str, object], geo: Dict[str, object]) -> Optional[Dict[str, object]]:
    if not profile or not geo:
        return None

    expected_country = str(profile.get("home_country") or profile.get("user_country") or "").lower()
    observed_country = str(geo.get("country") or "").lower()

    if expected_country and observed_country and expected_country != observed_country:
        return {
            "expected_country": expected_country,
            "observed_country": observed_country,
        }
    return None


def _detect_impossible_travel(metadata: Dict[str, Optional[str]], geo: Dict[str, object]) -> Optional[Dict[str, object]]:
    if not geo:
        return None

    current_time = _parse_datetime(geo.get("timestamp") or metadata.get("message_timestamp") or metadata.get("timestamp"))
    current_lat = _as_float(geo.get("latitude"))
    current_lon = _as_float(geo.get("longitude"))

    if current_time is None or current_lat is None or current_lon is None:
        return None

    history = metadata.get("recent_login_locations") or metadata.get("user_recent_locations")
    if not isinstance(history, list):
        return None

    for entry in history:
        if not isinstance(entry, dict):
            continue
        previous_time = _parse_datetime(entry.get("timestamp") or entry.get("time"))
        prev_lat = _as_float(entry.get("latitude"))
        prev_lon = _as_float(entry.get("longitude"))
        if previous_time is None or prev_lat is None or prev_lon is None:
            continue

        hours = abs((current_time - previous_time).total_seconds()) / 3600.0
        if hours == 0:
            continue

        distance = _haversine(prev_lat, prev_lon, current_lat, current_lon)
        speed = distance / hours
        if speed > IMPOSSIBLE_TRAVEL_SPEED_KMH:
            return {
                "from": entry.get("label") or entry.get("country"),
                "to": geo.get("city") or geo.get("country"),
                "distance_km": round(distance, 1),
                "hours_between": round(hours, 2),
            }
    return None


def _timezone_gap(metadata: Dict[str, Optional[str]], geo: Dict[str, object]) -> Optional[float]:
    user_timezone = metadata.get("user_timezone") or metadata.get("profile_timezone")
    geo_timezone = geo.get("timezone") or metadata.get("source_ip_timezone")

    user_offset = _parse_timezone_offset(user_timezone)
    geo_offset = _parse_timezone_offset(geo_timezone)

    if user_offset is None or geo_offset is None:
        return None

    gap = abs(user_offset - geo_offset)
    if gap >= 6:
        return round(gap, 2)
    return None


def _parse_datetime(value: object) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        try:
            return datetime.utcfromtimestamp(float(value))
        except (OSError, ValueError, OverflowError):
            return None
    if isinstance(value, str):
        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(value, fmt)
                if dt.tzinfo is None:
                    return dt
                return dt.astimezone(timezone.utc).replace(tzinfo=None)
            except ValueError:
                continue
    return None


def _as_float(value: object) -> Optional[float]:
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    radius = 6371.0
    lat1_rad, lon1_rad = math.radians(lat1), math.radians(lon1)
    lat2_rad, lon2_rad = math.radians(lat2), math.radians(lon2)

    dlat = lat2_rad - lat1_rad
    dlon = lon2_rad - lon1_rad

    a = math.sin(dlat / 2) ** 2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return radius * c


def _networks_from_metadata(value: object) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
    if value is None:
        return networks

    items: Iterable[object]
    if isinstance(value, str):
        items = [entry.strip() for entry in value.split(",") if entry.strip()]
    elif isinstance(value, Iterable):
        items = value
    else:
        return networks

    for item in items:
        try:
            networks.append(ipaddress.ip_network(str(item), strict=False))
        except ValueError:
            continue
    return networks


def _trusted_asn_matches(asn_text: str, metadata: Dict[str, Optional[str]]) -> List[str]:
    matches: List[str] = []
    for key in TRUSTED_ASN_METADATA_KEYS:
        raw = metadata.get(key)
        if raw is None:
            continue
        if isinstance(raw, str):
            values = [entry.strip().upper() for entry in raw.split(",") if entry.strip()]
        elif isinstance(raw, Iterable):
            values = [str(entry).strip().upper() for entry in raw if str(entry).strip()]
        else:
            continue
        for value in values:
            if value and value in asn_text:
                matches.append(value)
    return sorted(set(matches))


def _evaluate_hostname(
    hostname: str,
    risky_keywords: TypingIterable[str],
    trusted_keywords: TypingIterable[str],
) -> Dict[str, object]:
    lowered = hostname.lower()
    risk_hits = [keyword for keyword in risky_keywords if keyword in lowered]
    trust_hits = [keyword for keyword in trusted_keywords if keyword in lowered]

    risk_score = 0.0
    trust_score = 0.0

    if risk_hits:
        risk_score += 25
    if trust_hits:
        trust_score += 20

    reasons: Dict[str, List[str]] = {}
    if risk_hits:
        reasons["risk_hits"] = risk_hits
    if trust_hits:
        reasons["trust_hits"] = trust_hits

    return {
        "risk": risk_score,
        "trust": trust_score,
        "reasons": reasons,
    }


def _geo_confidence(metadata: Dict[str, Optional[str]], geo: Dict[str, object]) -> Optional[Dict[str, object]]:
    accuracy_candidates = (
        geo.get("accuracy"),
        metadata.get("geoip_accuracy_radius"),
        metadata.get("source_ip_accuracy_km"),
    )

    for candidate in accuracy_candidates:
        radius = _as_float(candidate)
        if radius is None or radius <= 0:
            continue
        if radius <= 25:
            level = "city"
        elif radius <= 100:
            level = "regional"
        else:
            level = "country"
        return {"radius_km": round(radius, 1), "level": level}

    provider = geo.get("provider") or metadata.get("geo_provider") or metadata.get("geoip_source")
    if provider:
        return {"provider": provider}
    return None


def _parse_timezone_offset(value: object) -> Optional[float]:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value:
        return None
    match = TZ_OFFSET_RE.match(value)
    if not match:
        return None
    sign, hours_text, minutes_text = match.groups()
    hours = int(hours_text)
    minutes = int(minutes_text or 0)
    offset = hours + minutes / 60.0
    if sign == "-":
        offset *= -1
    return offset


def _score_to_risk_level(score: float) -> str:
    if score >= 75:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


__all__ = ["analyze_ip_geolocation"]