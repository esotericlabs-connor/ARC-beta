"""Community-driven threat intelligence aggregation."""
from __future__ import annotations

import json
import os
import threading
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence

from ..models import SignalContribution
from .indicator_store import get_indicator_manager

DEFAULT_INTEL_PATH = Path(os.getenv("AETA_COMMUNITY_INTEL", "")).expanduser()
if not DEFAULT_INTEL_PATH:
    DEFAULT_INTEL_PATH = Path.home() / ".aeta" / "community_intel.json"

MAX_EVENTS = 1024


@dataclass
class CommunitySnapshot:
    """Summarised threat data for presentation."""

    generated_at: str
    totals: Mapping[str, int]
    top_domains: Sequence[Mapping[str, object]]
    top_networks: Sequence[Mapping[str, object]]
    top_countries: Sequence[Mapping[str, object]]
    threat_trends: Sequence[Mapping[str, object]]
    recent_events: Sequence[Mapping[str, object]]


class CommunityIntelHub:
    """Coordinates community threat submissions and aggregates telemetry."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = Path(path) if path else DEFAULT_INTEL_PATH
        self._lock = threading.RLock()
        self._state: Dict[str, object] = {"events": []}
        self._ensure_parent()
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def record_observation(
        self,
        metadata: Mapping[str, object],
        contributions: Sequence[SignalContribution],
        *,
        verdict: str,
        risk_score: float,
    ) -> None:
        """Store an anonymised observation and update dynamic indicators."""

        with self._lock:
            indicator_manager = get_indicator_manager()
            timestamp = datetime.now(tz=timezone.utc).isoformat()
            domain = _sanitize_domain(metadata.get("from_domain"))
            subject = _redact_subject(metadata.get("subject"))
            ip_prefix = _truncate_ip(metadata.get("source_ip"))
            geo = _geo_from_contributions(contributions)
            threat_tags = _threat_tags(contributions)

            event: MutableMapping[str, object] = {
                "timestamp": timestamp,
                "verdict": verdict,
                "risk": round(risk_score, 2),
                "threat_tags": threat_tags,
            }
            if domain:
                event["domain"] = domain
            if ip_prefix:
                event["ip_prefix"] = ip_prefix
            if geo:
                event["geo"] = geo
            if subject:
                event["subject"] = subject

            events: List[MutableMapping[str, object]] = self._state.setdefault("events", [])  # type: ignore[assignment]
            events.append(event)
            if len(events) > MAX_EVENTS:
                del events[: len(events) - MAX_EVENTS]

            if domain and risk_score >= 60:
                indicator_manager.add_keyword(
                    "risky_hostnames",
                    domain,
                    source="community_intel:domain",
                    confidence=0.65,
                )
            if ip_prefix and risk_score >= 70:
                indicator_manager.add_network(
                    "blacklisted_networks",
                    ip_prefix,
                    source="community_intel:network",
                    confidence=0.7,
                )

            self._save()
def ingest_external_event(self, payload: Mapping[str, object]) -> None:
        """Persist a community event submitted via the external API."""

        with self._lock:
            indicator_manager = get_indicator_manager()
            timestamp_value = payload.get("timestamp")
            if isinstance(timestamp_value, str) and timestamp_value.strip():
                timestamp = timestamp_value.strip()
            else:
                timestamp = datetime.now(tz=timezone.utc).isoformat()

            risk_value = payload.get("risk") or payload.get("score") or 0.0
            try:
                risk_score = max(0.0, min(100.0, float(risk_value)))
            except (TypeError, ValueError):
                risk_score = 0.0

            verdict = str(payload.get("verdict") or payload.get("classification") or "external")
            domain = _sanitize_domain(payload.get("domain"))
            ip_prefix = payload.get("ip_prefix") or payload.get("ip") or payload.get("source_ip")
            ip_prefix = _truncate_ip(ip_prefix)
            subject = payload.get("subject")
            tags = _normalise_tags(payload.get("threat_tags"))

            geo_payload = payload.get("geo")
            geo: Dict[str, object] = {}
            if isinstance(geo_payload, Mapping):
                for key in ("country", "city", "latitude", "longitude"):
                    value = geo_payload.get(key)
                    if value is not None:
                        geo[key] = value
            else:
                for key in ("geo_country", "geo_city"):
                    value = payload.get(key)
                    if value:
                        geo[key.split("_")[-1]] = value

            event: MutableMapping[str, object] = {
                "timestamp": timestamp,
                "verdict": verdict,
                "risk": round(risk_score, 2),
                "threat_tags": tags,
            }
            source = payload.get("source") or payload.get("provider")
            if source:
                event["source"] = str(source)
            if domain:
                event["domain"] = domain
            if ip_prefix:
                event["ip_prefix"] = ip_prefix
            if subject:
                event["subject"] = _redact_subject(subject)
            if geo:
                event["geo"] = geo

            events: List[MutableMapping[str, object]] = self._state.setdefault("events", [])  # type: ignore[assignment]
            events.append(event)
            if len(events) > MAX_EVENTS:
                del events[: len(events) - MAX_EVENTS]

            if domain and risk_score >= 60:
                indicator_manager.add_keyword(
                    "risky_hostnames",
                    domain,
                    source="community_intel:external",
                    confidence=0.6,
                )
            if ip_prefix and risk_score >= 70:
                indicator_manager.add_network(
                    "blacklisted_networks",
                    ip_prefix,
                    source="community_intel:external",
                    confidence=0.65,
                )

            self._save()
    def snapshot(self) -> CommunitySnapshot:
        """Return a summary suitable for dashboards."""

        with self._lock:
            events = list(self._state.get("events", []))

        domain_counter = Counter()
        network_counter = Counter()
        country_counter = Counter()
        tag_counter = Counter()

        for event in events:
            domain = event.get("domain")
            if domain:
                domain_counter[domain] += 1
            ip_prefix = event.get("ip_prefix")
            if ip_prefix:
                network_counter[ip_prefix] += 1
            geo = event.get("geo") or {}
            country = geo.get("country")
            if country:
                country_counter[str(country)] += 1
            for tag in event.get("threat_tags", []):
                tag_counter[str(tag)] += 1

        top_domains = _top_entries(domain_counter)
        top_networks = _top_entries(network_counter)
        top_countries = _top_entries(country_counter)
        threat_trends = _top_entries(tag_counter)
        recent_events = list(reversed(events[-10:]))

        totals = {
            "events": len(events),
            "unique_domains": len(domain_counter),
            "unique_networks": len(network_counter),
            "unique_countries": len(country_counter),
        }

        return CommunitySnapshot(
            generated_at=datetime.now(tz=timezone.utc).isoformat(),
            totals=totals,
            top_domains=top_domains,
            top_networks=top_networks,
            top_countries=top_countries,
            threat_trends=threat_trends,
            recent_events=recent_events,
        )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _ensure_parent(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> None:
        try:
            with self._path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except FileNotFoundError:
            return
        except json.JSONDecodeError:
            return
        if isinstance(payload, dict):
            self._state.update(payload)

    def _save(self) -> None:
        temp_path = self._path.with_suffix(".tmp")
        with temp_path.open("w", encoding="utf-8") as handle:
            json.dump(self._state, handle, indent=2, sort_keys=True)
        temp_path.replace(self._path)


_community_hub: Optional[CommunityIntelHub] = None
_hub_lock = threading.Lock()


def get_community_hub() -> CommunityIntelHub:
    """Return the shared community intelligence hub."""

    global _community_hub
    with _hub_lock:
        if _community_hub is None:
            _community_hub = CommunityIntelHub()
        return _community_hub


def reset_community_hub() -> None:
    """Reset the shared hub (used in tests)."""

    global _community_hub
    with _hub_lock:
        _community_hub = None


# ----------------------------------------------------------------------
# Helper utilities
# ----------------------------------------------------------------------
def _sanitize_domain(value: object) -> str:
    if not value:
        return ""
    return str(value).strip().lower()


def _redact_subject(value: object) -> str:
    if not value:
        return ""
    subject = str(value).strip()
    if len(subject) <= 6:
        return "*" * len(subject)
    return subject[:3] + "…" + subject[-3:]


def _truncate_ip(value: object) -> str:
    if not value:
        return ""
    try:
        address = ip_address(str(value))
    except ValueError:
        return ""
    network = ip_network(f"{address}/24" if address.version == 4 else f"{address}/48", strict=False)
    return str(network)


def _geo_from_contributions(contributions: Sequence[SignalContribution]) -> Dict[str, object]:
    for contribution in contributions:
        if contribution.name != "ip_geolocation":
            continue
        details = contribution.details
        geo = details.get("geo") if isinstance(details, dict) else None
        if isinstance(geo, Mapping):
            result: Dict[str, object] = {}
            for key in ("country", "city", "latitude", "longitude"):
                value = geo.get(key)
                if value is not None:
                    result[key] = value
            return result
    return {}
def _threat_tags(contributions: Sequence[SignalContribution]) -> List[str]:
    tags: List[str] = []
    for contribution in contributions:
        if contribution.score >= 60:
            tags.append(contribution.name)
    return sorted(set(tags))

def _top_entries(counter: Counter) -> List[Dict[str, object]]:
    results: List[Dict[str, object]] = []
    for value, count in counter.most_common(10):
        results.append({"value": value, "count": count})
    return results
def _normalise_tags(value: object) -> List[str]:
    if isinstance(value, str):
        candidate = value.strip()
        return [candidate] if candidate else []
    if isinstance(value, Iterable):
        results = [str(item).strip() for item in value if str(item).strip()]
        return sorted(set(results))
    return []
__all__ = [
    "CommunityIntelHub",
    "CommunitySnapshot",
    "get_community_hub",
    "reset_community_hub",
]
