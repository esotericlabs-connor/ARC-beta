"""Realtime OSINT aggregation for the ARC collector."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence

import httpx

try:
    from .models import NormalizedEvent
except ImportError:  # pragma: no cover - allow standalone imports in tests
    import importlib

    NormalizedEvent = importlib.import_module("models").NormalizedEvent  # type: ignore[attr-defined]

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Indicator:
    """Threat intelligence indicator used for correlation."""

    type: str
    value: str
    label: str
    source: str
    confidence: Optional[float] = None

    def matches(self, event: NormalizedEvent) -> bool:
        """Return ``True`` if the indicator applies to ``event``."""

        if self.type in {"ip", "ipv4", "ipv6"}:
            ip = event.geo.ip
            if not ip:
                return False
            try:
                indicator_ip = ipaddress.ip_address(self.value)
                return ipaddress.ip_address(ip) == indicator_ip
            except ValueError:
                return False
        if self.type in {"cidr", "network"}:
            ip = event.geo.ip
            if not ip:
                return False
            try:
                network = ipaddress.ip_network(self.value, strict=False)
                return ipaddress.ip_address(ip) in network
            except ValueError:
                return False
        if self.type == "asn":
            asn = (event.geo.asn or "").upper()
            value = self.value.upper()
            if not asn:
                return False
            if not value.startswith("AS"):
                value = f"AS{value}"
            return asn == value
        return False

    def describe(self, event: NormalizedEvent) -> str:
        """Return a human readable summary for dashboards."""

        confidence = f" (confidence {self.confidence:.0f}%)" if self.confidence is not None else ""
        ip = event.geo.ip or "unknown IP"
        return (
            f"{event.provider.title()} account activity from {ip} flagged by {self.source}: "
            f"{self.label}{confidence}"
        )


class OSINTSource:
    """Base interface for OSINT feeds."""

    name: str

    async def fetch(self) -> Sequence[Indicator]:  # pragma: no cover - interface
        raise NotImplementedError


class FeodoTrackerSource(OSINTSource):
    """Abuse.ch Feodo Tracker IP blocklist."""

    name = "Feodo Tracker"
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"

    async def fetch(self) -> Sequence[Indicator]:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(self.url)
            response.raise_for_status()
            payload = response.json()

        entries = payload.get("data") or payload
        indicators: List[Indicator] = []
        for item in entries:
            ip_value = item.get("ip_address") or item.get("ip")
            if not ip_value:
                continue
            description = item.get("description") or item.get("threat") or "Command and control host"
            indicators.append(
                Indicator(
                    type="ip",
                    value=str(ip_value).strip(),
                    label=description,
                    source=self.name,
                )
            )
        return indicators


class ThreatFoxSource(OSINTSource):
    """Abuse.ch ThreatFox API (malicious C2 infrastructure)."""

    name = "ThreatFox"
    url = "https://threatfox-api.abuse.ch/api/v1/"

    async def fetch(self) -> Sequence[Indicator]:
        payload = {"query": "get_iocs", "days": 7, "threat_type": "botnet_cc", "limit": 200}
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(self.url, json=payload)
            response.raise_for_status()
            data = response.json()

        indicators: List[Indicator] = []
        for item in data.get("data", []):
            indicator = item.get("ioc")
            ioc_type = item.get("ioc_type")
            if not indicator or ioc_type not in {"ipv4", "ipv6"}:
                continue
            label = item.get("malware") or item.get("threat_type") or "ThreatFox IOC"
            confidence = item.get("confidence_level")
            indicators.append(
                Indicator(
                    type="ip",
                    value=str(indicator).strip(),
                    label=label,
                    source=self.name,
                    confidence=float(confidence) if confidence is not None else None,
                )
            )
        return indicators


class TorExitSource(OSINTSource):
    """Tor Project exit node list."""

    name = "Tor Exit Nodes"
    url = "https://check.torproject.org/torbulkexitlist"

    async def fetch(self) -> Sequence[Indicator]:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(self.url)
            response.raise_for_status()
            text = response.text

        indicators: List[Indicator] = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                ipaddress.ip_address(stripped)
            except ValueError:
                continue
            indicators.append(
                Indicator(
                    type="ip",
                    value=stripped,
                    label="Tor exit node",
                    source=self.name,
                )
            )
        return indicators


class AbuseIPDBSource(OSINTSource):
    """AbuseIPDB blacklist feed."""

    name = "AbuseIPDB"

    def __init__(self, api_key: str, *, minimum_confidence: int = 90) -> None:
        self._api_key = api_key
        self._minimum_confidence = minimum_confidence

    async def fetch(self) -> Sequence[Indicator]:
        headers = {"Key": self._api_key, "Accept": "application/json"}
        params = {"confidenceMinimum": str(self._minimum_confidence)}
        url = "https://api.abuseipdb.com/api/v2/blacklist"
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(url, headers=headers, params=params)
            response.raise_for_status()
            payload = response.json()

        indicators: List[Indicator] = []
        for item in payload.get("data", []):
            ip_value = item.get("ipAddress")
            if not ip_value:
                continue
            confidence = item.get("abuseConfidenceScore")
            indicators.append(
                Indicator(
                    type="ip",
                    value=str(ip_value).strip(),
                    label="AbuseIPDB blacklist",
                    source=self.name,
                    confidence=float(confidence) if confidence is not None else None,
                )
            )
        return indicators


class AlienVaultOTXSource(OSINTSource):
    """AlienVault OTX pulse subscription feed."""

    name = "AlienVault OTX"

    def __init__(self, api_key: str, *, pages: int = 2) -> None:
        self._api_key = api_key
        self._pages = pages

    async def fetch(self) -> Sequence[Indicator]:
        headers = {"X-OTX-API-KEY": self._api_key}
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        indicators: List[Indicator] = []

        async with httpx.AsyncClient(timeout=30) as client:
            next_url: Optional[str] = url
            page = 0
            while next_url and page < self._pages:
                response = await client.get(next_url, headers=headers)
                if not response.is_success:
                    break
                payload = response.json()
                for pulse in payload.get("results", []):
                    pulse_name = pulse.get("name") or "AlienVault OTX pulse"
                    for indicator in pulse.get("indicators", []):
                        indicator_type = indicator.get("type")
                        if indicator_type not in {"IPv4", "IPv6"}:
                            continue
                        value = indicator.get("indicator")
                        if not value:
                            continue
                        confidence = indicator.get("confidence")
                        indicators.append(
                            Indicator(
                                type="ip",
                                value=str(value).strip(),
                                label=pulse_name,
                                source=self.name,
                                confidence=float(confidence) if confidence is not None else None,
                            )
                        )
                next_url = payload.get("next")
                page += 1

        return indicators


class OSINTClient:
    """Coordinator that maintains cached OSINT indicators and correlation helpers."""

    def __init__(self, sources: Sequence[OSINTSource], *, cache_ttl: int = 900) -> None:
        self._sources = list(sources)
        self._cache_ttl = cache_ttl
        self._cache: List[Indicator] = []
        self._cache_timestamp = 0.0
        self._lock = asyncio.Lock()

    @classmethod
    def from_settings(cls, settings) -> "OSINTClient":
        sources: List[OSINTSource] = []
        if getattr(settings, "osint_feodo_enabled", True):
            sources.append(FeodoTrackerSource())
        if getattr(settings, "osint_threatfox_enabled", True):
            sources.append(ThreatFoxSource())
        if getattr(settings, "osint_tor_enabled", True):
            sources.append(TorExitSource())
        if getattr(settings, "abuseipdb_api_key", None):
            sources.append(
                AbuseIPDBSource(
                    settings.abuseipdb_api_key,
                    minimum_confidence=getattr(settings, "abuseipdb_min_confidence", 90),
                )
            )
        if getattr(settings, "otx_api_key", None):
            sources.append(
                AlienVaultOTXSource(
                    settings.otx_api_key,
                    pages=getattr(settings, "otx_pages", 2),
                )
            )
        cache_ttl = int(getattr(settings, "osint_cache_ttl", 900))
        return cls(sources, cache_ttl=cache_ttl)

    async def _refresh_cache(self) -> None:
        now = time.time()
        if self._cache and now - self._cache_timestamp < self._cache_ttl:
            return
        if not self._sources:
            self._cache = []
            self._cache_timestamp = now
            return

        async with self._lock:
            if self._cache and now - self._cache_timestamp < self._cache_ttl:
                return
            indicators: List[Indicator] = []
            for source in self._sources:
                try:
                    fetched = await source.fetch()
                    indicators.extend(fetched)
                    logger.debug("Fetched %s indicators from %s", len(fetched), source.name)
                except httpx.HTTPError as exc:
                    logger.warning("OSINT source %s failed: %s", source.name, exc)
                except Exception:
                    logger.exception("Unexpected error while refreshing %s", source.name)
            # Deduplicate by value/type/source
            dedup: dict[tuple[str, str, str], Indicator] = {}
            for indicator in indicators:
                key = (indicator.type, indicator.value, indicator.source)
                dedup[key] = indicator
            self._cache = list(dedup.values())
            self._cache_timestamp = now

    async def indicators(self) -> Sequence[Indicator]:
        await self._refresh_cache()
        return list(self._cache)

    async def correlate_events(self, events: Iterable[NormalizedEvent]) -> List[str]:
        indicators = await self.indicators()
        if not indicators:
            return []
        matches: List[str] = []
        indicator_list = list(indicators)
        for event in events:
            for indicator in indicator_list:
                try:
                    if indicator.matches(event):
                        matches.append(indicator.describe(event))
                except Exception:
                    logger.exception("Error correlating indicator %s with event %s", indicator, event.id)
        # Preserve order while deduplicating
        seen = set()
        unique_matches: List[str] = []
        for item in matches:
            if item in seen:
                continue
            seen.add(item)
            unique_matches.append(item)
        return unique_matches


def correlate_events(events: Iterable[NormalizedEvent], indicators: Iterable[Indicator]) -> List[str]:
    """Legacy helper retained for compatibility and unit tests."""

    matches: List[str] = []
    indicator_list = list(indicators)
    for event in events:
        for indicator in indicator_list:
            if indicator.matches(event):
                matches.append(indicator.describe(event))
    seen = set()
    unique: List[str] = []
    for match in matches:
        if match in seen:
            continue
        seen.add(match)
        unique.append(match)
    return unique


def load_indicators(path) -> List[Indicator]:
    """Load indicators from disk (primarily for testing).

    The collector fetches indicators from realtime OSINT feeds by default,
    but this helper is maintained for unit tests that need deterministic
    fixtures.
    """

    data = json.loads(path.read_text())
    indicators = []
    for item in data:
        indicators.append(
            Indicator(
                type=item.get("type", "ip"),
                value=item["value"],
                label=item.get("label", "Static indicator"),
                source=item.get("source", "local"),
                confidence=item.get("confidence"),
            )
        )
    return indicators


__all__ = [
    "Indicator",
    "OSINTClient",
    "OSINTSource",
    "FeodoTrackerSource",
    "ThreatFoxSource",
    "TorExitSource",
    "AbuseIPDBSource",
    "AlienVaultOTXSource",
    "correlate_events",
    "load_indicators",
]
