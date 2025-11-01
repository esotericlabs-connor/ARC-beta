"""Geolocation helpers for the ARC collector."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional

try:
    import geoip2.database
except Exception:  # pragma: no cover - optional dependency
    geoip2 = None  # type: ignore


@dataclass
class GeoLookupResult:
    ip: Optional[str]
    country: Optional[str]
    region: Optional[str]
    city: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]
    asn: Optional[str]


class GeoResolver:
    """Resolve IP addresses into GeoLookupResult records."""

    def __init__(self, database_path: Optional[str] = None) -> None:
        self._reader = None
        if database_path and geoip2:
            try:
                self._reader = geoip2.database.Reader(database_path)
            except FileNotFoundError:
                self._reader = None

    def resolve(self, ip: Optional[str]) -> GeoLookupResult:
        if not ip:
            return GeoLookupResult(None, None, None, None, None, None, None)
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_reserved:
                return GeoLookupResult(ip, None, None, None, None, None, None)
        except ValueError:
            return GeoLookupResult(ip, None, None, None, None, None, None)

        if not self._reader:
            return GeoLookupResult(ip, None, None, None, None, None, None)

        try:  # pragma: no cover - requires geoip database
            city = self._reader.city(ip)
            asn = None
            try:
                if hasattr(self._reader, "asn"):
                    asn = self._reader.asn(ip).autonomous_system_number
            except Exception:
                asn = None
            country = city.country.iso_code
            region = city.subdivisions[0].name if city.subdivisions else None
            return GeoLookupResult(
                ip=ip,
                country=country,
                region=region,
                city=city.city.name,
                latitude=city.location.latitude,
                longitude=city.location.longitude,
                asn=f"AS{asn}" if asn else None,
            )
        except Exception:
            return GeoLookupResult(ip, None, None, None, None, None, None)

    def close(self) -> None:
        if self._reader:
            try:
                self._reader.close()
            except Exception:  # pragma: no cover
                pass


__all__ = ["GeoResolver", "GeoLookupResult"]