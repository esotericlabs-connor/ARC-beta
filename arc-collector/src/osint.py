"""OSINT correlation helpers for the ARC collector."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List

from .models import NormalizedEvent


@dataclass
class Indicator:
    type: str
    value: str
    label: str

    def matches(self, event: NormalizedEvent) -> bool:
        if self.type == "ip":
            ip = event.geo.ip
            if not ip:
                return False
            try:
                network = ipaddress.ip_network(self.value)
                return ipaddress.ip_address(ip) in network
            except ValueError:
                return False
        return False


def load_indicators(path: Path) -> List[Indicator]:
    data = json.loads(path.read_text())
    return [Indicator(**item) for item in data]


def correlate_events(events: Iterable[NormalizedEvent], indicators: Iterable[Indicator]) -> List[str]:
    matches: List[str] = []
    indicator_list = list(indicators)
    for event in events:
        for indicator in indicator_list:
            if indicator.matches(event):
                label = indicator.label
                matches.append(f"OSINT match for {event.geo.ip}: {label}")
    return sorted(set(matches))


__all__ = ["Indicator", "load_indicators", "correlate_events"]