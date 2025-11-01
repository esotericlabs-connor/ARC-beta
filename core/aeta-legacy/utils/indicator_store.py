"""Dynamic indicator repository for heuristic lookups."""
from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_network, IPv4Network, IPv6Network
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Set, Union

BASELINE_FILE = Path(__file__).resolve().parents[1] / "data" / "indicator_baseline.json"
DEFAULT_RUNTIME_PATH = Path(os.getenv("AETA_INDICATOR_STORE", "")).expanduser()
if not DEFAULT_RUNTIME_PATH:
    DEFAULT_RUNTIME_PATH = Path.home() / ".aeta" / "dynamic_indicators.json"

IndicatorValue = Union[str, Sequence[str]]
NetworkType = Union[IPv4Network, IPv6Network]


@dataclass
class PatternOverride:
    """Represents a compiled pattern override loaded from disk."""

    value: str
    source: str
    confidence: float
    first_seen: str


class DynamicIndicatorManager:
    """Loads and maintains dynamic indicator collections."""

    def __init__(self, runtime_path: Optional[Path] = None) -> None:
        self._baseline = self._load_baseline()
        self._runtime_path = Path(runtime_path) if runtime_path else DEFAULT_RUNTIME_PATH
        self._lock = threading.RLock()
        self._runtime_data: Dict[str, object] = {}
        self._runtime_mtime: Optional[float] = None
        self._ensure_runtime_dir()
        self._load_runtime()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def keywords(self, name: str, *, case: str = "lower") -> Set[str]:
        self._ensure_known_indicator(name)
        values = self._merged_keyword_values(name)
        if case == "lower":
            return {value.lower() for value in values}
        if case == "upper":
            return {value.upper() for value in values}
        return set(values)

    def pattern(self, name: str) -> PatternOverride:
        self._ensure_known_indicator(name)
        baseline_value = self._baseline.get(name, "")
        override = self._runtime_pattern(name)
        if override:
            return override
        return PatternOverride(
            value=str(baseline_value),
            source="baseline",
            confidence=1.0,
            first_seen="baseline",
        )

    def networks(self, name: str) -> List[NetworkType]:
        self._ensure_known_indicator(name)
        networks: List[NetworkType] = []
        baseline_items = self._baseline.get(name, [])
        for item in baseline_items:
            try:
                networks.append(ip_network(str(item), strict=False))
            except ValueError:
                continue
        for entry in self._runtime_list(name):
            value = str(entry.get("value", "")).strip()
            if not value:
                continue
            try:
                networks.append(ip_network(value, strict=False))
            except ValueError:
                continue
        return networks

    def ingest_metadata(
        self,
        metadata: Mapping[str, object],
        mapping: Mapping[str, Mapping[str, object]],
        *,
        source_prefix: str,
    ) -> None:
        """Update indicators based on metadata hints."""

        for indicator, descriptor in mapping.items():
            kind = descriptor.get("kind", "keyword")
            keys = descriptor.get("keys", [])
            confidence = float(descriptor.get("confidence", 0.6))
            for key in keys:
                raw = metadata.get(key)
                if raw in (None, ""):
                    continue
                source = f"{source_prefix}:{key}"
                if kind == "keyword":
                    for value in self._expand_values(raw):
                        self.add_keyword(indicator, value, source=source, confidence=confidence)
                elif kind == "network":
                    for value in self._expand_values(raw):
                        self.add_network(indicator, value, source=source, confidence=confidence)
                elif kind == "pattern":
                    pattern = str(raw).strip()
                    if pattern:
                        self.override_pattern(indicator, pattern, source=source, confidence=confidence)

    def add_keyword(self, name: str, value: str, *, source: str, confidence: float) -> None:
        self._ensure_known_indicator(name)
        normalized = value.strip()
        if not normalized:
            return
        baseline = {str(item).strip().lower() for item in self._baseline.get(name, [])}
        if normalized.lower() in baseline:
            return
        entries = self._runtime_list(name)
        if any(entry.get("value", "").lower() == normalized.lower() for entry in entries):
            return
        entries.append(
            {
                "value": normalized,
                "source": source,
                "confidence": round(confidence, 3),
                "first_seen": self._timestamp(),
            }
        )
        self._runtime_data[name] = entries
        self._save_runtime()

    def add_network(self, name: str, value: str, *, source: str, confidence: float) -> None:
        self._ensure_known_indicator(name)
        try:
            network_obj = ip_network(str(value), strict=False)
        except ValueError:
            return
        canonical = str(network_obj)
        baseline = {str(item).strip() for item in self._baseline.get(name, [])}
        if canonical in baseline:
            return
        entries = self._runtime_list(name)
        if any(entry.get("value") == canonical for entry in entries):
            return
        entries.append(
            {
                "value": canonical,
                "source": source,
                "confidence": round(confidence, 3),
                "first_seen": self._timestamp(),
            }
        )
        self._runtime_data[name] = entries
        self._save_runtime()

    def override_pattern(self, name: str, pattern: str, *, source: str, confidence: float) -> None:
        self._ensure_known_indicator(name)
        entry = {
            "value": pattern,
            "source": source,
            "confidence": round(confidence, 3),
            "first_seen": self._timestamp(),
        }
        self._runtime_data[f"pattern:{name}"] = entry
        self._save_runtime()

    def snapshot(self) -> Dict[str, object]:
        """Return a diagnostic snapshot of the indicator store."""

        with self._lock:
            self._maybe_reload_runtime()
            snapshot: Dict[str, object] = {"baseline": self._baseline, "runtime_path": str(self._runtime_path)}
            dynamic: Dict[str, object] = {}
            for key, value in self._runtime_data.items():
                if key.startswith("pattern:"):
                    dynamic[key] = value
                else:
                    dynamic[key] = list(value)  # type: ignore[arg-type]
            snapshot["dynamic"] = dynamic
            return snapshot

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _ensure_known_indicator(self, name: str) -> None:
        if name in self._baseline:
            return
        if name in self._runtime_data:
            return
        raise KeyError(f"Unknown indicator list '{name}'")

    def _ensure_runtime_dir(self) -> None:
        runtime_parent = self._runtime_path.parent
        runtime_parent.mkdir(parents=True, exist_ok=True)

    def _load_baseline(self) -> Dict[str, IndicatorValue]:
        if not BASELINE_FILE.exists():
            raise FileNotFoundError(f"Indicator baseline file missing: {BASELINE_FILE}")
        with BASELINE_FILE.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data

    def _load_runtime(self) -> None:
        with self._lock:
            self._runtime_data = {}
            try:
                with self._runtime_path.open("r", encoding="utf-8") as handle:
                    payload = json.load(handle)
            except FileNotFoundError:
                self._runtime_data = {}
                self._runtime_mtime = None
                return
            except json.JSONDecodeError:
                self._runtime_data = {}
                self._runtime_mtime = None
                return
            self._runtime_mtime = self._runtime_path.stat().st_mtime
            for key, value in payload.items():
                if key.startswith("pattern:"):
                    self._runtime_data[key] = value
                else:
                    self._runtime_data[key] = list(value)

    def _save_runtime(self) -> None:
        with self._lock:
            serializable: Dict[str, object] = {}
            for key, value in self._runtime_data.items():
                serializable[key] = value
            tmp_path = self._runtime_path.with_suffix(".tmp")
            with tmp_path.open("w", encoding="utf-8") as handle:
                json.dump(serializable, handle, indent=2, sort_keys=True)
            tmp_path.replace(self._runtime_path)
            self._runtime_mtime = self._runtime_path.stat().st_mtime

    def _maybe_reload_runtime(self) -> None:
        if not self._runtime_path.exists():
            return
        try:
            mtime = self._runtime_path.stat().st_mtime
        except FileNotFoundError:
            return
        if self._runtime_mtime is None or mtime > self._runtime_mtime:
            self._load_runtime()

    def _runtime_list(self, name: str) -> List[MutableMapping[str, object]]:
        with self._lock:
            self._maybe_reload_runtime()
            entry = self._runtime_data.setdefault(name, [])
            if isinstance(entry, list):
                return entry  # type: ignore[return-value]
            raise TypeError(f"Runtime indicator entry for '{name}' is not a list")

    def _runtime_pattern(self, name: str) -> Optional[PatternOverride]:
        with self._lock:
            self._maybe_reload_runtime()
            key = f"pattern:{name}"
            entry = self._runtime_data.get(key)
            if not isinstance(entry, Mapping):
                return None
            value = str(entry.get("value", "")).strip()
            if not value:
                return None
            return PatternOverride(
                value=value,
                source=str(entry.get("source", "runtime")),
                confidence=float(entry.get("confidence", 0.6)),
                first_seen=str(entry.get("first_seen", "unknown")),
            )

    def _merged_keyword_values(self, name: str) -> Set[str]:
        baseline_values = self._baseline.get(name, [])
        merged: Set[str] = {str(value).strip() for value in baseline_values if str(value).strip()}
        for entry in self._runtime_list(name):
            value = str(entry.get("value", "")).strip()
            if value:
                merged.add(value)
        return merged

    def _expand_values(self, raw: object) -> Iterable[str]:
        if isinstance(raw, str):
            parts = [segment.strip() for segment in raw.split(",") if segment.strip()]
            if parts:
                return parts
            return [raw.strip()]
        if isinstance(raw, Iterable):
            return [str(item).strip() for item in raw if str(item).strip()]
        return []

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(tz=timezone.utc).isoformat()


_indicator_manager: Optional[DynamicIndicatorManager] = None
_indicator_lock = threading.Lock()


def get_indicator_manager() -> DynamicIndicatorManager:
    """Return the shared indicator manager instance."""

    global _indicator_manager
    with _indicator_lock:
        if _indicator_manager is None:
            _indicator_manager = DynamicIndicatorManager()
        return _indicator_manager


def reset_indicator_manager() -> None:
    """Reset the shared indicator manager (useful for testing)."""

    global _indicator_manager
    with _indicator_lock:
        _indicator_manager = None
