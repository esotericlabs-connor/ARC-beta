"""Encrypted persistence layer for normalized events and accounts."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime
from pathlib import Path
from threading import RLock
from typing import Dict, Iterable, List, Sequence

from cryptography.fernet import Fernet, InvalidToken

from .models import ConnectedAccount, NormalizedEvent, SummaryMetrics
from .normalizer import compute_ati


def _derive_fernet_key(secret: str) -> bytes:
    """Return a valid Fernet key from an arbitrary secret string."""

    if not secret:
        raise ValueError("ARC_AES_KEY must not be empty")

    try:
        decoded = base64.urlsafe_b64decode(secret)
        if len(decoded) == 32:
            return base64.urlsafe_b64encode(decoded)
    except Exception:
        pass

    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


class EventStore:
    """Persist normalized events and connected accounts on disk."""

    def __init__(self, secret: str, storage_path: Path) -> None:
        self._fernet = Fernet(_derive_fernet_key(secret))
        self._storage_path = storage_path
        self._lock = RLock()
        self._events: List[NormalizedEvent] = []
        self._accounts: Dict[str, ConnectedAccount] = {}
        self._tokens: Dict[str, Dict] = {}
        self._load()

    # ------------------------------------------------------------------
    # Persistence helpers
    def _load(self) -> None:
        if not self._storage_path.exists():
            return
        try:
            encrypted = self._storage_path.read_bytes()
            payload = self._fernet.decrypt(encrypted)
        except (InvalidToken, ValueError):
            raise RuntimeError(
                "Unable to decrypt event store. Ensure ARC_AES_KEY matches the original value."
            )
        data = json.loads(payload.decode("utf-8"))
        self._events = [NormalizedEvent.parse_obj(item) for item in data.get("events", [])]
        self._accounts = {
            item["id"]: ConnectedAccount.parse_obj(item) for item in data.get("accounts", [])
        }
        self._tokens = data.get("tokens", {})

    def _serialize(self) -> bytes:
        data = {
            "events": [event.dict() for event in self._events],
            "accounts": [account.dict() for account in self._accounts.values()],
            "tokens": self._tokens,
        }
        return json.dumps(data, default=self._json_default, separators=(",", ":")).encode("utf-8")

    def _persist(self) -> None:
        payload = self._serialize()
        encrypted = self._fernet.encrypt(payload)
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._storage_path.write_bytes(encrypted)

    @staticmethod
    def _json_default(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj)!r} is not JSON serializable")

    # ------------------------------------------------------------------
    # Account management
    def register_account(self, account: ConnectedAccount, token: Dict) -> None:
        with self._lock:
            self._accounts[account.id] = account
            self._tokens[account.id] = token
            self._persist()

    def list_accounts(self) -> List[ConnectedAccount]:
        with self._lock:
            return list(self._accounts.values())

    def get_account(self, account_id: str) -> ConnectedAccount | None:
        with self._lock:
            return self._accounts.get(account_id)

    def get_token(self, account_id: str) -> Dict | None:
        with self._lock:
            return self._tokens.get(account_id)

    def update_token(self, account_id: str, token: Dict) -> None:
        with self._lock:
            if account_id not in self._accounts:
                raise KeyError(f'Unknown account {account_id}')
            self._tokens[account_id] = token
            self._persist()

    # ------------------------------------------------------------------
    # Event ingestion
    def upsert_events(self, account_id: str, events: Iterable[NormalizedEvent]) -> None:
        with self._lock:
            index = {event.id: event for event in self._events}
            for event in events:
                index[event.id] = event
            self._events = sorted(index.values(), key=lambda evt: evt.timestamp, reverse=True)
            if account_id in self._accounts:
                account = self._accounts[account_id]
                account.last_sync_at = datetime.utcnow()
                self._accounts[account_id] = account
            self._persist()

    def list_events(self, limit: int | None = None) -> List[NormalizedEvent]:
        with self._lock:
            events = list(self._events)
        return events[:limit] if limit else events

    def total_events(self) -> int:
        with self._lock:
            return len(self._events)

    # ------------------------------------------------------------------
    # Analytics helpers
    def build_summary(self, osint_matches: Sequence[str] | None = None) -> SummaryMetrics:
        with self._lock:
            events = list(self._events)
            risky_events = [
                event
                for event in events
                if event.signals.risk_level in {"medium", "high"}
                or bool(event.signals.session_anomaly)
                or "risky_sign_in" in event.risk_tags
            ]
            last_ingest = events[0].timestamp if events else None
            accounts = list(self._accounts.values())

        findings: List[str] = []
        for account in accounts:
            if account.mfa_enabled is False:
                label = account.display_name or account.email or account.id
                findings.append(f"Account {label} is missing MFA")

        osint_list = list(dict.fromkeys(osint_matches or []))
        findings.extend(osint_list)

        geo_points = [
            {
                'latitude': event.geo.latitude,
                'longitude': event.geo.longitude,
                'city': event.geo.city,
                'country': event.geo.country,
                'provider': event.provider,
                'timestamp': event.timestamp.isoformat(),
                'riskLevel': event.signals.risk_level,
                'username': event.username,
            }
            for event in events
            if event.geo.latitude is not None and event.geo.longitude is not None
        ]

        return SummaryMetrics(
            total_events=len(events),
            risky_events=len(risky_events),
            connected_accounts=len(accounts),
            adaptive_trust_index=compute_ati(events),
            last_ingest_at=last_ingest,
            osint_matches=osint_list,
            security_findings=findings,
            geo_points=geo_points,
        )

    # ------------------------------------------------------------------
    # OSINT correlation
    def events_for_osint(self) -> Sequence[NormalizedEvent]:
        with self._lock:
            return list(self._events)