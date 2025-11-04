"""Pydantic models used by the ARC collector."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class GeoContext(BaseModel):
    """Represents geolocation metadata about an event."""

    ip: Optional[str] = Field(default=None, description="Original IP address")
    country: Optional[str] = Field(default=None, description="ISO country code")
    region: Optional[str] = Field(default=None, description="Region or state")
    city: Optional[str] = Field(default=None, description="City name")
    latitude: Optional[float] = Field(default=None, description="Latitude in decimal degrees")
    longitude: Optional[float] = Field(default=None, description="Longitude in decimal degrees")
    asn: Optional[str] = Field(default=None, description="Autonomous system number")


class SignalVector(BaseModel):
    """Derived signal scores for an event."""

    auth_confidence: Optional[float] = Field(default=None, description="Confidence score for authentication")
    geo_risk: Optional[float] = Field(default=None, description="Risk derived from geolocation")
    session_anomaly: Optional[bool] = Field(default=None, description="Whether the session is anomalous")
    risk_level: Optional[str] = Field(default=None, description="High-level risk label")


class NormalizedEvent(BaseModel):
    """Unified event schema used across ARC components."""

    id: str
    provider: str
    account_id: str
    timestamp: datetime
    user_hash: str
    username: Optional[str] = None
    geo: GeoContext = Field(default_factory=GeoContext)
    signals: SignalVector = Field(default_factory=SignalVector)
    raw: Dict = Field(default_factory=dict)
    risk_tags: List[str] = Field(default_factory=list)
    insights: Dict = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class ConnectedAccount(BaseModel):
    """Metadata about a connected cloud account."""

    id: str
    provider: str
    display_name: Optional[str]
    email: Optional[str]
    mfa_enabled: Optional[bool]
    tenant_id: Optional[str] = None
    added_at: datetime = Field(default_factory=datetime.utcnow)
    last_sync_at: Optional[datetime] = None
    scopes: List[str] = Field(default_factory=list)


class SummaryMetrics(BaseModel):
    """Aggregated statistics for the dashboard."""

    total_events: int
    risky_events: int
    connected_accounts: int
    adaptive_trust_index: float
    last_ingest_at: Optional[datetime]
    osint_matches: List[str] = Field(default_factory=list)
    security_findings: List[str] = Field(default_factory=list)
    geo_points: List[Dict[str, Any]] = Field(default_factory=list)


class EventEnvelope(BaseModel):
    """API envelope for event responses."""

    events: List[NormalizedEvent]


class AccountsEnvelope(BaseModel):
    """API envelope for connected account responses."""

    accounts: List[ConnectedAccount]


class SummaryEnvelope(BaseModel):
    """API envelope for summary responses."""

    summary: SummaryMetrics