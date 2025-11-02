from datetime import datetime
from pathlib import Path
import os
import sys

os.environ.setdefault("ARC_AES_KEY", "dev-test-key")

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / "arc-collector" / "src"))

from models import GeoContext, NormalizedEvent, SignalVector  # type: ignore  # noqa: E402
from osint import Indicator  # type: ignore  # noqa: E402


def _event(ip: str | None = None, *, asn: str | None = None) -> NormalizedEvent:
    geo = GeoContext(ip=ip, asn=asn)
    signals = SignalVector(auth_confidence=80.0, geo_risk=10.0, session_anomaly=False, risk_level="low")
    return NormalizedEvent(
        id="evt",
        provider="microsoft",
        account_id="acct",
        timestamp=datetime.utcnow(),
        user_hash="user",
        geo=geo,
        signals=signals,
        raw={},
        risk_tags=[],
        insights={},
    )


def test_indicator_ip_match() -> None:
    indicator = Indicator(type="ip", value="1.2.3.4", label="test", source="unit")
    event = _event("1.2.3.4")
    assert indicator.matches(event)
    other = _event("5.6.7.8")
    assert not indicator.matches(other)


def test_indicator_cidr_match() -> None:
    indicator = Indicator(type="cidr", value="10.0.0.0/8", label="test", source="unit")
    event = _event("10.4.5.6")
    assert indicator.matches(event)
    other = _event("192.168.0.1")
    assert not indicator.matches(other)


def test_indicator_asn_match() -> None:
    indicator = Indicator(type="asn", value="AS13335", label="test", source="unit")
    event = _event("203.0.113.10", asn="AS13335")
    assert indicator.matches(event)
    other = _event("203.0.113.11", asn="AS15169")
    assert not indicator.matches(other)