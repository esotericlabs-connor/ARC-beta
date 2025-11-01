"""Google provider implementation for the ARC collector."""

from __future__ import annotations

import asyncio
from typing import Dict, List, Tuple

import httpx

from ..models import ConnectedAccount, NormalizedEvent
from ..normalizer import normalize_google
from ..utils.geo import GeoResolver

AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
REPORTS_URL = "https://www.googleapis.com/admin/reports/v1/activity/users/all/applications/login"


def register_client(oauth, settings) -> None:
    oauth.register(
        name="google",
        client_id=settings.google_client_id,
        client_secret=settings.google_client_secret,
        access_token_url=TOKEN_URL,
        authorize_url=AUTHORIZE_URL,
        api_base_url="https://www.googleapis.com/",
        client_kwargs={
            "scope": " ".join(settings.google_scopes),
            "access_type": "offline",
            "prompt": "consent",
        },
    )


async def fetch_profile(token: Dict) -> Dict:
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get(USERINFO_URL, headers={"Authorization": f"Bearer {token['access_token']}"})
        resp.raise_for_status()
        profile = resp.json()
        profile.setdefault("mfa_enabled", None)
        return profile


async def _fetch_login_events(token: Dict) -> List[Dict]:
    params = {"maxResults": 50, "customerId": "my_customer"}
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(REPORTS_URL, params=params, headers={"Authorization": f"Bearer {token['access_token']}"})
        if resp.is_success:
            return resp.json().get("items", [])
        return []


async def _fallback_event(token: Dict) -> List[Dict]:
    # Personal Google accounts do not expose Admin Reports; craft a synthetic login event.
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get(USERINFO_URL, headers={"Authorization": f"Bearer {token['access_token']}"})
        if not resp.is_success:
            return []
        profile = resp.json()
    return [
        {
            "id": {"time": profile.get("updated_at") or profile.get("sub"), "uniqueQualifier": profile.get("sub")},
            "name": "login_success",
            "type": "login_success",
            "actor": {"email": profile.get("email")},
            "parameters": [{"name": "ipAddress", "value": profile.get("hd") or "0.0.0.0"}],
        }
    ]


async def collect_events(token: Dict, account_id: str, resolver: GeoResolver) -> List[NormalizedEvent]:
    events = await _fetch_login_events(token)
    if not events:
        events = await _fallback_event(token)
    normalized: List[NormalizedEvent] = []
    for event in events:
        try:
            normalized.append(normalize_google(event, account_id, resolver))
        except Exception:
            continue
    return normalized


async def bootstrap_account(token: Dict, resolver: GeoResolver) -> Tuple[ConnectedAccount, List[NormalizedEvent]]:
    profile = await fetch_profile(token)
    account = ConnectedAccount(
        id=profile.get("sub") or profile.get("email"),
        provider="google",
        display_name=profile.get("name"),
        email=profile.get("email"),
        mfa_enabled=profile.get("mfa_enabled"),
        tenant_id=profile.get("hd"),
        scopes=token.get('scope', '').split() if token.get('scope') else [],
    )
    events = await collect_events(token, account.id, resolver)
    return account, events