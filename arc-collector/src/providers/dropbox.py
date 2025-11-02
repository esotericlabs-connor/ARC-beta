"""Dropbox connector for ARC collector."""

from __future__ import annotations

from typing import Dict, List, Tuple

import httpx

from ..models import ConnectedAccount, NormalizedEvent
from ..normalizer import normalize_dropbox
from ..utils.geo import GeoResolver

AUTH_URL = "https://www.dropbox.com/oauth2/authorize"
TOKEN_URL = "https://api.dropboxapi.com/oauth2/token"
API_BASE = "https://api.dropboxapi.com/2"


def register_client(oauth, settings) -> None:
    oauth.register(
        name="dropbox",
        client_id=settings.dropbox_client_id,
        client_secret=settings.dropbox_client_secret,
        access_token_url=TOKEN_URL,
        authorize_url=AUTH_URL,
        api_base_url=API_BASE,
        client_kwargs={
            "scope": " ".join(settings.dropbox_scopes),
            "token_endpoint_auth_method": "client_secret_post",
        },
    )


async def fetch_profile(token: Dict) -> Dict:
    headers = {
        "Authorization": f"Bearer {token['access_token']}",
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.post(f"{API_BASE}/users/get_current_account", headers=headers)
        response.raise_for_status()
        profile = response.json()
        if "is_two_step_enabled" in profile:
            profile["mfa_enabled"] = profile.get("is_two_step_enabled")
        return profile


async def _fetch_team_events(headers: Dict) -> List[Dict]:
    events: List[Dict] = []
    url = f"{API_BASE}/team_log/get_events"
    payload: Dict = {"limit": 100, "category": {".tag": "logins"}}

    async with httpx.AsyncClient(timeout=30) as client:
        while True:
            response = await client.post(url, headers=headers, json=payload)
            if not response.is_success:
                break
            data = response.json()
            events.extend(data.get("events", []))
            cursor = data.get("cursor")
            if not data.get("has_more") or not cursor:
                break
            url = f"{API_BASE}/team_log/get_events/continue"
            payload = {"cursor": cursor}
    return events


async def collect_events(token: Dict, account_id: str, resolver: GeoResolver) -> List[NormalizedEvent]:
    headers = {
        "Authorization": f"Bearer {token['access_token']}",
        "Content-Type": "application/json",
    }
    events: List[Dict] = []
    try:
        events = await _fetch_team_events(headers)
    except httpx.HTTPError:
        events = []

    normalized: List[NormalizedEvent] = []
    for event in events:
        try:
            normalized.append(normalize_dropbox(event, account_id, resolver))
        except Exception:
            continue
    return normalized


async def bootstrap_account(token: Dict, resolver: GeoResolver) -> Tuple[ConnectedAccount, List[NormalizedEvent]]:
    profile = await fetch_profile(token)
    account = ConnectedAccount(
        id=profile.get("account_id") or profile.get("team_member_id") or "dropbox-account",
        provider="dropbox",
        display_name=(profile.get("name") or {}).get("display_name") if isinstance(profile.get("name"), dict) else profile.get("name"),
        email=profile.get("email"),
        mfa_enabled=profile.get("mfa_enabled"),
        tenant_id=(profile.get("team") or {}).get("id") if isinstance(profile.get("team"), dict) else None,
        scopes=token.get("scope", "").split() if token.get("scope") else [],
    )
    events = await collect_events(token, account.id, resolver)
    return account, events


__all__ = [
    "register_client",
    "fetch_profile",
    "collect_events",
    "bootstrap_account",
]
