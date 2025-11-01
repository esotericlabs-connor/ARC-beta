"""Microsoft provider implementation for the ARC collector."""

from __future__ import annotations

import asyncio
from typing import Dict, List, Tuple

import httpx

from ..models import ConnectedAccount, NormalizedEvent
from ..normalizer import normalize_ms
from ..utils.geo import GeoResolver

AUTHORITY = "https://login.microsoftonline.com/consumers"
AUTHORIZE_URL = f"{AUTHORITY}/oauth2/v2.0/authorize"
TOKEN_URL = f"{AUTHORITY}/oauth2/v2.0/token"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"


def register_client(oauth, settings) -> None:
    oauth.register(
        name="microsoft",
        client_id=settings.microsoft_client_id,
        client_secret=settings.microsoft_client_secret,
        access_token_url=TOKEN_URL,
        authorize_url=AUTHORIZE_URL,
        api_base_url=GRAPH_BASE,
        client_kwargs={
            "scope": " ".join(settings.microsoft_scopes),
            "token_endpoint_auth_method": "client_secret_post",
        },
    )


async def fetch_profile(token: Dict) -> Dict:
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get(f"{GRAPH_BASE}/me", headers={"Authorization": f"Bearer {token['access_token']}"})
        resp.raise_for_status()
        profile = resp.json()
        mfa_enabled = None
        try:
            auth_resp = await client.get(
                f"{GRAPH_BASE}/me/authentication/methods",
                headers={"Authorization": f"Bearer {token['access_token']}"},
            )
            if auth_resp.is_success:
                methods = auth_resp.json().get("value", [])
                mfa_enabled = any(method.get("type") != "password" for method in methods)
        except httpx.HTTPError:
            mfa_enabled = None
        profile["mfa_enabled"] = mfa_enabled
        return profile


async def _fetch_signins(token: Dict) -> List[Dict]:
    url = f"{GRAPH_BASE}/auditLogs/signIns?$top=50&$orderby=createdDateTime desc"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(url, headers={"Authorization": f"Bearer {token['access_token']}"})
        if resp.is_success:
            return resp.json().get("value", [])
        return []


def _hydrate_risky_event(event: Dict) -> Dict:
    location = event.get("ipAddress", {})
    ip = location.get("ipAddress") if isinstance(location, dict) else location
    return {
        "id": event.get("id"),
        "createdDateTime": event.get("createdDateTime") or event.get("riskLastUpdatedDateTime"),
        "userPrincipalName": event.get("userPrincipalName"),
        "userDisplayName": event.get("userDisplayName"),
        "userId": event.get("userId"),
        "ipAddress": ip,
        "riskLevel": event.get("riskLevel"),
        "riskState": event.get("riskState"),
        "riskDetail": event.get("riskDetail"),
        "authenticationRequirement": event.get("authenticationRequirement"),
        "location": event.get("location"),
        "conditionalAccessStatus": event.get("conditionalAccessStatus"),
        "clientAppUsed": event.get("appliedConditionalAccessPolicies"),
    }


async def _fetch_risky_signins(token: Dict) -> List[Dict]:
    url = f"{GRAPH_BASE}/identityProtection/riskySignIns?$top=50&$orderby=riskLastUpdatedDateTime desc"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(url, headers={"Authorization": f"Bearer {token['access_token']}"})
        if resp.is_success:
            return [_hydrate_risky_event(item) for item in resp.json().get("value", [])]
        return []


async def collect_events(token: Dict, account_id: str, resolver: GeoResolver) -> List[NormalizedEvent]:
    signins, risky = await asyncio.gather(_fetch_signins(token), _fetch_risky_signins(token))
    events = signins + risky
    normalized: List[NormalizedEvent] = []
    for event in events:
        try:
            normalized.append(normalize_ms(event, account_id, resolver))
        except Exception:
            continue
    return normalized


async def bootstrap_account(token: Dict, resolver: GeoResolver) -> Tuple[ConnectedAccount, List[NormalizedEvent]]:
    profile = await fetch_profile(token)
    account = ConnectedAccount(
        id=profile.get("id") or profile.get("userPrincipalName") or profile.get("mail") or "microsoft-account",
        provider="microsoft",
        display_name=profile.get("displayName"),
        email=profile.get("mail") or profile.get("userPrincipalName"),
        mfa_enabled=profile.get("mfa_enabled"),
        tenant_id=profile.get("tenantId"),
        scopes=token.get('scope', '').split() if token.get('scope') else [],
    )
    events = await collect_events(token, account.id, resolver)
    return account, events