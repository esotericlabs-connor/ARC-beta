"""FastAPI application exposing the ARC collector dashboard and APIs."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Dict
from urllib.parse import urlparse

from authlib.integrations.starlette_client import OAuth
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .config import get_settings
from .models import AccountsEnvelope, EventEnvelope, SummaryEnvelope
from .osint import OSINTClient
from .providers import dropbox, google, microsoft
from .store import EventStore
from .utils.geo import GeoResolver

app = FastAPI(title="ARC Personal Cloud Collector", version="0.2.0")
settings = get_settings()

data_dir = settings.data_directory
store_path = data_dir / "events.json.enc"
geo_resolver = GeoResolver(settings.geoip_database_path.as_posix() if settings.geoip_database_path else None)
store = EventStore(settings.arc_aes_key, store_path)

oauth = OAuth()
if settings.microsoft_client_id and settings.microsoft_client_secret:
    microsoft.register_client(oauth, settings)
if settings.google_client_id and settings.google_client_secret:
    google.register_client(oauth, settings)
if settings.dropbox_client_id and settings.dropbox_client_secret:
    dropbox.register_client(oauth, settings)

static_dir = Path(__file__).resolve().parent.parent / "static"
templates_dir = Path(__file__).resolve().parent.parent / "templates"
app.mount("/static", StaticFiles(directory=static_dir), name="static")
templates = Jinja2Templates(directory=str(templates_dir))

osint_client = OSINTClient.from_settings(settings)


@app.on_event("shutdown")
def _shutdown() -> None:
    geo_resolver.close()


def get_store() -> EventStore:
    return store


def _build_redirect_uri(request: Request, provider: str) -> str:
    redirect = request.url_for("auth_callback", provider=provider)
    if settings.public_base_url:
        parsed = urlparse(redirect)
        base = settings.public_base_url.rstrip("/")
        redirect = f"{base}{parsed.path}"
    return redirect


async def _correlate_osint() -> list[str]:
    return await osint_client.correlate_events(store.events_for_osint())


def _get_client(provider: str):
    client = oauth.create_client(provider)
    if client is None:
        raise HTTPException(status_code=404, detail=f"Provider '{provider}' is not configured")
    return client


async def _ensure_token(provider: str, account_id: str, token: Dict) -> Dict:
    expires_at = token.get("expires_at")
    if expires_at and expires_at <= time.time() + 60 and token.get("refresh_token"):
        client = _get_client(provider)
        refreshed = await client.refresh_token(client.access_token_url, refresh_token=token["refresh_token"])
        token.update(refreshed)
        store.update_token(account_id, token)
    return token


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, store: EventStore = Depends(get_store)) -> HTMLResponse:
    osint_matches = await _correlate_osint()
    summary = store.build_summary(osint_matches)
    accounts = store.list_accounts()
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "summary": summary,
            "accounts": accounts,
            "accounts_payload": [account.dict() for account in accounts],
            "providers": {
                "microsoft": bool(settings.microsoft_client_id),
                "google": bool(settings.google_client_id),
                "dropbox": bool(settings.dropbox_client_id),
            },
        },
    )


@app.get("/auth/{provider}")
async def oauth_login(provider: str, request: Request):
    client = _get_client(provider)
    redirect_uri = _build_redirect_uri(request, provider)
    return await client.authorize_redirect(request, redirect_uri)


@app.get("/auth/{provider}/callback")
async def auth_callback(provider: str, request: Request, store: EventStore = Depends(get_store)):
    client = _get_client(provider)
    token = await client.authorize_access_token(request)
    token["provider"] = provider

    if provider == "microsoft":
        account, events = await microsoft.bootstrap_account(token, geo_resolver)
    elif provider == "google":
        account, events = await google.bootstrap_account(token, geo_resolver)
    elif provider == "dropbox":
        account, events = await dropbox.bootstrap_account(token, geo_resolver)
    else:
        raise HTTPException(status_code=404, detail=f"Unsupported provider '{provider}'")

    existing = store.get_account(account.id)
    if existing:
        account.added_at = existing.added_at

    store.register_account(account, token)
    store.upsert_events(account.id, events)
    osint_matches = await _correlate_osint()
    store.build_summary(osint_matches)
    return RedirectResponse(url="/")


@app.get("/api/events", response_model=EventEnvelope)
async def api_events(store: EventStore = Depends(get_store)) -> EventEnvelope:
    events = store.list_events()
    return EventEnvelope(events=events)


@app.get("/api/accounts", response_model=AccountsEnvelope)
async def api_accounts(store: EventStore = Depends(get_store)) -> AccountsEnvelope:
    return AccountsEnvelope(accounts=store.list_accounts())


@app.get("/api/summary", response_model=SummaryEnvelope)
async def api_summary(store: EventStore = Depends(get_store)) -> SummaryEnvelope:
    summary = store.build_summary(await _correlate_osint())
    return SummaryEnvelope(summary=summary)


@app.post("/api/accounts/{account_id}/sync", response_model=SummaryEnvelope)
async def api_sync_account(account_id: str, store: EventStore = Depends(get_store)) -> SummaryEnvelope:
    account = store.get_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    token = store.get_token(account_id)
    if not token:
        raise HTTPException(status_code=400, detail="No token stored for account")

    token = await _ensure_token(account.provider, account_id, token)

    if account.provider == "microsoft":
        events = await microsoft.collect_events(token, account.id, geo_resolver)
    elif account.provider == "google":
        events = await google.collect_events(token, account.id, geo_resolver)
    elif account.provider == "dropbox":
        events = await dropbox.collect_events(token, account.id, geo_resolver)
    else:
        raise HTTPException(status_code=400, detail="Unsupported provider")

    store.upsert_events(account.id, events)
    summary = store.build_summary(await _correlate_osint())
    return SummaryEnvelope(summary=summary)


@app.get("/healthz")
async def health() -> dict[str, str]:
    return {"status": "ok"}