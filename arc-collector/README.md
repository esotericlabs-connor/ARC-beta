# Codex Task: ARC collector to aggregate security events from Microsoft 365 and Google via a self-hosted HTTPS Docker service

Goal
----
Build a small, self-hosted collector that connects *personal* Microsoft 365 and Google accounts to ARC’s current logic. It should:
1) handle OAuth sign-in,
2) pull available security/sign-in/audit events,
3) normalize to ARC’s unified schema,
4) expose a local HTTPS page + JSON API,
5) run in Docker.

Notes & constraints
-------------------
- Microsoft: use Microsoft Graph. For best results, use an Entra ID tenant (even a “personal” dev tenant). Pure consumer MSA accounts have limited security endpoints.
  • APIs: `/beta/security/alerts_v2`, `auditLogs/signIns`, `identityProtection/riskyUsers`, `identityProtection/riskyServicePrincipals`
- Google: rich audit feeds require **Google Workspace** (admin). Personal @gmail.com accounts have limited security telemetry. If Workspace isn’t available, fall back to:
  • Gmail security settings + OAuth2 token events (limited)
  • Otherwise (Workspace): Admin SDK Reports API `activities.list` for apps `login`, `admin`, `token`, `drive`, `gcp`, and Cloud Logging (if using GCP).
- Privacy: store only anonymized/hashed identifiers per ARC method.

Directory layout (container)
----------------------------
/app
  /src
    arc_normalizer.py        # AETA/AIDA → unified event
    ms_graph_client.py       # Microsoft calls
    google_client.py         # Google calls
    store.py                 # sqlite or jsonl storage, AES-at-rest optional
    web.py                   # FastAPI app (OAuth, webhooks, viewer, API)
  /static                    # very small viewer UI
  requirements.txt
  Dockerfile
  docker-compose.yml

Environment variables
---------------------
ARC_MODE=production
ARC_SECRET=change_me                       # cookie/session signing
ARC_AES_KEY=base64_32_bytes               # for local at-rest encryption (optional)

# Microsoft
MS_CLIENT_ID=
MS_CLIENT_SECRET=
MS_TENANT_ID=consumers_or_your_tenant     # "common", "organizations", GUID, or "consumers"
MS_SCOPES="openid email offline_access https://graph.microsoft.com/.default"

# Google
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_SCOPES="openid email profile https://www.googleapis.com/auth/admin.reports.audit.readonly https://www.googleapis.com/auth/cloud-platform.read-only"
GOOGLE_WORKSPACE_CUSTOMER_ID=optional

SERVER_HOST=0.0.0.0
SERVER_PORT=8443
PUBLIC_BASE_URL=https://your.host.tld      # used in OAuth redirects

OAuth redirect URIs you must register
-------------------------------------
https://your.host.tld/oauth/ms/callback
https://your.host.tld/oauth/google/callback

API outline
-----------
GET  /            → tiny HTML page with “Connect Microsoft” / “Connect Google” + last 50 events
GET  /health      → 200 when ready
GET  /api/v1/events?limit=100&source=ms|google
POST /api/v1/pull/ms       → on-demand MS pull (requires Bearer admin token)
POST /api/v1/pull/google   → on-demand Google pull
GET  /oauth/ms/init        → starts MS auth code + PKCE
GET  /oauth/ms/callback    → exchanges code → stores refresh token (encrypted)
GET  /oauth/google/init
GET  /oauth/google/callback

Normalization (ARC Method)
--------------------------
Unified event (stored and returned by /api):
{
  "id": "evt-uuid",
  "source": "microsoft|google",
  "domain": "AETA|AIDA",                     // email vs identity context
  "timestamp": "2025-11-01T19:45:00Z",
  "identity": {
    "user_hash": "sha256(sid or email+salt)",
    "device_id": "optional hash",
    "asn": "ASxxxx",
    "geo": "CC-REGION"
  },
  "signals": {
    "auth_confidence": 0-100,
    "geo_risk": 0-100,
    "session_anomaly": true|false,
    "message_heuristic": 0-100               // if email context applies
  },
  "raw": { "provider_type": "...", "...": "..." },   // trimmed vendor fields
  "arc": {
    "ati": 0-100,                              // Adaptive Trust Index (computed)
    "node_reputation": 0.0-1.0,                // placeholder for future
    "decision_id": "ARC-UUID"
  }
}

# --- Microsoft OAuth client ---
oauth.register(
  name="ms",
  client_id=os.getenv("MS_CLIENT_ID"),
  client_secret=os.getenv("MS_CLIENT_SECRET"),
  server_metadata_url="https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration".format(
      tenant=os.getenv("MS_TENANT_ID","consumers")),
  client_kwargs={"scope": os.getenv("MS_SCOPES")}
)

# --- Google OAuth client ---
oauth.register(
  name="google",
  client_id=os.getenv("GOOGLE_CLIENT_ID"),
  client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
  server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
  client_kwargs={"scope": os.getenv("GOOGLE_SCOPES")}
)

@app.get("/", response_class=HTMLResponse)
async def home():
    # render minimal page (links to /oauth/ms/init and /oauth/google/init) + last events
    events = store.tail(50)
    return HTMLResponse(f"<h1>ARC Collector</h1><a href='/oauth/ms/init'>Connect Microsoft</a> · <a href='/oauth/google/init'>Connect Google</a><pre>{json.dumps(events, indent=2)}</pre>")

@app.get("/oauth/ms/init")
async def ms_init(request: Request):
    redirect_uri = os.getenv("PUBLIC_BASE_URL") + "/oauth/ms/callback"
    return await oauth.ms.authorize_redirect(request, redirect_uri)

@app.get("/oauth/ms/callback")
async def ms_callback(request: Request):
    token = await oauth.ms.authorize_access_token(request)
    store.save_secret("ms_token", token)
    return RedirectResponse("/")

@app.get("/oauth/google/init")
async def g_init(request: Request):
    redirect_uri = os.getenv("PUBLIC_BASE_URL") + "/oauth/google/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri, access_type="offline", prompt="consent")

@app.get("/oauth/google/callback")
async def g_callback(request: Request):
    token = await oauth.google.authorize_access_token(request)
    store.save_secret("google_token", token)
    return RedirectResponse("/")

@app.post("/api/v1/pull/ms")
async def pull_ms():
    token = store.load_secret("ms_token")
    if not token: return JSONResponse({"error":"not_connected"}, status_code=400)
    headers = {"Authorization": f"Bearer {token['access_token']}"}
    async with httpx.AsyncClient(timeout=30) as client:
        # sample: sign-ins + risky users (adjust per tenant capability)
        r1 = await client.get("https://graph.microsoft.com/beta/auditLogs/signIns?$top=50", headers=headers)
        r2 = await client.get("https://graph.microsoft.com/beta/identityProtection/riskyUsers?$top=50", headers=headers)
    events = []
    for item in r1.json().get("value", []):
        ev = normalize_ms(item)                 # → unified schema
        ev["arc"]["ati"] = compute_ati(ev)
        store.append(ev); events.append(ev)
    for item in r2.json().get("value", []):
        ev = normalize_ms(item)
        ev["arc"]["ati"] = compute_ati(ev)
        store.append(ev); events.append(ev)
    return {"ingested": len(events)}

@app.post("/api/v1/pull/google")
async def pull_google():
    token = store.load_secret("google_token")
    if not token: return JSONResponse({"error":"not_connected"}, status_code=400)
    headers = {"Authorization": f"Bearer {token['access_token']}"}
    async with httpx.AsyncClient(timeout=30) as client:
        # Workspace Admin Reports API (requires Workspace)
        # login activity
        r = await client.get("https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login?maxResults=50", headers=headers)
    events = []
    for item in r.json().get("items", []):
        ev = normalize_google(item)
        ev["arc"]["ati"] = compute_ati(ev)
        store.append(ev); events.append(ev)
    return {"ingested": len(events)}

@app.get("/api/v1/events")
async def list_events(limit: int = 100, source: str | None = None):
    return store.query(limit=limit, source=source)

HTTPS & certs
-------------
- For local dev, generate a self-signed cert in ./certs (key.pem, cert.pem) and trust locally.
- For public exposure, place this behind Caddy/Traefik and terminate TLS there.

What to hand-off to Codex now
-----------------------------
1) Implement the FastAPI app exactly as above (OAuth, pulls, unified schema, UI).
2) Fill in `ms_graph_client.py` and `google_client.py` helper calls if you prefer separate modules.
3) Complete normalizers (hashing, geo/asn lookups) using your existing ARC routines.
4) Persist events to sqlite or JSONL via `store.py` (AES-GCM optional using ARC_AES_KEY).
5) Ship Dockerfile + compose. Service must start with HTTPS on 8443.
6) Add a `/cron` container or background task to refresh tokens and pull new events every N minutes.

Acceptance
----------
- User can click “Connect Microsoft” or “Connect Google”, authorize, and then see live events on `/`.
- `/api/v1/events` returns normalized events with ARC’s `ati` computed.
- Container runs with HTTPS. No raw emails or PII are stored; only hashed identifiers per ARC Method.
