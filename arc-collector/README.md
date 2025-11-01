# ARC Personal Cloud Collector

A self-hosted FastAPI service that links personal Microsoft 365 and Google accounts to ARC’s adaptive trust pipeline. The
collector handles OAuth sign-in, gathers available sign-in and risk telemetry, normalizes events into ARC’s schema, and serves a
visual dashboard with JSON APIs. Everything runs inside Docker with encrypted, local-at-rest storage.


## Features

- **Secure OAuth onboarding** for multiple personal Microsoft 365 and Google accounts.
- **Normalized telemetry pipeline** that maps Microsoft Graph and Google Reports data to ARC’s unified event schema.
- **Adaptive Trust analytics** including ATI scoring, risky sign-in detection, MFA posture, and OSINT correlation against the
  community-driven M365 indicator set shipped with the image.
- **Rich dashboard** with an interactive world map, risk highlights, connected account management, and live event tables.
- **JSON APIs** (`/api/events`, `/api/accounts`, `/api/summary`) for downstream automation or integration tests.
- **Encrypted persistence** using Fernet with the `ARC_AES_KEY`, stored under `/data/events.json.enc` inside the container.

## Prerequisites

- Python 3.11 (for local development) or Docker
- Registered OAuth applications for:
  - Microsoft (Entra ID “personal” tenant or developer tenant works best)
  - Google (OAuth consent screen + credentials that allow the Admin Reports API, if available)
- A 32-byte secret for `ARC_AES_KEY` (Base64 or arbitrary string – the service derives a Fernet key).
- Optional: a MaxMind GeoLite2 database (`GEOIP_DATABASE_PATH`) for precise latitude/longitude lookups. Without it, the map falls
  back to vendor-provided coordinates.

## Environment variables

Create a `.env` file next to the Docker Compose file or export the variables manually.

```env
# Core service
ARC_AES_KEY=base64_or_passphrase
PUBLIC_BASE_URL=https://collector.example.com    # Used for OAuth redirect URIs
ARC_DATA_DIR=/data                               # Optional override of the encrypted store path

# Microsoft OAuth
MS_CLIENT_ID=
MS_CLIENT_SECRET=
MS_SCOPES="User.Read offline_access AuditLog.Read.All SecurityEvents.Read.All IdentityRiskEvent.Read.All"

# Google OAuth
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_SCOPES="openid email profile https://www.googleapis.com/auth/admin.reports.audit.readonly"

# Optional GeoIP database
GEOIP_DATABASE_PATH=/data/GeoLite2-City.mmdb
```

> **OAuth redirect URIs**
> - `https://<public-host>/auth/microsoft/callback`
> - `https://<public-host>/auth/google/callback`

## Running with Docker Compose

```bash
cd arc-collector
cp .env.example .env  # create and edit if you maintain one
mkdir -p data certs
# place TLS certs in certs/cert.pem and certs/key.pem

docker compose up --build
```

The service listens on `8443` with TLS enabled. Visit `https://localhost:8443/` (or your public host) to connect accounts and
view telemetry.

## API reference

| Endpoint                           | Description                                                   |
| ---------------------------------- | ------------------------------------------------------------- |
| `GET /`                            | Dashboard UI                                                  |
| `GET /healthz`                    | Basic readiness probe                                         |
| `GET /api/events`                 | Returns normalized events (`EventEnvelope`)                   |
| `GET /api/accounts`               | Lists connected accounts (`AccountsEnvelope`)                 |
| `GET /api/summary`                | Aggregated metrics, ATI score, OSINT matches, geo footprint   |
| `POST /api/accounts/{id}/sync`    | Refreshes telemetry for a specific account and returns summary|

All API responses are JSON and rely on the models defined in `src/models.py`.

## Project layout

```
arc-collector/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── src/
│   ├── config.py            # Settings loader (BaseSettings)
│   ├── models.py            # Pydantic schemas
│   ├── normalizer.py        # Provider → ARC schema normalization + ATI
│   ├── osint.py             # Indicator loading + correlation helpers
│   ├── providers/
│   │   ├── google.py        # Google OAuth + telemetry collection
│   │   └── microsoft.py     # Microsoft OAuth + telemetry collection
│   ├── store.py             # Encrypted event + token persistence
│   └── web.py               # FastAPI app + routes + dashboard wiring
├── static/
│   ├── css/dashboard.css    # Styling for the dashboard
│   ├── js/dashboard.js      # Front-end logic + map rendering
│   └── data/m365_community_indicators.json
├── templates/
│   └── dashboard.html       # Jinja2 template for the dashboard
└── data/                    # Mounted volume for encrypted storage
```

## Local development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export ARC_AES_KEY=dev_key_please_change
uvicorn src.web:app --reload --port 8443 --ssl-keyfile certs/key.pem --ssl-certfile certs/cert.pem
```

The development server hot-reloads on file changes. You can disable TLS for local testing by dropping the `--ssl-*` flags and
changing the Docker command accordingly.

## Security posture

- Tokens are stored encrypted with Fernet (derived from `ARC_AES_KEY`).
- Normalized events hash user identifiers before storage.
- Dashboard displays security findings such as missing MFA, risky sign-ins, and OSINT matches.
- The optional GeoIP database improves map accuracy without leaking data to third parties.

## Extending

- Add more OSINT sources by dropping additional JSON files into `static/data` and loading them in `web.py`.
- Integrate new providers by adding modules to `src/providers` that expose `register_client`, `collect_events`, and
  `bootstrap_account`.
- Enhance analytics inside `src/normalizer.compute_ati` and `src/store.build_summary` to align with ARC core models.