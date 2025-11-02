"""Configuration utilities for the ARC collector."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from dotenv import load_dotenv
from pydantic import Field, validator
try:
    from pydantic_settings import BaseSettings
except ImportError:  # pragma: no cover - fallback for restricted environments
    from pydantic import BaseModel

    class BaseSettings(BaseModel):  # type: ignore[misc]
        """Minimal fallback that reads environment variables directly."""

        class Config:
            arbitrary_types_allowed = True

        def __init__(self, **values):
            env_values = {}
            for name, field in self.__class__.model_fields.items():
                env_name = None
                if field.json_schema_extra:
                    env_name = field.json_schema_extra.get("env")
                if not env_name:
                    env_name = name.upper()
                if env_name and name not in values and env_name in os.environ:
                    env_values[name] = os.environ[env_name]
            super().__init__(**env_values, **values)


load_dotenv()


class Settings(BaseSettings):
    """Environment-backed settings for the collector."""

    arc_aes_key: str = Field(..., env="ARC_AES_KEY")
    public_base_url: Optional[str] = Field(default=None, env="PUBLIC_BASE_URL")
    data_directory: Path = Field(default=Path("/data"), env="ARC_DATA_DIR")

    microsoft_client_id: Optional[str] = Field(default=None, env="MS_CLIENT_ID")
    microsoft_client_secret: Optional[str] = Field(default=None, env="MS_CLIENT_SECRET")
    microsoft_scopes: List[str] = Field(
        default_factory=lambda: [
            "User.Read",
            "offline_access",
            "AuditLog.Read.All",
            "SecurityEvents.Read.All",
            "IdentityRiskEvent.Read.All",
        ],
        env="MS_SCOPES",
    )

    google_client_id: Optional[str] = Field(default=None, env="GOOGLE_CLIENT_ID")
    google_client_secret: Optional[str] = Field(default=None, env="GOOGLE_CLIENT_SECRET")
    google_scopes: List[str] = Field(
        default_factory=lambda: [
            "openid",
            "email",
            "profile",
            "https://www.googleapis.com/auth/admin.reports.audit.readonly",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
        ],
        env="GOOGLE_SCOPES",
    )

    dropbox_client_id: Optional[str] = Field(default=None, env="DROPBOX_CLIENT_ID")
    dropbox_client_secret: Optional[str] = Field(default=None, env="DROPBOX_CLIENT_SECRET")
    dropbox_scopes: List[str] = Field(
        default_factory=lambda: [
            "account_info.read",
            "team_data.member",
            "team_info.read",
            "members.read",
            "team_data.team_space",
            "events.read",
        ],
        env="DROPBOX_SCOPES",
    )

    geoip_database_path: Optional[Path] = Field(default=None, env="GEOIP_DATABASE_PATH")

    osint_cache_ttl: int = Field(default=900, env="OSINT_CACHE_TTL")
    osint_feodo_enabled: bool = Field(default=True, env="OSINT_FEODO_ENABLED")
    osint_threatfox_enabled: bool = Field(default=True, env="OSINT_THREATFOX_ENABLED")
    osint_tor_enabled: bool = Field(default=True, env="OSINT_TOR_ENABLED")
    abuseipdb_api_key: Optional[str] = Field(default=None, env="ABUSEIPDB_API_KEY")
    abuseipdb_min_confidence: int = Field(default=90, env="ABUSEIPDB_MIN_CONFIDENCE")
    otx_api_key: Optional[str] = Field(default=None, env="OTX_API_KEY")
    otx_pages: int = Field(default=2, env="OTX_PAGES")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

    @validator("microsoft_scopes", "google_scopes", "dropbox_scopes", pre=True)
    def _split_scopes(cls, value):  # type: ignore[override]
        if isinstance(value, str):
            separators = [",", " ", "\n"]
            for sep in separators:
                if sep in value:
                    parts = [part.strip() for part in value.replace("\n", sep).split(sep)]
                    return [part for part in parts if part]
            return [value.strip()] if value.strip() else []
        return value

    @validator("data_directory", pre=True)
    def _expand_path(cls, value):  # type: ignore[override]
        if isinstance(value, str):
            return Path(value).expanduser()
        if isinstance(value, Path):
            return value.expanduser()
        raise ValueError("data_directory must be a filesystem path")

    @validator("geoip_database_path", pre=True)
    def _optional_path(cls, value):  # type: ignore[override]
        if value in (None, ""):
            return None
        if isinstance(value, str):
            return Path(value).expanduser()
        if isinstance(value, Path):