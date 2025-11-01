"""Configuration utilities for the ARC collector."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic import BaseSettings, Field, validator


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

    geoip_database_path: Optional[Path] = Field(default=None, env="GEOIP_DATABASE_PATH")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

    @validator("microsoft_scopes", "google_scopes", pre=True)
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
            return value.expanduser()
        raise ValueError("geoip_database_path must be a filesystem path or empty")


@lru_cache()
def get_settings() -> Settings:
    """Return the cached application settings."""

    settings = Settings()
    settings.data_directory.mkdir(parents=True, exist_ok=True)
    return settings