from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "TraceX API"
    app_version: str = "0.1.0"
    environment: str = "development"

    api_prefix: str = "/api"

    max_upload_size_mb: int = 10

    virustotal_api_key: str = ""
    abuseipdb_api_key: str = " "

    mongodb_uri: str = ""
    database_name: str = "tracex"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()