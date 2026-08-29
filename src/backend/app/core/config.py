from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "MALCIE"
    app_env: str = "development"
    api_v1_prefix: str = "/api/v1"
    database_url: str = "******db:5432/malciedb"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
