from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "MALCIE"
    app_env: str = "development"
    api_v1_prefix: str = "/api/v1"
    database_url: str = "sqlite:///./malcie.db"

    graph_client_id: str = ""
    graph_tenant_id: str = "common"
    graph_client_secret: str = ""
    graph_scope: str = "offline_access Mail.Read"

    artifact_storage_path: str = "artifacts"
    max_eml_size_bytes: int = 10 * 1024 * 1024
    max_attachment_size_bytes: int = 25 * 1024 * 1024

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
