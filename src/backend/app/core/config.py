from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "MALCIE"
    app_env: str = "development"
    api_v1_prefix: str = "/api/v1"
    database_url: str = "sqlite:///./malcie.db"
    api_key: str = ""
    allowed_origins: str = "http://localhost:3000"
    graph_redirect_uris: str = ""

    graph_client_id: str = ""
    graph_tenant_id: str = "common"
    graph_client_secret: str = ""
    graph_scope: str = "offline_access Mail.Read"
    graph_webhook_client_state: str = ""
    graph_timeout_seconds: float = 20.0
    graph_max_retries: int = 3

    vt_api_key: str = ""
    vt_base_url: str = "https://www.virustotal.com/api/v3"
    vt_timeout_seconds: float = 15.0
    vt_max_retries: int = 3
    vt_cache_ttl_seconds: int = 86400

    artifact_storage_path: str = "artifacts"
    yara_rules_path: str = "rules/yara"
    max_eml_size_bytes: int = 10 * 1024 * 1024
    max_attachment_size_bytes: int = 25 * 1024 * 1024
    max_telemetry_size_bytes: int = 10 * 1024 * 1024
    max_telemetry_events: int = 1000
    graph_webhook_max_body_bytes: int = 1024 * 1024
    graph_webhook_max_notifications: int = 100

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
