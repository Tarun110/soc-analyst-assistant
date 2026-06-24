"""Application configuration."""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent
KNOWLEDGE_BASE_DIR = BASE_DIR / "data" / "knowledge_base"
SAMPLE_ALERTS_DIR = BASE_DIR / "data" / "sample_alerts"
REPORTS_DIR = BASE_DIR / "reports"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    openai_embedding_model: str = "text-embedding-3-small"
    chroma_persist_dir: str = str(BASE_DIR / "data" / "chroma_db")
    retrieval_top_k: int = 5
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    @property
    def has_openai_key(self) -> bool:
        return bool(self.openai_api_key and self.openai_api_key != "sk-your-openai-api-key-here")


settings = Settings()
