from functools import cached_property
from pathlib import Path
from zoneinfo import ZoneInfo

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Elasticsearch ---
    # Адрес, API-ключ и проверка TLS задаются в меню «Подключение» и хранятся в БД.
    # Эти переменные — только начальные значения для формы при первом запуске.
    es_url: str = "http://localhost:9200"
    es_username: str | None = None
    es_password: str | None = None
    es_api_key: str | None = None
    es_verify_certs: bool = True
    es_ca_certs: str | None = None
    es_timeout: float = 120.0
    # Разрешать только читающие запросы (GET и POST на _search/_count/_msearch/_sql ...)
    es_read_only: bool = True
    max_concurrent_queries: int = 4

    # --- Сервис ---
    data_dir: Path = Path("./data")
    database_url: str | None = None  # по умолчанию sqlite в data_dir
    timezone: str = "UTC"
    # Внешний адрес сервиса для публичных ссылок (если пусто — берётся из запроса)
    public_base_url: str | None = None

    # Первый администратор создаётся из этих переменных при старте, если пользователей ещё нет.
    # Если не заданы — сервис предложит создать администратора в веб-интерфейсе.
    admin_username: str | None = None
    admin_password: str | None = None
    session_ttl_hours: int = 12

    # --- Результаты ---
    # Сколько хранить результат ручного запуска, если хранение явно не включено
    default_result_ttl_minutes: int = 60
    max_result_ttl_days: int = 90
    max_result_mb: int = 200
    preview_max_kb: int = 1024
    run_history_days: int = 30
    cleanup_interval_minutes: int = 5

    # --- Webhook ---
    webhook_timeout: float = 60.0
    webhook_retries: int = 3
    # Входящие вебхуки: максимум вызовов в минуту для одной задачи.
    # Пользователь может задать в задаче меньший лимит, но не больше этого значения.
    hook_rate_limit_per_minute: int = 30

    # --- Планировщик ---
    misfire_grace_seconds: int = 600

    @cached_property
    def tz(self) -> ZoneInfo:
        return ZoneInfo(self.timezone)

    @property
    def results_dir(self) -> Path:
        return self.data_dir / "results"

    @property
    def db_url(self) -> str:
        return self.database_url or f"sqlite:///{(self.data_dir / 'service.db').resolve()}"


settings = Settings()
