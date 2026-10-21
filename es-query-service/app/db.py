from datetime import datetime, timezone

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    """Текущее время в UTC без tzinfo — в таком виде даты хранятся в БД."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


_is_sqlite = settings.db_url.startswith("sqlite")
engine = create_engine(
    settings.db_url,
    connect_args={"check_same_thread": False} if _is_sqlite else {},
    pool_pre_ping=True,
)

if _is_sqlite:

    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA busy_timeout=5000")
        cur.close()


SessionLocal = sessionmaker(engine, expire_on_commit=False)


def init_db() -> None:
    from . import models  # noqa: F401  (регистрация моделей)

    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.results_dir.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(engine)
    migrate(engine)


def _add_column(conn, insp, table: str, column: str, ddl: str) -> None:
    if column not in {c["name"] for c in insp.get_columns(table)}:
        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))


def migrate(eng) -> None:
    """Обновляет БД, созданную предыдущими версиями сервиса. Безопасна для повторного запуска."""
    insp = inspect(eng)
    tables = set(insp.get_table_names())
    now = utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")  # формат дат SQLAlchemy в SQLite
    with eng.begin() as conn:
        _add_column(conn, insp, "tasks", "key_id", "INTEGER REFERENCES cluster_keys(id)")
        _add_column(conn, insp, "tasks", "owner_id", "INTEGER REFERENCES users(id) ON DELETE SET NULL")
        _add_column(conn, insp, "runs", "cluster_name", "VARCHAR(100)")
        _add_column(conn, insp, "runs", "key_name", "VARCHAR(100)")
        _add_column(conn, insp, "runs", "user_id", "INTEGER REFERENCES users(id) ON DELETE SET NULL")
        _add_column(conn, insp, "runs", "user_name", "VARCHAR(200)")
        _add_column(conn, insp, "runs", "es_took_ms", "INTEGER")
        _add_column(conn, insp, "runs", "client_ip", "VARCHAR(64)")
        _add_column(conn, insp, "tasks", "hook_token", "VARCHAR(64)")
        _add_column(conn, insp, "tasks", "hook_allowed_ips", "TEXT")
        _add_column(conn, insp, "tasks", "hook_rate_limit", "INTEGER")
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_tasks_hook_token ON tasks (hook_token)"))
        task_cols = {c["name"] for c in insp.get_columns("tasks")}
        cluster_cols = {c["name"] for c in insp.get_columns("clusters")}

        def add_key(cluster_id: int, api_key: str | None) -> None:
            conn.execute(text("INSERT INTO cluster_keys (cluster_id, name, api_key, created_at) "
                              "VALUES (:c, 'Основной ключ', :k, :now)"), {"c": cluster_id, "k": api_key, "now": now})

        # v1: единственное подключение (es_connection) -> кластер «Основной» с ключом
        if "es_connection" in tables:
            if not conn.execute(text("SELECT 1 FROM clusters LIMIT 1")).first():
                row = conn.execute(text("SELECT url, api_key, verify_tls FROM es_connection WHERE id = 1")).first()
                if row:
                    cid = conn.execute(
                        text("INSERT INTO clusters (name, url, verify_tls, is_default, created_at, updated_at) "
                             "VALUES ('Основной', :url, :tls, 1, :now, :now) RETURNING id"),
                        {"url": row.url, "tls": bool(row.verify_tls), "now": now},
                    ).scalar()
                    add_key(cid, row.api_key)
            conn.execute(text("DROP TABLE es_connection"))

        # v2: API-ключ хранился в самом кластере -> отдельный ключ кластера
        if "api_key" in cluster_cols:
            for cid, api_key in conn.execute(text("SELECT id, api_key FROM clusters")).all():
                if not conn.execute(text("SELECT 1 FROM cluster_keys WHERE cluster_id = :c"), {"c": cid}).first():
                    add_key(cid, api_key)
            conn.execute(text("ALTER TABLE clusters DROP COLUMN api_key"))

        # v2: задача ссылалась на кластер -> ключ этого кластера
        if "cluster_id" in task_cols:
            conn.execute(text(
                "UPDATE tasks SET key_id = (SELECT MIN(k.id) FROM cluster_keys k WHERE k.cluster_id = tasks.cluster_id) "
                "WHERE key_id IS NULL AND cluster_id IS NOT NULL"))
            # Старая колонка больше не используется; обнуляем, чтобы её внешний ключ не мешал удалять кластеры
            conn.execute(text("UPDATE tasks SET cluster_id = NULL WHERE cluster_id IS NOT NULL"))

        # Задачи без ключа — на первый ключ кластера по умолчанию
        conn.execute(text(
            "UPDATE tasks SET key_id = (SELECT MIN(k.id) FROM cluster_keys k JOIN clusters c ON c.id = k.cluster_id "
            "WHERE c.is_default) WHERE key_id IS NULL"))
