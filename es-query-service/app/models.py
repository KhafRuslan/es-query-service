from datetime import datetime

from sqlalchemy import Column, ForeignKey, Integer, String, Table, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base, utcnow

# Режимы запуска задачи
MODE_NOW = "now"      # моментально (и потом вручную по кнопке)
MODE_ONCE = "once"    # отложенно, один раз в заданное время
MODE_CRON = "cron"    # по расписанию

# Статусы запуска
RUN_RUNNING = "running"
RUN_SUCCESS = "success"
RUN_ERROR = "error"

# Статусы профилирования
PROFILE_RUNNING = "running"
PROFILE_DONE = "done"
PROFILE_ERROR = "error"
PROFILE_UNSUPPORTED = "unsupported"


class Task(Base):
    __tablename__ = "tasks"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))

    # Ключ доступа (через него — кластер), с которым выполняется запрос
    key_id: Mapped[int | None] = mapped_column(ForeignKey("cluster_keys.id"), default=None, index=True)
    # Автор задачи; от его имени выполняются запуски по расписанию
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), default=None, index=True)
    method: Mapped[str] = mapped_column(String(10), default="POST")
    path: Mapped[str] = mapped_column(String(2000))
    body: Mapped[str] = mapped_column(Text, default="")

    # Расписание
    mode: Mapped[str] = mapped_column(String(10), default=MODE_NOW)
    run_at: Mapped[datetime | None] = mapped_column(default=None)  # UTC
    cron: Mapped[str | None] = mapped_column(String(100), default=None)
    enabled: Mapped[bool] = mapped_column(default=True)

    # Доставка результата
    webhook_url: Mapped[str | None] = mapped_column(String(2000), default=None)
    webhook_headers: Mapped[str | None] = mapped_column(Text, default=None)  # "Header: value" построчно
    store_result: Mapped[bool] = mapped_column(default=False)
    store_ttl_minutes: Mapped[int] = mapped_column(Integer, default=1440)
    share_result: Mapped[bool] = mapped_column(default=False)

    # Входящий вебхук: POST /hooks/<hook_token> запускает задачу (None — выключен)
    hook_token: Mapped[str | None] = mapped_column(String(64), default=None, unique=True, index=True)
    hook_allowed_ips: Mapped[str | None] = mapped_column(Text, default=None)  # IP/подсети через запятую или с новой строки
    # Лимит вызовов в минуту, заданный пользователем (None — максимум из HOOK_RATE_LIMIT_PER_MINUTE)
    hook_rate_limit: Mapped[int | None] = mapped_column(default=None)

    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)

    key: Mapped["ClusterKey | None"] = relationship(lazy="joined")
    owner: Mapped["User | None"] = relationship(lazy="joined")
    runs: Mapped[list["Run"]] = relationship(
        back_populates="task",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="Run.id.desc()",
    )


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id", ondelete="CASCADE"), index=True)
    trigger: Mapped[str] = mapped_column(String(10))  # manual | once | cron
    cluster_name: Mapped[str | None] = mapped_column(String(100), default=None)
    key_name: Mapped[str | None] = mapped_column(String(100), default=None)
    # Кто запустил: пользователь (вручную) или владелец задачи (по расписанию). Имя — снимок на момент запуска
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), default=None)
    user_name: Mapped[str | None] = mapped_column(String(200), default=None)
    client_ip: Mapped[str | None] = mapped_column(String(64), default=None)  # кто вызвал входящий вебхук
    status: Mapped[str] = mapped_column(String(10), default=RUN_RUNNING)

    started_at: Mapped[datetime] = mapped_column(default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(default=None)
    duration_ms: Mapped[int | None] = mapped_column(default=None)

    es_status: Mapped[int | None] = mapped_column(default=None)
    es_took_ms: Mapped[int | None] = mapped_column(default=None)  # "took" из ответа поиска
    error: Mapped[str | None] = mapped_column(Text, default=None)

    # Сохранённый результат
    result_file: Mapped[str | None] = mapped_column(String(500), default=None)
    result_size: Mapped[int | None] = mapped_column(default=None)
    content_type: Mapped[str | None] = mapped_column(String(100), default=None)
    expires_at: Mapped[datetime | None] = mapped_column(default=None, index=True)
    share_token: Mapped[str | None] = mapped_column(String(64), default=None, unique=True, index=True)

    # Доставка на webhook
    webhook_status: Mapped[str | None] = mapped_column(Text, default=None)

    task: Mapped[Task] = relationship(back_populates="runs")

    @property
    def has_result(self) -> bool:
        return self.result_file is not None



class Cluster(Base):
    """Кластер Elasticsearch. Доступ к нему выполняется через ключи (ClusterKey)."""

    __tablename__ = "clusters"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    url: Mapped[str] = mapped_column(String(2000))
    verify_tls: Mapped[bool] = mapped_column(default=True)
    is_default: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)

    keys: Mapped[list["ClusterKey"]] = relationship(
        back_populates="cluster", cascade="all, delete-orphan", order_by="ClusterKey.name", lazy="selectin")


class ClusterKey(Base):
    """Ключ доступа к кластеру (API-ключ или «без авторизации»). Ключи выдаются пользователям через роли."""

    __tablename__ = "cluster_keys"

    id: Mapped[int] = mapped_column(primary_key=True)
    cluster_id: Mapped[int] = mapped_column(ForeignKey("clusters.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    api_key: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)

    cluster: Mapped[Cluster] = relationship(back_populates="keys", lazy="joined")

    @property
    def label(self) -> str:
        return f"{self.cluster.name} / {self.name}"


user_roles = Table(
    "user_roles", Base.metadata,
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
)

role_keys = Table(
    "role_keys", Base.metadata,
    Column("role_id", ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column("key_id", ForeignKey("cluster_keys.id", ondelete="CASCADE"), primary_key=True),
)


class Role(Base):
    """Роль — набор ключей доступа. Через ключи определяет, к каким кластерам есть доступ."""

    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(default=utcnow)

    keys: Mapped[list[ClusterKey]] = relationship(secondary=role_keys, lazy="selectin", order_by=ClusterKey.id)
    users: Mapped[list["User"]] = relationship(secondary=user_roles, back_populates="roles", lazy="selectin")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    display_name: Mapped[str] = mapped_column(String(200), default="")
    password_hash: Mapped[str] = mapped_column(String(300))
    is_admin: Mapped[bool] = mapped_column(default=False)
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(default=None)

    roles: Mapped[list[Role]] = relationship(secondary=user_roles, back_populates="users", lazy="selectin",
                                             order_by=Role.name)

    @property
    def title(self) -> str:
        return self.display_name or self.username


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(index=True)


class QueryProfile(Base):
    """Профиль поискового запроса (Profile API). Один на отпечаток запроса, общий для всех его запусков."""

    __tablename__ = "query_profiles"

    fingerprint: Mapped[str] = mapped_column(String(64), primary_key=True)
    cluster_id: Mapped[int | None] = mapped_column(ForeignKey("clusters.id", ondelete="CASCADE"), default=None)
    status: Mapped[str] = mapped_column(String(15))
    requested_at: Mapped[datetime] = mapped_column(default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(default=None)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    took_ms: Mapped[int | None] = mapped_column(default=None)
    complexity_score: Mapped[int | None] = mapped_column(default=None)
    complexity_level: Mapped[str | None] = mapped_column(String(30), default=None)
    speed_level: Mapped[str | None] = mapped_column(String(30), default=None)
    metrics: Mapped[str | None] = mapped_column(Text, default=None)  # JSON с подробностями
