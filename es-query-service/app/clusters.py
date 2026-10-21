"""Кластеры и ключи доступа: чтение из БД и синхронизация с пулом HTTP-клиентов (по одному на ключ)."""

from sqlalchemy import select

from .access import allowed_key_ids
from .db import SessionLocal
from .es import Connection, es_pool
from .models import Cluster, ClusterKey, User


def to_conn(key: ClusterKey) -> Connection:
    return Connection(key.cluster.url, key.api_key, key.cluster.verify_tls)


def all_clusters(s) -> list[Cluster]:
    return list(s.scalars(select(Cluster).order_by(Cluster.is_default.desc(), Cluster.name)))


def default(s) -> Cluster | None:
    return s.scalar(select(Cluster).where(Cluster.is_default.is_(True))) or s.scalar(select(Cluster).order_by(Cluster.id))


def accessible_keys(s, user: User) -> list[ClusterKey]:
    """Ключи, доступные пользователю: сначала кластер по умолчанию, затем по названию."""
    q = select(ClusterKey).join(Cluster).order_by(Cluster.is_default.desc(), Cluster.name, ClusterKey.name)
    allowed = allowed_key_ids(user)
    if allowed is not None:
        q = q.where(ClusterKey.id.in_(allowed))
    return list(s.scalars(q).unique())


def sync_cluster(cluster: Cluster) -> None:
    for key in cluster.keys:
        es_pool.configure(key.id, to_conn(key))


def load_pool() -> int:
    """Создаёт клиентов для всех ключей. Возвращает число кластеров."""
    with SessionLocal() as s:
        clusters = all_clusters(s)
    for c in clusters:
        sync_cluster(c)
    return len(clusters)
