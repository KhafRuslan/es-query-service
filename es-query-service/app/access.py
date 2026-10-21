"""Права доступа: какие ключи (и через них кластеры) доступны пользователю."""

from sqlalchemy import true

from .db import SessionLocal
from .models import ClusterKey, Task, User


def allowed_key_ids(user: User) -> set[int] | None:
    """Ключи из ролей пользователя; None — без ограничений (администратор)."""
    if user.is_admin:
        return None
    return {k.id for role in user.roles for k in role.keys}


def can_use_key(user: User, key_id: int | None) -> bool:
    allowed = allowed_key_ids(user)
    return key_id is not None and (allowed is None or key_id in allowed)


def can_see_task(user: User, task: Task) -> bool:
    return user.is_admin or can_use_key(user, task.key_id)


def task_filter(user: User):
    """Условие для запросов: задачи, видимые пользователю."""
    allowed = allowed_key_ids(user)
    if allowed is None:
        return true()
    return Task.key_id.in_(allowed)


def run_permission_error(user_id: int | None, key_id: int | None) -> str | None:
    """Почему запуск от имени пользователя невозможен (None — можно)."""
    with SessionLocal() as s:
        if key_id is None or s.get(ClusterKey, key_id) is None:
            return "Для задачи не выбран ключ доступа (или он удалён) — выберите ключ в настройках задачи"
        if user_id is None:
            return "У задачи нет владельца (пользователь удалён) — откройте задачу и сохраните её, чтобы стать владельцем"
        user = s.get(User, user_id)
        if user is None or not user.is_active:
            return "Владелец задачи удалён или заблокирован"
        if not can_use_key(user, key_id):
            return f"У пользователя {user.title} нет доступа к ключу задачи (проверьте его роли)"
    return None
