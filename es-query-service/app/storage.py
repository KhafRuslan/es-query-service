"""Хранение результатов запросов на диске."""

import asyncio
import logging
import os
import time
from datetime import timedelta

from sqlalchemy import delete, select

from .config import settings
from .db import SessionLocal, utcnow
from .models import Run

log = logging.getLogger(__name__)


def result_path(name: str):
    return settings.results_dir / name


def _write(name: str, content: bytes) -> None:
    path = result_path(name)
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(content)
    os.replace(tmp, path)


async def save(run_id: int, content: bytes) -> str:
    name = f"{run_id}.json"
    await asyncio.to_thread(_write, name, content)
    return name


def remove(name: str | None) -> None:
    if name:
        result_path(name).unlink(missing_ok=True)


def read_head(name: str, limit: int) -> bytes:
    with open(result_path(name), "rb") as f:
        return f.read(limit)


def cleanup() -> None:
    """Удаляет просроченные результаты и старую историю запусков."""
    now = utcnow()
    with SessionLocal() as s:
        expired = s.scalars(select(Run).where(Run.expires_at.is_not(None), Run.expires_at <= now)).all()
        for run in expired:
            remove(run.result_file)
            run.result_file = None
            run.share_token = None
            run.expires_at = None
        if expired:
            log.info("Удалено просроченных результатов: %d", len(expired))

        old = now - timedelta(days=settings.run_history_days)
        old_runs = s.scalars(
            select(Run).where(Run.started_at < old, Run.result_file.is_(None))
        ).all()
        if old_runs:
            s.execute(delete(Run).where(Run.id.in_([r.id for r in old_runs])))
        s.commit()

        # Файлы, на которые больше нет ссылок (например, после удаления задачи)
        known = set(s.scalars(select(Run.result_file).where(Run.result_file.is_not(None))))
    # (старше часа — чтобы не задеть файл запуска, который ещё не успел записаться в БД)
    threshold = time.time() - 3600
    for path in settings.results_dir.glob("*.json"):
        if path.name not in known and path.stat().st_mtime < threshold:
            path.unlink(missing_ok=True)
