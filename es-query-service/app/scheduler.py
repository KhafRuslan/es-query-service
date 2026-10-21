"""Планировщик: отложенные (один раз) и периодические (cron) запуски."""

import logging
from datetime import datetime, timedelta, timezone

from apscheduler.jobstores.base import JobLookupError
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select, update

from . import profiler, storage
from .config import settings
from .db import SessionLocal, utcnow
from .executor import execute
from .models import MODE_CRON, MODE_NOW, MODE_ONCE, RUN_ERROR, RUN_RUNNING, Run, Task

log = logging.getLogger(__name__)

scheduler = AsyncIOScheduler(timezone=settings.tz)


def _job_id(task_id: int) -> str:
    return f"task-{task_id}"


def parse_cron(expr: str) -> CronTrigger:
    """Cron из 5 полей: минута час день месяц день_недели."""
    expr = " ".join((expr or "").split())
    if len(expr.split(" ")) != 5:
        raise ValueError("Cron-выражение должно состоять из 5 полей: минута час день месяц день_недели")
    try:
        return CronTrigger.from_crontab(expr, timezone=settings.tz)
    except ValueError as e:
        raise ValueError(f"Некорректное cron-выражение: {e}") from None


async def _run_job(task_id: int, trigger: str) -> None:
    if trigger == MODE_ONCE:
        # Отложенная задача выполняется один раз — после запуска выключаем её
        with SessionLocal() as s:
            s.execute(update(Task).where(Task.id == task_id).values(enabled=False))
            s.commit()
    await execute(task_id, trigger)


def sync_task(task: Task) -> None:
    """Приводит задание в планировщике в соответствие с задачей из БД."""
    remove_task(task.id)
    if not task.enabled:
        return
    common = dict(
        id=_job_id(task.id),
        replace_existing=True,
        misfire_grace_time=settings.misfire_grace_seconds,
        coalesce=True,
        max_instances=1,
    )
    if task.mode == MODE_ONCE and task.run_at:
        run_at = task.run_at.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        if run_at < now:
            # Сервис был выключен в момент запуска — выполняем сразу после старта
            run_at = now + timedelta(seconds=2)
        scheduler.add_job(_run_job, DateTrigger(run_date=run_at), args=[task.id, MODE_ONCE], **common)
    elif task.mode == MODE_CRON and task.cron:
        scheduler.add_job(_run_job, parse_cron(task.cron), args=[task.id, MODE_CRON], **common)


def remove_task(task_id: int) -> None:
    try:
        scheduler.remove_job(_job_id(task_id))
    except JobLookupError:
        pass


def next_run_time(task_id: int) -> datetime | None:
    job = scheduler.get_job(_job_id(task_id))
    return job.next_run_time if job else None


def _cleanup() -> None:
    storage.cleanup()
    profiler.cleanup()


def start() -> None:
    with SessionLocal() as s:
        # Запуски, прерванные остановкой сервиса
        s.execute(
            update(Run).where(Run.status == RUN_RUNNING)
            .values(status=RUN_ERROR, error="Выполнение прервано перезапуском сервиса", finished_at=utcnow())
        )
        s.commit()
        tasks = s.scalars(select(Task).where(Task.enabled.is_(True), Task.mode != MODE_NOW)).all()

    for task in tasks:
        try:
            sync_task(task)
        except Exception:  # noqa: BLE001
            log.exception("Не удалось запланировать задачу %s", task.id)

    profiler.reset_interrupted()
    scheduler.add_job(_cleanup, IntervalTrigger(minutes=settings.cleanup_interval_minutes),
                      id="cleanup", replace_existing=True, next_run_time=datetime.now(settings.tz))
    scheduler.start()
    log.info("Планировщик запущен, заданий по расписанию: %d", len(tasks))


def shutdown() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)
