"""Выполнение запроса: Elasticsearch -> сохранение -> webhook."""

import asyncio
import logging
import re
import secrets
import time
from dataclasses import dataclass
from datetime import timedelta
from urllib.parse import quote

import httpx

from . import storage
from .config import settings
from .db import SessionLocal, utcnow
from .access import run_permission_error
from .profiler import KIND_SEARCH, query_kind, schedule_profile
from .es import ESRequestError, es_pool
from .models import RUN_ERROR, RUN_RUNNING, RUN_SUCCESS, Run, Task, User

log = logging.getLogger(__name__)

_semaphore: asyncio.Semaphore | None = None


def _sem() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(settings.max_concurrent_queries)
    return _semaphore


@dataclass
class RunOutcome:
    run_id: int
    status: str
    content: bytes | None
    content_type: str | None


def parse_headers(text: str | None) -> dict[str, str]:
    """Заголовки в формате 'Name: value' по одному на строку."""
    headers: dict[str, str] = {}
    for n, line in enumerate((text or "").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        name, sep, value = line.partition(":")
        if not sep or not name.strip():
            raise ValueError(f"Заголовок в строке {n} должен иметь вид 'Имя: значение'")
        headers[name.strip()] = value.strip()
    return headers


async def send_webhook(url: str, headers_text: str | None, content: bytes, content_type: str,
                       task_id: int, run_id: int, task_name: str, cluster_name: str = "") -> str:
    headers = {
        "Content-Type": content_type or "application/json",
        "X-ES-Task-Id": str(task_id),
        "X-ES-Run-Id": str(run_id),
        "X-ES-Task-Name": quote(task_name),  # URL-encoded (кириллица)
        "X-ES-Cluster": quote(cluster_name),
        "User-Agent": "es-query-service",
    }
    headers.update(parse_headers(headers_text))
    last_error = ""
    async with httpx.AsyncClient(timeout=settings.webhook_timeout, follow_redirects=True) as client:
        for attempt in range(1, settings.webhook_retries + 1):
            try:
                resp = await client.post(url, content=content, headers=headers)
                if resp.status_code < 300:
                    return f"OK: HTTP {resp.status_code}"
                last_error = f"HTTP {resp.status_code}: {resp.text[:300]}"
                if 400 <= resp.status_code < 500 and resp.status_code not in (408, 429):
                    break  # повтор не поможет
            except httpx.HTTPError as e:
                last_error = f"{type(e).__name__}: {e}"
            if attempt < settings.webhook_retries:
                await asyncio.sleep(2 ** attempt)
    return f"Ошибка (попыток: {attempt}): {last_error}"


_background: set[asyncio.Task] = set()


def start_run(task_id: int, trigger: str, user_id: int | None = None, client_ip: str | None = None) -> int | None:
    """Создаёт запись о запуске (статус running) и возвращает её id.

    user_id — кто запустил вручную; для запусков по расписанию запуск идёт от имени владельца задачи.
    """
    with SessionLocal() as s:
        task = s.get(Task, task_id)
        if task is None:
            return None
        actor_id = user_id if user_id is not None else task.owner_id
        actor = s.get(User, actor_id) if actor_id is not None else None
        run = Run(task_id=task_id, trigger=trigger, status=RUN_RUNNING, started_at=utcnow(),
                  cluster_name=task.key.cluster.name if task.key else None,
                  key_name=task.key.name if task.key else None,
                  user_id=actor.id if actor else None, user_name=actor.title if actor else None,
                  client_ip=client_ip)
        s.add(run)
        s.commit()
        return run.id


async def execute(task_id: int, trigger: str) -> RunOutcome | None:
    run_id = start_run(task_id, trigger)
    return await perform(run_id) if run_id else None


def perform_in_background(run_id: int) -> None:
    t = asyncio.create_task(perform(run_id))
    _background.add(t)
    t.add_done_callback(_background.discard)


async def perform(run_id: int) -> RunOutcome | None:
    with SessionLocal() as s:
        run = s.get(Run, run_id)
        if run is None:
            return None
        task_id, trigger, task = run.task_id, run.trigger, run.task
        key_id, actor_id = task.key_id, run.user_id
        cluster_name = task.key.cluster.name if task.key else ""
        spec = {c: getattr(task, c) for c in (
            "name", "method", "path", "body", "webhook_url", "webhook_headers",
            "store_result", "store_ttl_minutes", "share_result")}

    log.info("Запуск задачи %s (%s), run=%s", task_id, trigger, run_id)
    t0 = time.monotonic()
    status, es_status, error, content, ctype = RUN_ERROR, None, None, None, None
    try:
        denied = run_permission_error(actor_id, key_id)
        if denied:
            raise ESRequestError(denied)
        async with _sem():
            resp = await es_pool.request(key_id, spec["method"], spec["path"], spec["body"])
        es_status, content, ctype = resp.status, resp.content, resp.content_type
        if 200 <= resp.status < 300:
            status = RUN_SUCCESS
        else:
            error = f"Elasticsearch вернул HTTP {resp.status}: {resp.content[:1000].decode('utf-8', 'replace')}"
    except (ESRequestError, ValueError) as e:
        error = str(e)
    except Exception as e:  # noqa: BLE001
        log.exception("Ошибка выполнения run=%s", run_id)
        error = f"{type(e).__name__}: {e}"
    duration = int((time.monotonic() - t0) * 1000)

    # Сохранение: если включено в задаче, либо временно — для ручного запуска и вебхука (чтобы забрать результат)
    ttl = spec["store_ttl_minutes"] if spec["store_result"] else (
        settings.default_result_ttl_minutes if trigger in ("manual", "webhook") else None)
    result_file = expires_at = token = None
    if content is not None and ttl:
        result_file = await storage.save(run_id, content)
        expires_at = utcnow() + timedelta(minutes=ttl)
        if spec["store_result"] and spec["share_result"] and status == RUN_SUCCESS:
            token = secrets.token_urlsafe(24)

    send_hook = bool(spec["webhook_url"]) and status == RUN_SUCCESS
    if not _update_run(run_id, status=status, finished_at=utcnow(), duration_ms=duration,
                       es_status=es_status, es_took_ms=extract_took(content) if status == RUN_SUCCESS else None,
                       error=error, result_file=result_file,
                       result_size=len(content) if content is not None else None,
                       content_type=ctype, expires_at=expires_at, share_token=token,
                       webhook_status="Отправляется…" if send_hook else None):
        storage.remove(result_file)  # задачу удалили во время выполнения
        return None

    # Поисковый запрос профилируется один раз — если для текущей версии запроса профиля ещё нет
    if status == RUN_SUCCESS and query_kind(spec["path"]) == KIND_SEARCH:
        schedule_profile(task_id, actor_id)

    if send_hook:
        wh = await send_webhook(spec["webhook_url"], spec["webhook_headers"], content, ctype,
                                task_id, run_id, spec["name"], cluster_name)
        _update_run(run_id, webhook_status=wh)

    log.info("Задача %s run=%s: %s за %d мс", task_id, run_id, status, duration)
    return RunOutcome(run_id, status, content, ctype)


_TOOK = re.compile(rb'^\s*\{\s*"took"\s*:\s*(\d+)')


def extract_took(content: bytes | None) -> int | None:
    """"took" из ответа поиска: ES пишет его первым полем, поэтому читаем только начало ответа."""
    m = _TOOK.match(content[:64]) if content else None
    return int(m.group(1)) if m else None


def _update_run(run_id: int, **fields) -> bool:
    with SessionLocal() as s:
        run = s.get(Run, run_id)
        if run is None:
            return False
        for k, v in fields.items():
            setattr(run, k, v)
        s.commit()
        return True
