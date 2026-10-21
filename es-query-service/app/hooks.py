"""Входящие вебхуки: внешняя система запускает задачу POST-запросом на секретный адрес.

    POST /hooks/<token>                     запуск, ответ 202 с номером запуска
    POST /hooks/<token>?wait=1[&timeout=N]  дождаться выполнения и вернуть ответ Elasticsearch
    GET  /hooks/<token>/runs/<id>           статус запуска
    GET  /hooks/<token>/runs/<id>/result    сохранённый результат

Запуск идёт от имени автора задачи (как запуски по расписанию), права проверяются при выполнении.
"""

import asyncio
import ipaddress
import logging
import secrets
import time

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from sqlalchemy import select

from . import storage
from .config import settings
from .db import SessionLocal, utcnow
from .executor import perform, start_run
from .models import RUN_RUNNING, RUN_SUCCESS, Run, Task

log = logging.getLogger(__name__)
router = APIRouter()

TRIGGER = "webhook"


def new_token() -> str:
    return secrets.token_urlsafe(32)


def hook_url(request: Request, token: str) -> str:
    base = (settings.public_base_url or str(request.base_url)).rstrip("/")
    return f"{base}/hooks/{token}"


# ---------------------------------------------------------------- ограничения по IP и частоте

def parse_networks(text: str | None) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """IP-адреса и подсети через запятую, пробел или с новой строки. Ошибка — ValueError с понятным текстом."""
    nets = []
    for item in (text or "").replace(",", " ").split():
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            raise ValueError(f"Некорректный IP-адрес или подсеть: {item}") from None
    return nets


def ip_allowed(client_ip: str | None, allowed: str | None) -> bool:
    nets = parse_networks(allowed)
    if not nets:
        return True
    try:
        ip = ipaddress.ip_address(client_ip or "")
    except ValueError:
        return False
    return any(ip in net for net in nets)


_calls: dict[int, list[float]] = {}


def max_rate_limit() -> int:
    return max(1, settings.hook_rate_limit_per_minute)


def effective_rate_limit(task_limit: int | None) -> int:
    """Лимит задачи, но не больше максимума из HOOK_RATE_LIMIT_PER_MINUTE (его могли снизить после сохранения)."""
    return min(task_limit, max_rate_limit()) if task_limit else max_rate_limit()


def parse_rate_limit(value: str | None) -> int | None:
    """Значение из формы: пусто — максимум (None), иначе целое от 1 до максимума."""
    value = (value or "").strip()
    if not value:
        return None
    try:
        limit = int(value)
    except ValueError:
        raise ValueError("Лимит вызовов вебхука должен быть целым числом") from None
    if not 1 <= limit <= max_rate_limit():
        raise ValueError(f"Лимит вызовов вебхука — от 1 до {max_rate_limit()} в минуту "
                         "(максимум задаёт администратор переменной HOOK_RATE_LIMIT_PER_MINUTE)")
    return limit


def rate_limited(task_id: int, limit: int) -> bool:
    now = time.monotonic()
    calls = [t for t in _calls.get(task_id, []) if now - t < 60]
    limited = len(calls) >= limit
    if not limited:
        calls.append(now)
    _calls[task_id] = calls
    return limited


# ---------------------------------------------------------------- эндпоинты

def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


def _task_by_token(token: str) -> Task | None:
    with SessionLocal() as s:
        return s.scalar(select(Task).where(Task.hook_token == token)) if token else None


def _run_info(request: Request, token: str, run: Run) -> dict:
    base = hook_url(request, token)
    info = {
        "run_id": run.id,
        "task_id": run.task_id,
        "status": run.status,
        "started_at": run.started_at.isoformat() + "Z" if run.started_at else None,
        "finished_at": run.finished_at.isoformat() + "Z" if run.finished_at else None,
        "duration_ms": run.duration_ms,
        "es_status": run.es_status,
        "error": run.error,
        "status_url": f"{base}/runs/{run.id}",
    }
    if run.result_file and run.expires_at and run.expires_at > utcnow():
        info["result_url"] = f"{base}/runs/{run.id}/result"
        info["result_expires_at"] = run.expires_at.isoformat() + "Z"
    return info


@router.post("/hooks/{token}")
async def hook_trigger(request: Request, token: str, wait: bool = False, timeout: float | None = None):
    task = _task_by_token(token)
    if task is None:
        return _error(404, "Вебхук не найден или отключён")
    client_ip = request.client.host if request.client else None
    if not ip_allowed(client_ip, task.hook_allowed_ips):
        log.warning("Вебхук задачи %s: вызов с запрещённого адреса %s", task.id, client_ip)
        return _error(403, f"Вызов с адреса {client_ip} не разрешён")
    limit = effective_rate_limit(task.hook_rate_limit)
    if rate_limited(task.id, limit):
        return _error(429, f"Слишком много вызовов: не больше {limit} в минуту")

    run_id = start_run(task.id, TRIGGER, client_ip=client_ip)
    if run_id is None:
        return _error(404, "Задача не найдена")
    log.info("Вебхук: задача %s, запуск %s, адрес %s", task.id, run_id, client_ip)
    job = asyncio.create_task(perform(run_id))
    _jobs.add(job)
    job.add_done_callback(_jobs.discard)

    if wait:
        limit = min(timeout or settings.es_timeout, settings.es_timeout + 30)
        try:
            outcome = await asyncio.wait_for(asyncio.shield(job), limit)
        except asyncio.TimeoutError:
            outcome = None  # запуск продолжается; статус можно получить по status_url
        if outcome is not None and outcome.content is not None and outcome.status == RUN_SUCCESS:
            return Response(outcome.content, media_type=outcome.content_type or "application/json",
                            headers={"X-ES-Run-Id": str(run_id), "X-ES-Task-Id": str(task.id)})

    with SessionLocal() as s:
        run = s.get(Run, run_id)
        info = _run_info(request, token, run)
    if wait and run.status not in (RUN_RUNNING, RUN_SUCCESS):
        return JSONResponse(info, status_code=502)  # запрос в ES завершился ошибкой
    return JSONResponse(info, status_code=202 if run.status == RUN_RUNNING else 200)


_jobs: set[asyncio.Task] = set()


def _hook_run(token: str, run_id: int) -> Run | None:
    task = _task_by_token(token)
    if task is None:
        return None
    with SessionLocal() as s:
        run = s.get(Run, run_id)
        return run if run is not None and run.task_id == task.id else None


@router.get("/hooks/{token}/runs/{run_id}")
def hook_run_status(request: Request, token: str, run_id: int):
    run = _hook_run(token, run_id)
    if run is None:
        return _error(404, "Запуск не найден")
    return _run_info(request, token, run)


@router.get("/hooks/{token}/runs/{run_id}/result")
def hook_run_result(token: str, run_id: int):
    run = _hook_run(token, run_id)
    if run is None:
        return _error(404, "Запуск не найден")
    if not run.result_file or not run.expires_at or run.expires_at <= utcnow():
        return _error(404, "Результат не сохранён или срок его хранения истёк")
    path = storage.result_path(run.result_file)
    if not path.exists():
        return _error(404, "Файл результата не найден")
    return FileResponse(path, media_type=run.content_type or "application/json", headers={"Cache-Control": "no-store"})


@router.get("/hooks/{token}")
def hook_get(token: str):
    return _error(405, "Используйте POST для запуска задачи") if _task_by_token(token) else \
        _error(404, "Вебхук не найден или отключён")
