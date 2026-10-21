"""Общее для веб-страниц: шаблоны, фильтры, текущий пользователь."""

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .config import settings
from .models import MODE_CRON, MODE_NOW, MODE_ONCE, User
from .profiler import KIND_LABELS, query_kind, speed_level

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=BASE_DIR / "templates")

TTL_UNITS = {"m": 1, "h": 60, "d": 1440}


def to_local(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(settings.tz)


def f_dt(dt: datetime | None) -> str:
    dt = to_local(dt)
    return dt.strftime("%d.%m.%Y %H:%M:%S") if dt else "—"


def f_size(n: int | None) -> str:
    if n is None:
        return "—"
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if n < 1024 or unit == "ГБ":
            return f"{n:.0f} {unit}" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def f_duration(ms: int | None) -> str:
    if ms is None:
        return "—"
    return f"{ms} мс" if ms < 1000 else f"{ms / 1000:.1f} с"


def f_ttl(minutes: int) -> str:
    if minutes % 1440 == 0:
        return f"{minutes // 1440} дн."
    if minutes % 60 == 0:
        return f"{minutes // 60} ч."
    return f"{minutes} мин."


def _static_version() -> str:
    """Хеш содержимого статики: меняется при обновлении сервиса, и браузер не берёт старые CSS/JS из кэша."""
    digest = hashlib.sha256()
    for path in sorted((BASE_DIR / "static").rglob("*")):
        if path.is_file():
            digest.update(path.name.encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()[:12]


STATIC_VERSION = _static_version()

templates.env.filters.update(dt=f_dt, size=f_size, duration=f_duration, ttl=f_ttl)
templates.env.globals.update(settings=settings, MODE_NOW=MODE_NOW, MODE_ONCE=MODE_ONCE, MODE_CRON=MODE_CRON,
                             KIND_LABELS=KIND_LABELS, query_kind=query_kind, speed_level=speed_level,
                             static_version=STATIC_VERSION)


def current_user(request: Request) -> User:
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(401, "Требуется вход")
    return user


def require_admin(request: Request) -> User:
    user = current_user(request)
    if not user.is_admin:
        raise HTTPException(403, "Раздел доступен только администраторам")
    return user


def render(request: Request, name: str, status_code: int = 200, **ctx) -> HTMLResponse:
    ctx.setdefault("user", getattr(request.state, "user", None))
    return templates.TemplateResponse(request, name, ctx, status_code=status_code)


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def safe_next(url: str | None) -> str:
    """Только относительные адреса этого сервиса (защита от открытого редиректа)."""
    if url and url.startswith("/") and not url.startswith("//") and "\\" not in url:
        return url
    return "/"
