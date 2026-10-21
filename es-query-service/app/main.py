import asyncio
import json
import logging
import math
import re
import secrets
from collections import Counter
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select

from . import admin_routes, auth_routes, hooks, profiler, scheduler, security, storage
from .access import allowed_key_ids, can_see_task, can_use_key, task_filter
from .clusters import accessible_keys, default as default_cluster, load_pool
from .config import settings
from .db import SessionLocal, init_db, utcnow
from .es import ALLOWED_METHODS, check_allowed, es_pool, normalize_path, validate_body
from .executor import parse_headers, perform, perform_in_background, start_run
from .models import (MODE_CRON, MODE_NOW, MODE_ONCE, PROFILE_DONE, RUN_ERROR, RUN_RUNNING, RUN_SUCCESS, ClusterKey, Run,
                     Task, User)
from .profiler import KIND_LABELS, KIND_SEARCH, profiles_for, query_kind, schedule_profile
from .web import BASE_DIR, TTL_UNITS, current_user, redirect, render, to_local

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("app")


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    auth_routes.bootstrap_admin_from_env()
    if not load_pool():
        log.info("Кластеры Elasticsearch не добавлены — откройте веб-интерфейс")
    scheduler.start()
    yield
    scheduler.shutdown()
    await es_pool.close()


app = FastAPI(title="ES Query Service", lifespan=lifespan, docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
app.include_router(auth_routes.router)
app.include_router(admin_routes.router)
app.include_router(hooks.router)

# Без входа: публичные ссылки, входящие вебхуки (защищены токеном в адресе), healthcheck, статика
OPEN_PREFIXES = ("/s/", "/hooks/", "/health", "/static/")
# Пока не добавлен ни один кластер, администратор может открыть только эти разделы
NO_CLUSTER_PREFIXES = ("/admin", "/clusters", "/account", "/logout", "/api/")


# ---------------------------------------------------------------- middleware

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith("/hooks/"):  # внешние системы: без сессии и проверки Origin, доступ по токену
        return await call_next(request)
    # Защита от CSRF: POST принимаем только со своего origin (дополнительно к SameSite cookie)
    if request.method == "POST":
        origin = request.headers.get("origin") or request.headers.get("referer")
        if origin and urlsplit(origin).netloc != request.headers.get("host"):
            return Response("Запрос с чужого источника отклонён", status_code=403)
    if path.startswith(OPEN_PREFIXES):
        return await call_next(request)

    # Первый запуск: создание администратора
    if not auth_routes.users_exist():
        return await call_next(request) if path == "/setup/admin" else redirect("/setup/admin")
    if path in ("/login", "/setup/admin"):
        return await call_next(request)

    user = security.user_by_session(request.cookies.get(security.SESSION_COOKIE))
    if user is None:
        if path.startswith("/api/") or request.method != "GET":
            return Response("Требуется вход", status_code=401)
        target = path + (f"?{request.url.query}" if request.url.query else "")
        return redirect(f"/login?next={quote(target)}")
    request.state.user = user

    if user.is_admin and not es_pool.configured and not path.startswith(NO_CLUSTER_PREFIXES):
        return redirect("/admin/clusters/new")
    return await call_next(request)


# ---------------------------------------------------------------- доступ к задачам и запускам

def share_url(request: Request, token: str) -> str:
    base = (settings.public_base_url or str(request.base_url)).rstrip("/")
    return f"{base}/s/{token}"


def get_task(s, task_id: int, user: User) -> Task:
    task = s.get(Task, task_id)
    if task is None or not can_see_task(user, task):
        raise HTTPException(404, "Задача не найдена")
    return task


def get_run(s, run_id: int, user: User) -> Run:
    run = s.get(Run, run_id)
    if run is None or not can_see_task(user, run.task):
        raise HTTPException(404, "Запуск не найден")
    return run


# ---------------------------------------------------------------- форма задачи

DEFAULT_BODY = '{\n  "query": {\n    "match_all": {}\n  },\n  "size": 10\n}'


def split_ttl(minutes: int) -> tuple[int, str]:
    for unit in ("d", "h"):
        if minutes % TTL_UNITS[unit] == 0:
            return minutes // TTL_UNITS[unit], unit
    return minutes, "m"


def form_from_task(task: Task | None, default_key_id: int | None = None) -> dict:
    if task is None:
        return {
            "key_id": default_key_id, "name": "", "method": "POST", "path": "/_search", "body": DEFAULT_BODY,
            "mode": MODE_NOW, "run_at": "", "cron": "0 9 * * *",
            "webhook_enabled": False, "webhook_url": "", "webhook_headers": "",
            "store_enabled": False, "ttl_value": 1, "ttl_unit": "d", "share_enabled": True,
            "hook_enabled": False, "hook_allowed_ips": "", "hook_rate_limit": "",
        }
    ttl_value, ttl_unit = split_ttl(task.store_ttl_minutes)
    run_at = to_local(task.run_at)
    return {
        "key_id": task.key_id, "name": task.name, "method": task.method, "path": task.path, "body": task.body,
        "mode": task.mode, "run_at": run_at.strftime("%Y-%m-%dT%H:%M") if run_at else "",
        "cron": task.cron or "0 9 * * *",
        "webhook_enabled": bool(task.webhook_url), "webhook_url": task.webhook_url or "",
        "webhook_headers": task.webhook_headers or "",
        "store_enabled": task.store_result, "ttl_value": ttl_value, "ttl_unit": ttl_unit,
        "share_enabled": task.share_result,
        "hook_enabled": bool(task.hook_token), "hook_allowed_ips": task.hook_allowed_ips or "",
        "hook_rate_limit": task.hook_rate_limit or "",
    }


def parse_task_form(data, user: User) -> tuple[dict, dict, list[str]]:
    """Возвращает (значения формы для повторного показа, поля задачи, ошибки)."""
    f = {
        "key_id": int(data["key_id"]) if (data.get("key_id") or "").isdigit() else None,
        "name": (data.get("name") or "").strip(),
        "method": (data.get("method") or "POST").upper(),
        "path": (data.get("path") or "").strip(),
        "body": (data.get("body") or "").replace("\r\n", "\n"),
        "mode": data.get("mode") or MODE_NOW,
        "run_at": (data.get("run_at") or "").strip(),
        "cron": " ".join((data.get("cron") or "").split()),
        "webhook_enabled": data.get("webhook_enabled") == "on",
        "webhook_url": (data.get("webhook_url") or "").strip(),
        "webhook_headers": (data.get("webhook_headers") or "").replace("\r\n", "\n").strip(),
        "store_enabled": data.get("store_enabled") == "on",
        "ttl_value": (data.get("ttl_value") or "1").strip(),
        "ttl_unit": data.get("ttl_unit") or "d",
        "share_enabled": data.get("share_enabled") == "on",
        "hook_enabled": data.get("hook_enabled") == "on",
        "hook_allowed_ips": (data.get("hook_allowed_ips") or "").strip(),
        "hook_rate_limit": (data.get("hook_rate_limit") or "").strip(),
    }
    errors: list[str] = []
    out: dict = {}

    with SessionLocal() as s:
        key_exists = f["key_id"] is not None and s.get(ClusterKey, f["key_id"]) is not None
    if not (key_exists and can_use_key(user, f["key_id"])):
        errors.append("Выберите кластер и ключ доступа")
    out["key_id"] = f["key_id"]

    out["name"] = f["name"][:200] or f"Запрос от {datetime.now(settings.tz):%d.%m.%Y %H:%M}"

    try:
        out["path"] = normalize_path(f["path"])
        out["method"] = f["method"]
        check_allowed(out["method"], out["path"])
        out["body"] = validate_body(out["path"], f["body"])
    except ValueError as e:
        errors.append(str(e))

    if f["mode"] not in (MODE_NOW, MODE_ONCE, MODE_CRON):
        errors.append("Неизвестный режим запуска")
    out["mode"] = f["mode"]
    out["run_at"] = None
    out["cron"] = None
    if f["mode"] == MODE_ONCE:
        try:
            local = datetime.fromisoformat(f["run_at"]).replace(tzinfo=settings.tz)
            if local <= datetime.now(settings.tz):
                errors.append("Время отложенного запуска должно быть в будущем")
            out["run_at"] = local.astimezone(timezone.utc).replace(tzinfo=None)
        except ValueError:
            errors.append("Укажите дату и время отложенного запуска")
    elif f["mode"] == MODE_CRON:
        try:
            scheduler.parse_cron(f["cron"])
            out["cron"] = f["cron"]
        except ValueError as e:
            errors.append(str(e))

    out["webhook_url"] = None
    out["webhook_headers"] = None
    if f["webhook_enabled"]:
        u = urlsplit(f["webhook_url"])
        if u.scheme not in ("http", "https") or not u.netloc:
            errors.append("Адрес webhook должен начинаться с http:// или https://")
        out["webhook_url"] = f["webhook_url"]
        try:
            parse_headers(f["webhook_headers"])
            out["webhook_headers"] = f["webhook_headers"] or None
        except ValueError as e:
            errors.append(str(e))

    out["store_result"] = f["store_enabled"]
    out["share_result"] = f["store_enabled"] and f["share_enabled"]
    try:
        ttl = int(f["ttl_value"]) * TTL_UNITS[f["ttl_unit"]]
        if ttl <= 0:
            raise ValueError
        if ttl > settings.max_result_ttl_days * 1440:
            errors.append(f"Срок хранения не может превышать {settings.max_result_ttl_days} дн.")
        out["store_ttl_minutes"] = ttl
    except (ValueError, KeyError):
        if f["store_enabled"]:
            errors.append("Укажите срок хранения — целое положительное число")
        out["store_ttl_minutes"] = 1440

    out["hook_allowed_ips"] = None
    out["hook_rate_limit"] = None
    if f["hook_enabled"]:
        try:
            nets = hooks.parse_networks(f["hook_allowed_ips"])
            out["hook_allowed_ips"] = "\n".join(str(n) for n in nets) or None
        except ValueError as e:
            errors.append(str(e))
        try:
            out["hook_rate_limit"] = hooks.parse_rate_limit(f["hook_rate_limit"])
        except ValueError as e:
            errors.append(str(e))

    if f["mode"] in (MODE_ONCE, MODE_CRON) and not (f["webhook_enabled"] or f["store_enabled"]):
        errors.append("Для отложенного и периодического запуска выберите, куда девать результат: "
                      "отправить на адрес и/или сохранить в сервисе")
    return f, out, errors


def task_form_page(request: Request, form: dict, task: Task | None, errors=(), status_code: int = 200):
    user = current_user(request)
    with SessionLocal() as s:
        keys = accessible_keys(s, user)
    groups: dict[str, list[ClusterKey]] = {}
    for k in keys:
        groups.setdefault(k.cluster.name, []).append(k)
    return render(request, "task_form.html", status_code, form=form, task=task, errors=list(errors),
                  methods=ALLOWED_METHODS, key_groups=groups)


def _default_key_id(user: User) -> int | None:
    """Первый доступный ключ кластера по умолчанию (или просто первый доступный)."""
    with SessionLocal() as s:
        keys = accessible_keys(s, user)
        default = default_cluster(s)
    for k in keys:
        if default and k.cluster_id == default.id:
            return k.id
    return keys[0].id if keys else None


def _apply(task: Task, values: dict) -> None:
    for k, v in values.items():
        setattr(task, k, v)
    task.enabled = True


# ---------------------------------------------------------------- задачи

@app.get("/", response_class=HTMLResponse)
def index(request: Request, kind: str | None = None):
    user = current_user(request)
    with SessionLocal() as s:
        all_tasks = s.scalars(select(Task).where(task_filter(user)).order_by(Task.id.desc())).unique().all()
        kinds = {t.id: query_kind(t.path) for t in all_tasks}
        kind = kind if kind in KIND_LABELS else None
        tasks = [t for t in all_tasks if kind is None or kinds[t.id] == kind]
        ids = [t.id for t in tasks]
        last_ids = s.scalars(select(func.max(Run.id)).where(Run.task_id.in_(ids)).group_by(Run.task_id)).all()
        last_runs = {r.task_id: r for r in s.scalars(select(Run).where(Run.id.in_(last_ids)))}
        # Средний took поисковых запросов по последним успешным запускам
        avg_took = dict(s.execute(select(Run.task_id, func.avg(Run.es_took_ms)).where(
            Run.task_id.in_(ids), Run.status == RUN_SUCCESS, Run.es_took_ms.is_not(None)).group_by(Run.task_id)).all())
        has_keys = bool(accessible_keys(s, user))
        errors_24h = s.scalar(select(func.count(Run.id)).where(
            Run.task_id.in_([t.id for t in all_tasks]), Run.status == RUN_ERROR,
            Run.started_at >= utcnow() - timedelta(hours=24)))
    # Сводка — по всем доступным задачам, независимо от выбранной вкладки
    upcoming = [(scheduler.next_run_time(t.id), t) for t in all_tasks]
    upcoming = sorted(((when, t) for when, t in upcoming if when), key=lambda x: x[0])
    stats = {
        "total": len(all_tasks),
        "scheduled": sum(1 for t in all_tasks if t.mode in (MODE_ONCE, MODE_CRON) and t.enabled),
        "errors_24h": errors_24h,
        "next": upcoming[0] if upcoming else None,
    }
    return render(request, "index.html", tasks=tasks, last_runs=last_runs, has_keys=has_keys, stats=stats,
                  kinds=kinds, kind=kind, kind_counts=Counter(kinds.values()), profiles=profiles_for(tasks),
                  avg_took=avg_took)


@app.get("/tasks/new", response_class=HTMLResponse)
def task_new(request: Request, clone: int | None = None):
    user = current_user(request)
    form = form_from_task(None, _default_key_id(user))
    if clone:
        with SessionLocal() as s:
            src = get_task(s, clone, user)
            form = form_from_task(src)
            form["name"] = f"{src.name} (копия)"
    return task_form_page(request, form, None)


@app.post("/tasks")
async def task_create(request: Request):
    user = current_user(request)
    data = await request.form()
    action = data.get("action", "save")
    f, values, errors = parse_task_form(data, user)
    if errors:
        return task_form_page(request, f, None, errors, 422)
    with SessionLocal() as s:
        task = Task(owner_id=user.id)
        _apply(task, values)
        task.hook_token = hooks.new_token() if f["hook_enabled"] else None
        s.add(task)
        s.commit()
        scheduler.sync_task(task)
        task_id = task.id
    _profile_if_search(task_id, values["path"], user)

    if values["mode"] == MODE_NOW:
        if action == "download":
            return await _run_and_download(task_id, user)
        if action == "run":
            return _run_now(task_id, user)
    return redirect(f"/tasks/{task_id}")


@app.get("/tasks/{task_id}", response_class=HTMLResponse)
def task_detail(request: Request, task_id: int, msg: str | None = None):
    user = current_user(request)
    with SessionLocal() as s:
        task = get_task(s, task_id, user)
        runs = s.scalars(select(Run).where(Run.task_id == task_id).order_by(Run.id.desc()).limit(50)).all()
        total_runs = s.scalar(select(func.count(Run.id)).where(Run.task_id == task_id))
        speed = _speed_stats(s, task_id)
    kind = query_kind(task.path)
    profile = profiles_for([task]).get(task.id) if kind == KIND_SEARCH else None
    metrics = json.loads(profile.metrics) if profile and profile.status == PROFILE_DONE and profile.metrics else None
    running = any(r.status == RUN_RUNNING for r in runs)
    return render(request, "task_detail.html", task=task, runs=runs, total_runs=total_runs,
                  next_run=scheduler.next_run_time(task_id), running=running, msg=msg,
                  kind=kind, profile=profile, metrics=metrics, speed=speed,
                  hook_url=hooks.hook_url(request, task.hook_token) if task.hook_token else None,
                  hook_limit=hooks.effective_rate_limit(task.hook_rate_limit))


def _stats(values: list[int]) -> dict | None:
    if not values:
        return None
    ordered = sorted(values)
    return {"last": values[0], "avg": round(sum(values) / len(values)), "min": ordered[0], "max": ordered[-1],
            "p95": ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]}


def _speed_stats(s, task_id: int, limit: int = 100) -> dict:
    """Скорость по последним успешным запускам: took из ответа ES и полное время запроса."""
    rows = s.execute(select(Run.es_took_ms, Run.duration_ms).where(
        Run.task_id == task_id, Run.status == RUN_SUCCESS).order_by(Run.id.desc()).limit(limit)).all()
    return {"count": len(rows), "took": _stats([r[0] for r in rows if r[0] is not None]),
            "duration": _stats([r[1] for r in rows if r[1] is not None])}


def _profile_if_search(task_id: int, path: str, user: User) -> None:
    if query_kind(path) == KIND_SEARCH:
        schedule_profile(task_id, user.id)


@app.post("/tasks/{task_id}/profile")
async def task_profile(request: Request, task_id: int):  # async: фоновая задача создаётся в event loop
    user = current_user(request)
    with SessionLocal() as s:
        task = get_task(s, task_id, user)
    if query_kind(task.path) != KIND_SEARCH:
        raise HTTPException(400, "Профилирование доступно только для поисковых запросов")
    schedule_profile(task_id, user.id, force=True)
    await asyncio.sleep(0)  # дать фоновой задаче отметить профиль как выполняющийся
    return redirect(f"/tasks/{task_id}#profile")


@app.get("/tasks/{task_id}/profile/status")
def task_profile_status(request: Request, task_id: int):
    with SessionLocal() as s:
        task = get_task(s, task_id, current_user(request))
    profile = profiles_for([task]).get(task.id)
    return {"status": profile.status if profile else None}


@app.get("/tasks/{task_id}/profile/raw")
def task_profile_raw(request: Request, task_id: int):
    with SessionLocal() as s:
        task = get_task(s, task_id, current_user(request))
    profile = profiles_for([task]).get(task.id)
    path = profiler.profile_path(profile.fingerprint) if profile and profile.status == PROFILE_DONE else None
    if path is None or not path.exists():
        raise HTTPException(404, "Профиль не найден")
    return FileResponse(path, media_type="application/json",
                        headers={"Content-Disposition": _attachment(f"profile_{task.name}_{task.id}.json")})


@app.get("/tasks/{task_id}/edit", response_class=HTMLResponse)
def task_edit(request: Request, task_id: int):
    user = current_user(request)
    with SessionLocal() as s:
        task = get_task(s, task_id, user)
    return task_form_page(request, form_from_task(task), task)


@app.post("/tasks/{task_id}")
async def task_update(request: Request, task_id: int):
    user = current_user(request)
    data = await request.form()
    f, values, errors = parse_task_form(data, user)
    with SessionLocal() as s:
        task = get_task(s, task_id, user)
        if errors:
            return task_form_page(request, f, task, errors, 422)
        _apply(task, values)
        # Адрес вебхука сохраняется при редактировании; новый выдаётся при включении или по кнопке
        task.hook_token = (task.hook_token or hooks.new_token()) if f["hook_enabled"] else None
        if task.owner_id is None:  # владелец удалён — задачу забирает тот, кто её сохранил
            task.owner_id = user.id
        s.commit()
        scheduler.sync_task(task)
    _profile_if_search(task_id, values["path"], user)  # запрос изменился — профиль строится заново
    if values["mode"] == MODE_NOW:
        if data.get("action") == "download":
            return await _run_and_download(task_id, user)
        if data.get("action") == "run":
            return _run_now(task_id, user)
    return redirect(f"/tasks/{task_id}?msg=saved")


@app.post("/tasks/{task_id}/run")
async def task_run(request: Request, task_id: int):  # async: фоновая задача создаётся в event loop
    return _run_now(task_id, current_user(request))


@app.post("/tasks/{task_id}/download")
async def task_download(request: Request, task_id: int):
    return await _run_and_download(task_id, current_user(request))


@app.post("/tasks/{task_id}/toggle")
def task_toggle(request: Request, task_id: int):
    user = current_user(request)
    with SessionLocal() as s:
        task = get_task(s, task_id, user)
        if task.mode == MODE_ONCE and not task.enabled and task.run_at and task.run_at <= utcnow():
            return redirect(f"/tasks/{task_id}?msg=past")
        task.enabled = not task.enabled
        s.commit()
        scheduler.sync_task(task)
    return redirect(f"/tasks/{task_id}")


@app.post("/tasks/{task_id}/hook/rotate")
def task_hook_rotate(request: Request, task_id: int):
    """Новый адрес вебхука (старый перестаёт работать) или включение вебхука."""
    with SessionLocal() as s:
        task = get_task(s, task_id, current_user(request))
        task.hook_token = hooks.new_token()
        s.commit()
    return redirect(f"/tasks/{task_id}?msg=hook#hook")


@app.post("/tasks/{task_id}/hook/disable")
def task_hook_disable(request: Request, task_id: int):
    with SessionLocal() as s:
        task = get_task(s, task_id, current_user(request))
        task.hook_token = None
        s.commit()
    return redirect(f"/tasks/{task_id}?msg=hook_off#hook")


@app.post("/tasks/{task_id}/delete")
def task_delete(request: Request, task_id: int):
    user = current_user(request)
    with SessionLocal() as s:
        task = get_task(s, task_id, user)
        files = s.scalars(select(Run.result_file).where(Run.task_id == task_id, Run.result_file.is_not(None))).all()
        s.delete(task)
        s.commit()
    scheduler.remove_task(task_id)
    for name in files:
        storage.remove(name)
    return redirect("/")


def _start(task_id: int, user: User) -> int:
    with SessionLocal() as s:
        get_task(s, task_id, user)
    run_id = start_run(task_id, "manual", user.id)
    if run_id is None:
        raise HTTPException(404, "Задача не найдена")
    return run_id


def _run_now(task_id: int, user: User):
    run_id = _start(task_id, user)
    perform_in_background(run_id)
    return redirect(f"/runs/{run_id}")


def _download_name(task_name: str, run_id: int, ext: str = "json") -> str:
    return f"{task_name}_{run_id}_{datetime.now(settings.tz):%Y%m%d_%H%M%S}.{ext}"


def _attachment(filename: str) -> str:
    ascii_name = re.sub(r"[^A-Za-z0-9._-]+", "_", filename).strip("_") or "result.json"
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(filename)}"


async def _run_and_download(task_id: int, user: User):
    run_id = _start(task_id, user)
    outcome = await perform(run_id)
    if outcome is None or outcome.content is None:
        return redirect(f"/runs/{run_id}")
    with SessionLocal() as s:
        name = s.get(Task, task_id).name
    ext = "json" if "json" in (outcome.content_type or "json") else "txt"
    return Response(outcome.content, media_type=outcome.content_type or "application/json",
                    headers={"Content-Disposition": _attachment(_download_name(name, run_id, ext))})


# ---------------------------------------------------------------- запуски

@app.get("/runs", response_class=HTMLResponse)
def runs_list(request: Request, stored: bool = False):
    user = current_user(request)
    with SessionLocal() as s:
        q = select(Run).join(Task).where(task_filter(user)).order_by(Run.id.desc()).limit(200)
        if stored:
            q = q.where(Run.result_file.is_not(None))
        runs = s.scalars(q).all()
        names = dict(s.execute(select(Task.id, Task.name)).all())
    return render(request, "runs.html", runs=runs, names=names, stored=stored)


def _summary(data) -> list[tuple[str, str]]:
    if not isinstance(data, dict):
        return []
    out = []
    if "took" in data:
        out.append(("Время в ES", f"{data['took']} мс"))
    hits = data.get("hits")
    if isinstance(hits, dict):
        total = hits.get("total")
        if isinstance(total, dict):
            out.append(("Найдено", f"{'≥ ' if total.get('relation') == 'gte' else ''}{total.get('value')}"))
        elif total is not None:
            out.append(("Найдено", str(total)))
        if isinstance(hits.get("hits"), list):
            out.append(("Возвращено документов", str(len(hits["hits"]))))
    if "count" in data:
        out.append(("Количество", str(data["count"])))
    if isinstance(data.get("aggregations"), dict):
        out.append(("Агрегации", ", ".join(data["aggregations"].keys())))
    if isinstance(data.get("responses"), list):
        out.append(("Ответов (msearch)", str(len(data["responses"]))))
    shards = data.get("_shards")
    if isinstance(shards, dict) and shards.get("failed"):
        out.append(("Ошибок шардов", str(shards["failed"])))
    if data.get("timed_out"):
        out.append(("Таймаут", "да"))
    return out


@app.get("/runs/{run_id}", response_class=HTMLResponse)
def run_detail(request: Request, run_id: int):
    user = current_user(request)
    with SessionLocal() as s:
        run = get_run(s, run_id, user)
        task = run.task
    preview, truncated, summary = None, False, []
    if run.result_file:
        limit = settings.preview_max_kb * 1024
        try:
            raw = storage.read_head(run.result_file, limit + 1)
        except FileNotFoundError:
            raw = None
        if raw is not None:
            truncated = len(raw) > limit
            text = raw[:limit].decode("utf-8", "replace")
            if not truncated:
                try:
                    data = json.loads(text)
                    summary = _summary(data)
                    text = json.dumps(data, ensure_ascii=False, indent=2)
                except json.JSONDecodeError:
                    pass
            preview = text
    return render(request, "run_detail.html", run=run, task=task, preview=preview, truncated=truncated,
                  summary=summary, share=share_url(request, run.share_token) if run.share_token else None)


@app.get("/runs/{run_id}/status")
def run_status(request: Request, run_id: int):
    with SessionLocal() as s:
        run = get_run(s, run_id, current_user(request))
        return {"status": run.status, "webhook_status": run.webhook_status}


@app.get("/runs/{run_id}/download")
def run_download(request: Request, run_id: int):
    with SessionLocal() as s:
        run = get_run(s, run_id, current_user(request))
        name = run.task.name
    return _file_response(run, _download_name(name, run.id), attachment=True)


@app.post("/runs/{run_id}/share")
def run_share(request: Request, run_id: int):
    with SessionLocal() as s:
        run = get_run(s, run_id, current_user(request))
        if run.result_file and not run.share_token:
            run.share_token = secrets.token_urlsafe(24)
            s.commit()
    return redirect(f"/runs/{run_id}")


@app.post("/runs/{run_id}/unshare")
def run_unshare(request: Request, run_id: int):
    with SessionLocal() as s:
        run = get_run(s, run_id, current_user(request))
        run.share_token = None
        s.commit()
    return redirect(f"/runs/{run_id}")


@app.post("/runs/{run_id}/ttl")
async def run_ttl(request: Request, run_id: int):
    data = await request.form()
    try:
        minutes = int(data.get("ttl_value", "")) * TTL_UNITS[data.get("ttl_unit", "d")]
    except (ValueError, KeyError):
        raise HTTPException(400, "Некорректный срок") from None
    if not 0 < minutes <= settings.max_result_ttl_days * 1440:
        raise HTTPException(400, f"Срок должен быть от 1 минуты до {settings.max_result_ttl_days} дн.")
    with SessionLocal() as s:
        run = get_run(s, run_id, current_user(request))
        if run.result_file:
            run.expires_at = utcnow() + timedelta(minutes=minutes)
            s.commit()
    return redirect(f"/runs/{run_id}")


@app.post("/runs/{run_id}/delete-result")
def run_delete_result(request: Request, run_id: int):
    with SessionLocal() as s:
        run = get_run(s, run_id, current_user(request))
        storage.remove(run.result_file)
        run.result_file = run.share_token = run.expires_at = None
        s.commit()
    return redirect(f"/runs/{run_id}")


def _file_response(run: Run, filename: str, attachment: bool) -> Response:
    if not run.result_file or (run.expires_at and run.expires_at <= utcnow()):
        raise HTTPException(404, "Результат не найден или срок его хранения истёк")
    path = storage.result_path(run.result_file)
    if not path.exists():
        raise HTTPException(404, "Файл результата не найден")
    media = run.content_type or "application/json"
    headers = {"Content-Disposition": _attachment(filename) if attachment else "inline",
               "Cache-Control": "no-store"}
    return FileResponse(path, media_type=media, headers=headers)


# ---------------------------------------------------------------- публичные ссылки

@app.get("/s/{token}")
def shared(token: str, download: bool = False):
    with SessionLocal() as s:
        run = s.scalar(select(Run).where(Run.share_token == token))
        if run is None:
            raise HTTPException(404, "Ссылка недействительна или срок хранения истёк")
        name = run.task.name
    return _file_response(run, _download_name(name, run.id), attachment=download)


# ---------------------------------------------------------------- служебное

@app.get("/health")
def health():
    return {"status": "ok", "scheduler": scheduler.scheduler.running}


@app.get("/api/status")
async def api_status(request: Request):
    """Доступность кластеров и ключей, доступных пользователю (результат кэшируется на 30 с)."""
    user = current_user(request)
    with SessionLocal() as s:
        keys = [(k.id, k.name, k.cluster_id, k.cluster.name) for k in accessible_keys(s, user)]
    results = await asyncio.gather(*(es_pool.status(k[0]) for k in keys))
    key_list = [{"id": kid, "name": name, "cluster_id": cid, **res} for (kid, name, cid, _), res in zip(keys, results)]
    clusters: dict[int, dict] = {}
    for (_, _, cid, cname), res in zip(keys, results):
        c = clusters.setdefault(cid, {"id": cid, "name": cname, "ok": False, "error": res.get("error")})
        if res["ok"] and not c["ok"]:
            c.update(ok=True, cluster=res["cluster"], version=res["version"], error=None)
    return {"clusters": list(clusters.values()), "keys": key_list, "restricted": allowed_key_ids(user) is not None}
