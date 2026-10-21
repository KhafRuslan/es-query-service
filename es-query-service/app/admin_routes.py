"""Администрирование: пользователи, роли, кластеры и ключи доступа (только для администраторов)."""

import logging
import re
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select, update

from . import security
from .clusters import all_clusters, sync_cluster, to_conn
from .config import settings
from .db import SessionLocal
from .es import Connection, ESRequestError, es_pool, normalize_api_key, normalize_url, probe
from .models import Cluster, ClusterKey, Role, Task, User
from .web import redirect, render, require_admin

log = logging.getLogger(__name__)
router = APIRouter(dependencies=[Depends(require_admin)])


def _ids(values) -> set[int]:
    return {int(v) for v in values if str(v).isdigit()}


def _get(s, model, obj_id: int, what: str):
    obj = s.get(model, obj_id)
    if obj is None:
        raise HTTPException(404, f"{what} не найден")
    return obj


@router.get("/admin")
def admin_home():
    return redirect("/admin/users")


# ================================================================ пользователи

@router.get("/admin/users", response_class=HTMLResponse)
def users_page(request: Request, msg: str | None = None):
    with SessionLocal() as s:
        users = list(s.scalars(select(User).order_by(User.username)))
        tasks = dict(s.execute(select(Task.owner_id, func.count(Task.id)).group_by(Task.owner_id)).all())
    return render(request, "admin/users.html", users=users, tasks=tasks, msg=msg, section="users")


def _user_form_page(request: Request, target: User | None, form: dict, status_code: int = 200, error: str = ""):
    with SessionLocal() as s:
        roles = list(s.scalars(select(Role).order_by(Role.name)))
    return render(request, "admin/user_form.html", status_code, target=target, form=form, roles=roles,
                  error=error, section="users")


@router.get("/admin/users/new", response_class=HTMLResponse)
def user_new(request: Request):
    return _user_form_page(request, None, {"username": "", "display_name": "", "is_admin": False,
                                           "is_active": True, "role_ids": set()})


@router.get("/admin/users/{user_id}", response_class=HTMLResponse)
def user_edit(request: Request, user_id: int):
    with SessionLocal() as s:
        target = _get(s, User, user_id, "Пользователь")
    return _user_form_page(request, target, {
        "username": target.username, "display_name": target.display_name, "is_admin": target.is_admin,
        "is_active": target.is_active, "role_ids": {r.id for r in target.roles}})


def _other_active_admins(s, user_id: int | None) -> int:
    q = select(func.count(User.id)).where(User.is_admin.is_(True), User.is_active.is_(True))
    if user_id is not None:
        q = q.where(User.id != user_id)
    return s.scalar(q)


@router.post("/admin/users")
async def user_create(request: Request):
    return await _save_user(request, None)


@router.post("/admin/users/{user_id}")
async def user_update(request: Request, user_id: int):
    return await _save_user(request, user_id)


async def _save_user(request: Request, user_id: int | None):
    me = request.state.user
    data = await request.form()
    form = {
        "username": (data.get("username") or "").strip(),
        "display_name": (data.get("display_name") or "").strip()[:200],
        "is_admin": data.get("is_admin") == "on",
        "is_active": data.get("is_active") == "on",
        "role_ids": _ids(data.getlist("role_ids")),
    }
    password = data.get("password") or ""
    with SessionLocal() as s:
        target = _get(s, User, user_id, "Пользователь") if user_id else None
        try:
            if not re.match(security.USERNAME_RE, form["username"]):
                raise ValueError("Логин: 2–64 символа — латиница, цифры, точка, дефис, подчёркивание, @")
            if s.scalar(select(User.id).where(User.username == form["username"], User.id != (user_id or 0))):
                raise ValueError(f"Пользователь {form['username']} уже существует")
            if target is None or password:
                security.check_password_policy(password)
                if password != data.get("password2"):
                    raise ValueError("Пароли не совпадают")
            if target is not None and target.id == me.id and (not form["is_admin"] or not form["is_active"]):
                raise ValueError("Нельзя снять с себя права администратора или заблокировать себя")
            if target is not None and target.is_admin and target.is_active \
                    and not (form["is_admin"] and form["is_active"]) and not _other_active_admins(s, target.id):
                raise ValueError("Это последний активный администратор")
        except ValueError as e:
            return _user_form_page(request, target, form, 422, str(e))

        user = target or User()
        user.username, user.display_name = form["username"], form["display_name"]
        user.is_admin, user.is_active = form["is_admin"], form["is_active"]
        user.roles = list(s.scalars(select(Role).where(Role.id.in_(form["role_ids"]))))
        if password:
            user.password_hash = security.hash_password(password)
        s.add(user)
        s.flush()
        if target is not None and (password or not form["is_active"]):
            security.drop_user_sessions(s, user.id)
        s.commit()
    log.info("Пользователь %s сохранён (%s)", form["username"], me.username)
    return redirect("/admin/users?msg=saved")


@router.post("/admin/users/{user_id}/delete")
def user_delete(request: Request, user_id: int):
    me = request.state.user
    with SessionLocal() as s:
        target = _get(s, User, user_id, "Пользователь")
        if target.id == me.id:
            return redirect("/admin/users?msg=self")
        if target.is_admin and target.is_active and not _other_active_admins(s, target.id):
            return redirect("/admin/users?msg=last_admin")
        s.delete(target)
        s.commit()
    return redirect("/admin/users?msg=deleted")


# ================================================================ роли

@router.get("/admin/roles", response_class=HTMLResponse)
def roles_page(request: Request, msg: str | None = None):
    with SessionLocal() as s:
        roles = list(s.scalars(select(Role).order_by(Role.name)))
    return render(request, "admin/roles.html", roles=roles, msg=msg, section="roles")


def _role_form_page(request: Request, role: Role | None, form: dict, status_code: int = 200, error: str = ""):
    with SessionLocal() as s:
        clusters = all_clusters(s)
        users = list(s.scalars(select(User).order_by(User.username)))
    return render(request, "admin/role_form.html", status_code, role=role, form=form, clusters=clusters,
                  users=users, error=error, section="roles")


@router.get("/admin/roles/new", response_class=HTMLResponse)
def role_new(request: Request):
    return _role_form_page(request, None, {"name": "", "description": "", "key_ids": set(), "user_ids": set()})


@router.get("/admin/roles/{role_id}", response_class=HTMLResponse)
def role_edit(request: Request, role_id: int):
    with SessionLocal() as s:
        role = _get(s, Role, role_id, "Роль")
    return _role_form_page(request, role, {"name": role.name, "description": role.description,
                                           "key_ids": {k.id for k in role.keys},
                                           "user_ids": {u.id for u in role.users}})


@router.post("/admin/roles")
async def role_create(request: Request):
    return await _save_role(request, None)


@router.post("/admin/roles/{role_id}")
async def role_update(request: Request, role_id: int):
    return await _save_role(request, role_id)


async def _save_role(request: Request, role_id: int | None):
    data = await request.form()
    form = {
        "name": (data.get("name") or "").strip()[:100],
        "description": (data.get("description") or "").strip(),
        "key_ids": _ids(data.getlist("key_ids")),
        "user_ids": _ids(data.getlist("user_ids")),
    }
    with SessionLocal() as s:
        role = _get(s, Role, role_id, "Роль") if role_id else None
        error = ""
        if not form["name"]:
            error = "Укажите название роли"
        elif s.scalar(select(Role.id).where(Role.name == form["name"], Role.id != (role_id or 0))):
            error = f"Роль «{form['name']}» уже существует"
        if error:
            return _role_form_page(request, role, form, 422, error)
        role = role or Role()
        role.name, role.description = form["name"], form["description"]
        role.keys = list(s.scalars(select(ClusterKey).where(ClusterKey.id.in_(form["key_ids"]))))
        role.users = list(s.scalars(select(User).where(User.id.in_(form["user_ids"]))))
        s.add(role)
        s.commit()
    return redirect("/admin/roles?msg=saved")


@router.post("/admin/roles/{role_id}/delete")
def role_delete(role_id: int):
    with SessionLocal() as s:
        s.delete(_get(s, Role, role_id, "Роль"))
        s.commit()
    return redirect("/admin/roles?msg=deleted")


# ================================================================ кластеры

def _key_usage(s) -> dict[int, int]:
    return dict(s.execute(select(Task.key_id, func.count(Task.id)).group_by(Task.key_id)).all())


@router.get("/clusters")
def clusters_legacy():
    return redirect("/admin/clusters")


@router.get("/admin/clusters", response_class=HTMLResponse)
def clusters_page(request: Request, msg: str | None = None):
    with SessionLocal() as s:
        clusters = all_clusters(s)
        usage = _key_usage(s)
    tasks = {c.id: sum(usage.get(k.id, 0) for k in c.keys) for c in clusters}
    return render(request, "admin/clusters.html", clusters=clusters, tasks=tasks, msg=msg, section="clusters")


def _env_api_key() -> str | None:
    try:
        return normalize_api_key(settings.es_api_key)
    except ValueError:
        return None


def _cluster_form_page(request: Request, cluster: Cluster | None, form: dict, status_code: int = 200, **ctx):
    usage, roles_by_key = {}, {}
    if cluster:
        with SessionLocal() as s:
            usage = _key_usage(s)
            for role in s.scalars(select(Role)):
                for k in role.keys:
                    roles_by_key.setdefault(k.id, []).append(role.name)
    first = not es_pool.configured and cluster is None
    return render(request, "admin/cluster_form.html", status_code, cluster=cluster, form=form, first_run=first,
                  usage=usage, roles_by_key=roles_by_key, section="clusters", **ctx)


@router.get("/admin/clusters/new", response_class=HTMLResponse)
def cluster_new(request: Request):
    first = not es_pool.configured
    form = {"name": "Основной" if first else "", "url": settings.es_url if first else "",
            "skip_tls": not settings.es_verify_certs if first else False, "is_default": first,
            "key_name": "Основной ключ"}
    return _cluster_form_page(request, None, form, has_env_key=first and bool(_env_api_key()))


@router.get("/admin/clusters/{cluster_id}", response_class=HTMLResponse)
def cluster_edit(request: Request, cluster_id: int, msg: str | None = None):
    with SessionLocal() as s:
        c = _get(s, Cluster, cluster_id, "Кластер")
    return _cluster_form_page(request, c, {"name": c.name, "url": c.url, "skip_tls": not c.verify_tls,
                                           "is_default": c.is_default}, msg=msg)


@router.post("/admin/clusters")
async def cluster_create(request: Request):
    return await _save_cluster(request, None)


@router.post("/admin/clusters/{cluster_id}")
async def cluster_update(request: Request, cluster_id: int):
    return await _save_cluster(request, cluster_id)


async def _check(action: str, conn: Connection):
    """Проверка подключения: (info, ошибка)."""
    if action == "save_nocheck":
        return None, None
    try:
        return await probe(conn), None
    except ESRequestError as e:
        return None, str(e)


async def _save_cluster(request: Request, cluster_id: int | None):
    data = await request.form()
    action = data.get("action", "save")
    form = {
        "name": (data.get("name") or "").strip()[:100],
        "url": (data.get("url") or "").strip(),
        "skip_tls": data.get("skip_tls") == "on",
        "is_default": data.get("is_default") == "on",
        "key_name": (data.get("key_name") or "").strip()[:100] or "Основной ключ",
    }
    with SessionLocal() as s:
        cluster = _get(s, Cluster, cluster_id, "Кластер") if cluster_id else None
        first = not s.scalar(select(func.count(Cluster.id)))
        page = dict(has_env_key=first and bool(_env_api_key()))
        try:
            url = normalize_url(form["url"])
            name = form["name"] or urlsplit(url).hostname
            if s.scalar(select(Cluster.id).where(Cluster.name == name, Cluster.id != (cluster_id or 0))):
                raise ValueError(f"Кластер с названием «{name}» уже есть")
            if cluster is None:  # новый кластер создаётся вместе с первым ключом
                api_key = normalize_api_key(data.get("api_key")) or (_env_api_key() if first else None)
            else:  # для проверки берём существующий ключ кластера
                api_key = cluster.keys[0].api_key if cluster.keys else None
        except ValueError as e:
            return _cluster_form_page(request, cluster, form, 422, error=str(e), **page)

    conn = Connection(url=url, api_key=api_key, verify_tls=not form["skip_tls"])
    info, error = await _check(action, conn)
    if error:
        return _cluster_form_page(request, cluster, form, 422, error=error, allow_nocheck=action == "save", **page)
    if action == "test":
        return _cluster_form_page(request, cluster, form, info=info, **page)

    with SessionLocal() as s:
        c = _get(s, Cluster, cluster_id, "Кластер") if cluster_id else Cluster()
        c.name, c.url, c.verify_tls = name, url, conn.verify_tls
        if first or form["is_default"]:
            s.execute(update(Cluster).values(is_default=False))
            c.is_default = True
        if cluster_id is None:
            c.keys = [ClusterKey(name=form["key_name"], api_key=api_key)]
        s.add(c)
        s.flush()
        if first:  # задачи, созданные до появления кластеров
            s.execute(update(Task).where(Task.key_id.is_(None)).values(key_id=c.keys[0].id))
        s.commit()
        s.refresh(c)
        sync_cluster(c)
        saved_id = c.id
    log.info("Кластер «%s»: %s (проверка TLS: %s)", name, url, conn.verify_tls)
    if first:
        return redirect("/")
    return redirect(f"/admin/clusters/{saved_id}?msg=saved" if cluster_id is None else "/admin/clusters?msg=saved")


@router.post("/admin/clusters/{cluster_id}/default")
def cluster_set_default(cluster_id: int):
    with SessionLocal() as s:
        c = _get(s, Cluster, cluster_id, "Кластер")
        s.execute(update(Cluster).values(is_default=False))
        c.is_default = True
        s.commit()
    return redirect("/admin/clusters")


@router.post("/admin/clusters/{cluster_id}/delete")
async def cluster_delete(cluster_id: int):  # async: es_pool.remove() работает в event loop
    with SessionLocal() as s:
        c = _get(s, Cluster, cluster_id, "Кластер")
        key_ids = [k.id for k in c.keys]
        if key_ids and s.scalar(select(func.count(Task.id)).where(Task.key_id.in_(key_ids))):
            return redirect("/admin/clusters?msg=busy")
        was_default = c.is_default
        s.delete(c)
        s.commit()
        if was_default:
            other = s.scalar(select(Cluster).order_by(Cluster.id))
            if other:
                other.is_default = True
                s.commit()
    for kid in key_ids:
        es_pool.remove(kid)
    return redirect("/admin/clusters?msg=deleted")


# ================================================================ ключи доступа

def _key_form_page(request: Request, cluster: Cluster, key: ClusterKey | None, form: dict,
                   status_code: int = 200, **ctx):
    with SessionLocal() as s:
        roles = list(s.scalars(select(Role).order_by(Role.name)))
    return render(request, "admin/key_form.html", status_code, cluster=cluster, key=key, form=form, roles=roles,
                  section="clusters", **ctx)


@router.get("/admin/clusters/{cluster_id}/keys/new", response_class=HTMLResponse)
def key_new(request: Request, cluster_id: int):
    with SessionLocal() as s:
        cluster = _get(s, Cluster, cluster_id, "Кластер")
    return _key_form_page(request, cluster, None, {"name": "", "role_ids": set()})


@router.get("/admin/clusters/{cluster_id}/keys/{key_id}", response_class=HTMLResponse)
def key_edit(request: Request, cluster_id: int, key_id: int):
    with SessionLocal() as s:
        key = _get(s, ClusterKey, key_id, "Ключ")
        if key.cluster_id != cluster_id:
            raise HTTPException(404, "Ключ не найден")
        role_ids = {r.id for r in s.scalars(select(Role)) if key in r.keys}
    return _key_form_page(request, key.cluster, key, {"name": key.name, "role_ids": role_ids})


@router.post("/admin/clusters/{cluster_id}/keys")
async def key_create(request: Request, cluster_id: int):
    return await _save_key(request, cluster_id, None)


@router.post("/admin/clusters/{cluster_id}/keys/{key_id}")
async def key_update(request: Request, cluster_id: int, key_id: int):
    return await _save_key(request, cluster_id, key_id)


async def _save_key(request: Request, cluster_id: int, key_id: int | None):
    data = await request.form()
    action = data.get("action", "save")
    form = {"name": (data.get("name") or "").strip()[:100], "role_ids": _ids(data.getlist("role_ids"))}
    with SessionLocal() as s:
        cluster = _get(s, Cluster, cluster_id, "Кластер")
        key = _get(s, ClusterKey, key_id, "Ключ") if key_id else None
        if key is not None and key.cluster_id != cluster_id:
            raise HTTPException(404, "Ключ не найден")
        try:
            if not form["name"]:
                raise ValueError("Укажите название ключа")
            if s.scalar(select(ClusterKey.id).where(ClusterKey.cluster_id == cluster_id,
                                                    ClusterKey.name == form["name"],
                                                    ClusterKey.id != (key_id or 0))):
                raise ValueError(f"У кластера уже есть ключ «{form['name']}»")
            new_key = normalize_api_key(data.get("api_key"))
            if new_key or key is None or data.get("no_key") == "on":
                api_key = new_key
            else:
                api_key = key.api_key  # поле пустое — оставляем сохранённый ключ
        except ValueError as e:
            return _key_form_page(request, cluster, key, form, 422, error=str(e))

    conn = Connection(cluster.url, api_key, cluster.verify_tls)
    info, error = await _check(action, conn)
    if error:
        return _key_form_page(request, cluster, key, form, 422, error=error, allow_nocheck=action == "save")
    if action == "test":
        return _key_form_page(request, cluster, key, form, info=info)

    with SessionLocal() as s:
        k = _get(s, ClusterKey, key_id, "Ключ") if key_id else ClusterKey(cluster_id=cluster_id)
        k.name, k.api_key = form["name"], api_key
        s.add(k)
        s.flush()
        for role in s.scalars(select(Role)):
            if role.id in form["role_ids"] and k not in role.keys:
                role.keys.append(k)
            elif role.id not in form["role_ids"] and k in role.keys:
                role.keys.remove(k)
        s.commit()
        s.refresh(k)
        es_pool.configure(k.id, to_conn(k))
    return redirect(f"/admin/clusters/{cluster_id}?msg=key_saved")


@router.post("/admin/clusters/{cluster_id}/keys/{key_id}/delete")
async def key_delete(cluster_id: int, key_id: int):
    with SessionLocal() as s:
        key = _get(s, ClusterKey, key_id, "Ключ")
        if key.cluster_id != cluster_id:
            raise HTTPException(404, "Ключ не найден")
        if s.scalar(select(func.count(Task.id)).where(Task.key_id == key_id)):
            return redirect(f"/admin/clusters/{cluster_id}?msg=key_busy")
        s.delete(key)
        s.commit()
    es_pool.remove(key_id)
    return redirect(f"/admin/clusters/{cluster_id}?msg=key_deleted")
