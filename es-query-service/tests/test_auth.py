from sqlalchemy import func, select

from app import auth_routes, scheduler, security
from app.db import SessionLocal
from app.es import Connection, es_pool
from app.models import Cluster, ClusterKey, Role, Run, Task, User

from .conftest import (ADMIN, ES_REQUESTS, SEARCH_RESPONSE, ensure_admin, ensure_local_cluster, form, last_id,
                       local_key_id, login, reset_all, wait_run)


def cluster_row(name: str) -> Cluster | None:
    with SessionLocal() as s:
        return s.scalar(select(Cluster).where(Cluster.name == name))


def key_row(cluster: str, name: str) -> ClusterKey | None:
    with SessionLocal() as s:
        return s.scalar(select(ClusterKey).join(Cluster).where(Cluster.name == cluster, ClusterKey.name == name))


def user_row(username: str) -> User | None:
    with SessionLocal() as s:
        return s.scalar(select(User).where(User.username == username))


def create_user(c, username: str, password: str = "user-pass-123", **extra) -> int:
    data = {"username": username, "display_name": extra.pop("display_name", ""), "password": password,
            "password2": password, "is_active": "on", **extra}
    r = c.post("/admin/users", data=data, follow_redirects=False)
    assert r.status_code == 303, r.text
    return user_row(username).id


# ================================================================ первый запуск

def test_first_run(app_client):
    c = app_client
    reset_all(c)

    # Пока нет пользователей — все страницы ведут на создание администратора
    for path in ("/", "/login", "/admin/users", "/api/status"):
        r = c.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/setup/admin", path
    assert c.get("/health").status_code == 200

    r = c.post("/setup/admin", data={"username": "admin", "password": "short", "password2": "short"})
    assert r.status_code == 422 and "не короче 8" in r.text
    r = c.post("/setup/admin", data={"username": "admin", "password": ADMIN[1], "password2": "other-pass-1"})
    assert r.status_code == 422 and "не совпадают" in r.text
    r = c.post("/setup/admin", data={"username": "admin", "display_name": "Главный",
                                     "password": ADMIN[1], "password2": ADMIN[1]}, follow_redirects=False)
    assert r.status_code == 303 and security.SESSION_COOKIE in r.headers["set-cookie"]
    assert "HttpOnly" in r.headers["set-cookie"] and "SameSite=lax" in r.headers["set-cookie"]
    admin = user_row("admin")
    assert admin.is_admin and admin.password_hash.startswith("scrypt$") and ADMIN[1] not in admin.password_hash

    # Повторно создать администратора нельзя
    assert c.get("/setup/admin", follow_redirects=False).headers["location"] == "/login"

    # Администратор вошёл; кластеров нет — открывается форма подключения
    r = c.get("/", follow_redirects=False)
    assert r.headers["location"] == "/admin/clusters/new"
    assert "Подключение к Elasticsearch" in c.get("/admin/clusters/new").text

    r = c.post("/admin/clusters", data={"url": "es.local:9200", "action": "save"})
    assert r.status_code == 422 and "http://" in r.text
    r = c.post("/admin/clusters", data={"url": "https://es.local:9200", "api_key": "bad:key", "action": "save"})
    assert r.status_code == 422 and "API-ключ" in r.text and "save_nocheck" in r.text
    r = c.post("/admin/clusters", data={"url": "https://es.local:9200", "api_key": "c2VjcmV0", "action": "test"})
    assert "Подключение успешно" in r.text and not es_pool.configured

    r = c.post("/admin/clusters", data={"name": "Основной", "url": "https://es.local:9200/", "key_name": "reader",
                                        "api_key": "myid:mykey", "skip_tls": "on", "action": "save"},
               follow_redirects=False)
    assert r.headers["location"] == "/"
    main = cluster_row("Основной")
    assert (main.url, main.verify_tls, main.is_default) == ("https://es.local:9200", False, True)
    key = key_row("Основной", "reader")
    assert key.api_key == "bXlpZDpteWtleQ=="
    assert es_pool.connection(key.id) == Connection("https://es.local:9200", "bXlpZDpteWtleQ==", False)
    assert c.get("/", follow_redirects=False).status_code == 200


# ================================================================ вход и сессии

def test_login_logout_and_throttling(client):
    c = client
    c.post("/logout")
    r = c.get("/runs?stored=1", follow_redirects=False)
    assert r.headers["location"] == "/login?next=/runs%3Fstored%3D1"
    assert c.get("/api/status").status_code == 401
    assert c.post("/tasks", data=form()).status_code == 401

    r = c.post("/login", data={"username": "admin", "password": "wrong-password"})
    assert r.status_code == 401 and "Неверный логин или пароль" in r.text
    # Перенаправление после входа — только внутри сервиса
    r = c.post("/login", data={"username": ADMIN[0], "password": ADMIN[1], "next": "//evil.example/"},
               follow_redirects=False)
    assert r.headers["location"] == "/"

    for _ in range(5):
        c.post("/login", data={"username": "victim", "password": "wrong-password"})
    r = c.post("/login", data={"username": "victim", "password": "wrong-password"})
    assert r.status_code == 429
    security._failures.clear()


def test_account_password_change(client):
    c = client
    create_user(c, "olga", "olga-pass-123")
    login(c, "olga", "olga-pass-123")
    other = c.cookies.get(security.SESSION_COOKIE)
    r = c.post("/account/password", data={"current_password": "nope", "new_password": "olga-new-123",
                                          "new_password2": "olga-new-123"})
    assert r.status_code == 422 and "неверно" in r.text
    r = c.post("/account/password", data={"current_password": "olga-pass-123", "new_password": "olga-new-123",
                                          "new_password2": "olga-new-123"}, follow_redirects=False)
    assert r.headers["location"] == "/account?msg=password"
    assert security.user_by_session(other) is None  # старые сессии завершены
    login(c, "olga", "olga-new-123")


# ================================================================ пользователи

def test_user_management_rules(client):
    c = client
    admin = user_row("admin")
    r = c.post("/admin/users", data={"username": "admin", "password": "x-pass-1234", "password2": "x-pass-1234"})
    assert r.status_code == 422 and "уже существует" in r.text
    r = c.post("/admin/users", data={"username": "bad name", "password": "x-pass-1234", "password2": "x-pass-1234"})
    assert r.status_code == 422 and "Логин" in r.text

    # Нельзя лишить себя прав и удалить себя
    r = c.post(f"/admin/users/{admin.id}", data={"username": "admin", "is_active": "on"})
    assert r.status_code == 422 and "Нельзя снять с себя" in r.text
    assert c.post(f"/admin/users/{admin.id}/delete", follow_redirects=False).headers["location"].endswith("msg=self")

    # Блокировка завершает сессии пользователя
    uid = create_user(c, "blocked", "blocked-123")
    login(c, "blocked", "blocked-123")
    assert c.get("/", follow_redirects=False).status_code == 200
    login(c, *ADMIN)
    c.post(f"/admin/users/{uid}", data={"username": "blocked"})  # is_active не отмечен
    login(c, *ADMIN)
    r = c.post("/login", data={"username": "blocked", "password": "blocked-123"})
    assert r.status_code == 401
    security._failures.clear()


# ================================================================ кластеры, ключи, роли, доступ

def test_clusters_keys_roles_and_access(client):
    c = client
    # Второй кластер с ключом и ещё один ключ
    r = c.post("/admin/clusters", data={"name": "dc2", "url": "https://dc2.local:9200", "key_name": "reader-all",
                                        "api_key": "c2VjcmV0", "action": "save"}, follow_redirects=False)
    dc2 = cluster_row("dc2")
    assert r.headers["location"] == f"/admin/clusters/{dc2.id}?msg=saved" and not dc2.is_default
    r = c.post(f"/admin/clusters/{dc2.id}/keys", data={"name": "reader-logs", "api_key": "logs:key",
                                                       "action": "save"}, follow_redirects=False)
    assert r.status_code == 303
    r = c.post(f"/admin/clusters/{dc2.id}/keys", data={"name": "reader-logs", "action": "save"})
    assert r.status_code == 422 and "уже есть ключ" in r.text
    r = c.post(f"/admin/clusters/{dc2.id}/keys", data={"name": "broken", "api_key": "bad:key", "action": "save"})
    assert r.status_code == 422 and "API-ключ" in r.text
    all_key, logs_key = key_row("dc2", "reader-all"), key_row("dc2", "reader-logs")
    assert logs_key.api_key == "bG9nczprZXk="
    page = c.get(f"/admin/clusters/{dc2.id}").text
    assert "reader-logs" in page and "bG9nczprZXk" not in page

    # Роль «logs» даёт только ключ reader-logs
    r = c.post("/admin/roles", data={"name": "logs", "description": "Логи", "key_ids": [str(logs_key.id)]},
               follow_redirects=False)
    assert r.status_code == 303
    with SessionLocal() as s:
        role_id = s.scalar(select(Role.id).where(Role.name == "logs"))
    ivan = create_user(c, "ivan", "ivan-pass-123", display_name="Иван Петров", role_ids=[str(role_id)])
    create_user(c, "petr", "petr-pass-123")

    # Задачи администратора на разных ключах
    r = c.post("/tasks", data=form(key_id=str(all_key.id), name="секретная", action="save"), follow_redirects=False)
    secret_task = last_id(r)
    run_secret = last_id(c.post(f"/tasks/{secret_task}/run", follow_redirects=False))
    wait_run(run_secret)
    r = c.post("/tasks", data=form(key_id=str(logs_key.id), name="логи", action="save"), follow_redirects=False)
    logs_task = last_id(r)
    assert c.post(f"/tasks/{logs_task}/download").json() == SEARCH_RESPONSE
    assert ES_REQUESTS[-1].url.host == "dc2.local" and ES_REQUESTS[-1].headers["authorization"] == "ApiKey bG9nczprZXk="

    # --- Иван видит только задачи на своих ключах
    login(c, "ivan", "ivan-pass-123")
    index = c.get("/").text
    assert "логи" in index and "секретная" not in index
    assert c.get(f"/tasks/{secret_task}").status_code == 404
    assert c.get(f"/runs/{run_secret}").status_code == 404
    assert c.post(f"/tasks/{secret_task}/run").status_code == 404
    assert f"/runs/{run_secret}" not in c.get("/runs").text
    assert c.get("/admin/users").status_code == 403
    assert c.get("/admin/clusters").status_code == 403

    new_form = c.get("/tasks/new").text
    assert f'value="{logs_key.id}"' in new_form and f'value="{all_key.id}"' not in new_form
    assert f'value="{local_key_id()}"' not in new_form
    status = c.get("/api/status").json()
    assert [k["id"] for k in status["keys"]] == [logs_key.id] and status["restricted"] is True

    # Нельзя создать задачу с чужим ключом
    r = c.post("/tasks", data=form(key_id=str(all_key.id)))
    assert r.status_code == 422 and "Выберите кластер и ключ" in r.text

    # Своя задача и запуск — с именем пользователя в истории
    r = c.post("/tasks", data=form(key_id=str(logs_key.id), name="задача Ивана", mode="cron", cron="0 * * * *",
                                   store_enabled="on", action="save"), follow_redirects=False)
    ivan_task = last_id(r)
    run = wait_run(last_id(c.post(f"/tasks/{ivan_task}/run", follow_redirects=False)))
    assert run.status == "success" and run.user_name == "Иван Петров"
    assert (run.cluster_name, run.key_name) == ("dc2", "reader-logs")
    assert "Иван Петров" in c.get(f"/tasks/{ivan_task}").text
    # Задачи администратора на ключе роли тоже доступны (роль работает как команда)
    run = wait_run(last_id(c.post(f"/tasks/{logs_task}/run", follow_redirects=False)))
    assert run.user_name == "Иван Петров"

    # --- Петр без ролей не видит ничего
    login(c, "petr", "petr-pass-123")
    assert "Нет доступных кластеров" in c.get("/").text
    assert "Нет доступных кластеров" in c.get("/tasks/new").text
    assert c.get(f"/tasks/{logs_task}").status_code == 404
    assert c.get("/api/status").json()["clusters"] == []

    # --- Отзыв доступа: запуски по расписанию от имени Ивана больше не выполняются
    login(c, *ADMIN)
    c.post(f"/admin/roles/{role_id}", data={"name": "logs", "key_ids": [], "user_ids": [str(ivan)]})
    c.portal.call(scheduler._run_job, ivan_task, "cron")
    with SessionLocal() as s:
        last = s.scalar(select(Run).where(Run.task_id == ivan_task).order_by(Run.id.desc()))
        assert last.status == "error" and "нет доступа к ключу" in last.error and last.user_name == "Иван Петров"

    # Ключ и кластер, используемые в задачах, удалить нельзя
    r = c.post(f"/admin/clusters/{dc2.id}/keys/{logs_key.id}/delete", follow_redirects=False)
    assert r.headers["location"].endswith("msg=key_busy")
    r = c.post(f"/admin/clusters/{dc2.id}/delete", follow_redirects=False)
    assert r.headers["location"].endswith("msg=busy")

    # Удаление пользователя: задачи остаются без владельца, имя в истории сохраняется
    c.post(f"/admin/users/{ivan}/delete")
    with SessionLocal() as s:
        assert s.get(Task, ivan_task).owner_id is None
        assert s.scalar(select(func.count(Run.id)).where(Run.user_name == "Иван Петров")) >= 2

    # После удаления задач — удаляются ключ и кластер
    for tid in (secret_task, logs_task, ivan_task):
        c.post(f"/tasks/{tid}/delete")
    assert c.post(f"/admin/clusters/{dc2.id}/keys/{logs_key.id}/delete",
                  follow_redirects=False).headers["location"].endswith("msg=key_deleted")
    assert es_pool.connection(logs_key.id) is None
    assert c.post(f"/admin/clusters/{dc2.id}/delete", follow_redirects=False).headers["location"].endswith("deleted")
    assert cluster_row("dc2") is None and es_pool.connection(all_key.id) is None
    with SessionLocal() as s:
        assert s.get(Role, role_id).keys == []


def test_default_cluster_preselected(client):
    c = client
    c.post("/admin/clusters", data={"name": "dc3", "url": "https://dc3.local:9200", "key_name": "k3",
                                    "is_default": "on", "action": "save"})
    k3 = key_row("dc3", "k3")
    assert cluster_row("dc3").is_default and not cluster_row("local").is_default
    assert f'<option value="{k3.id}" selected>' in c.get("/tasks/new").text
    ensure_local_cluster(c)  # вернуть "local" по умолчанию
    c.post(f"/admin/clusters/{cluster_row('dc3').id}/delete")
    assert cluster_row("dc3") is None


def test_users_exist_cache_matches_db(client):
    ensure_admin(client)
    assert auth_routes.users_exist()


def test_all_pages_render(client):
    c = client
    with SessionLocal() as s:
        cid = s.scalar(select(Cluster.id).where(Cluster.name == "local"))
        kid = local_key_id()
    c.post("/admin/roles", data={"name": "smoke", "key_ids": [str(kid)]})
    with SessionLocal() as s:
        rid = s.scalar(select(Role.id).where(Role.name == "smoke"))
    uid = create_user(c, "smoke", "smoke-pass-123", role_ids=[str(rid)])
    task_id = last_id(c.post("/tasks", data=form(action="save"), follow_redirects=False))
    run_id = wait_run(last_id(c.post(f"/tasks/{task_id}/run", follow_redirects=False))).id

    common = ["/", "/runs", "/runs?stored=1", "/tasks/new", f"/tasks/{task_id}", f"/tasks/{task_id}/edit",
              f"/tasks/new?clone={task_id}", f"/runs/{run_id}", "/account"]
    admin_pages = ["/admin/users", "/admin/users/new", f"/admin/users/{uid}", "/admin/roles", "/admin/roles/new",
                   f"/admin/roles/{rid}", "/admin/clusters", "/admin/clusters/new", f"/admin/clusters/{cid}",
                   f"/admin/clusters/{cid}/keys/new", f"/admin/clusters/{cid}/keys/{kid}"]
    for path in common + admin_pages:
        r = c.get(path)
        assert r.status_code == 200, (path, r.status_code)
        assert 'href="/admin/users"' in r.text, path  # пункт «Управление» в боковом меню

    login(c, "smoke", "smoke-pass-123")
    for path in common:
        r = c.get(path)
        assert r.status_code == 200, (path, r.status_code)
        assert 'href="/admin/users"' not in r.text, path
    for path in admin_pages:
        assert c.get(path).status_code == 403, path
    login(c, *ADMIN)
    c.post(f"/tasks/{task_id}/delete")
