from app import hooks
from app.config import settings
from app.db import SessionLocal
from app.models import Task

from .conftest import ADMIN, ES_REQUESTS, SEARCH_RESPONSE, WEBHOOK_REQUESTS, form, last_id, login, wait_run


def hook_task(c, **kw) -> tuple[int, str]:
    data = {"name": "по вебхуку", "action": "save", "hook_enabled": "on"}
    data.update(kw)
    task_id = last_id(c.post("/tasks", data=form(**data), follow_redirects=False))
    with SessionLocal() as s:
        return task_id, s.get(Task, task_id).hook_token


def test_networks_parsing():
    assert [str(n) for n in hooks.parse_networks("10.0.0.0/8, 192.168.1.15\n::1")] == \
        ["10.0.0.0/8", "192.168.1.15/32", "::1/128"]
    assert hooks.ip_allowed("10.1.2.3", "10.0.0.0/8") and not hooks.ip_allowed("11.0.0.1", "10.0.0.0/8")
    assert hooks.ip_allowed("1.2.3.4", None) and not hooks.ip_allowed("not-an-ip", "10.0.0.0/8")


def test_hook_async_status_and_result(client):
    c = client
    task_id, token = hook_task(c)
    assert token and len(token) >= 40
    page = c.get(f"/tasks/{task_id}").text
    assert f"/hooks/{token}" in page and "Внешний вебхук" in page

    c.cookies.clear()  # внешняя система — без сессии
    r = c.post(f"/hooks/{token}")
    assert r.status_code in (200, 202)
    info = r.json()
    run = wait_run(info["run_id"])
    assert run.trigger == "webhook" and run.status == "success" and run.client_ip == "testclient"
    assert run.user_name and run.task_id == task_id  # от имени автора задачи
    status = c.get(f"/hooks/{token}/runs/{run.id}").json()
    assert status["status"] == "success" and status["result_url"].endswith(f"/hooks/{token}/runs/{run.id}/result")
    assert c.get(f"/hooks/{token}/runs/{run.id}/result").json() == SEARCH_RESPONSE

    # Чужой токен не даёт доступа к запуску; GET не запускает задачу
    assert c.get(f"/hooks/wrong-token/runs/{run.id}").status_code == 404
    assert c.post("/hooks/wrong-token").status_code == 404
    before = len(ES_REQUESTS)
    assert c.get(f"/hooks/{token}").status_code == 405
    assert len(ES_REQUESTS) == before
    # Чужой Origin не мешает (вебхук вызывается не из браузера)
    assert c.post(f"/hooks/{token}", headers={"Origin": "http://other.example"}).status_code in (200, 202)

    login(c, *ADMIN)
    assert "вебхук" in c.get(f"/tasks/{task_id}").text
    assert "testclient" in c.get(f"/runs/{run.id}").text


def test_hook_wait_returns_es_response(client):
    c = client
    task_id, token = hook_task(c, webhook_enabled="on", webhook_url="https://hook.example/out")
    hooks_before = len(WEBHOOK_REQUESTS)
    r = c.post(f"/hooks/{token}?wait=1")
    assert r.status_code == 200 and r.json() == SEARCH_RESPONSE
    run_id = int(r.headers["x-es-run-id"])
    assert wait_run(run_id).webhook_status.startswith("OK")  # доставка по настройкам задачи
    assert len(WEBHOOK_REQUESTS) == hooks_before + 1

    # Ошибка Elasticsearch — 502 с текстом ошибки
    _, bad = hook_task(c, name="ошибка", path="/missing/_field_caps")
    r = c.post(f"/hooks/{bad}?wait=1")
    assert r.status_code == 502 and r.json()["status"] == "error" and "index_not_found" in r.json()["error"]


def test_hook_ip_allowlist_and_rate_limit(client, monkeypatch):
    c = client
    r = c.post("/tasks", data=form(name="ip", action="save", hook_enabled="on", hook_allowed_ips="10.0.0.0/8, bad"))
    assert r.status_code == 422 and "Некорректный IP" in r.text

    task_id, token = hook_task(c, name="только 10/8", hook_allowed_ips="10.0.0.0/8")
    r = c.post(f"/hooks/{token}")
    assert r.status_code == 403 and "testclient" in r.json()["error"]

    task_id, token = hook_task(c, name="лимит")
    monkeypatch.setattr(settings, "hook_rate_limit_per_minute", 2)
    hooks._calls.clear()
    codes = [c.post(f"/hooks/{token}").status_code for _ in range(3)]
    assert codes[:2] != [429, 429] and codes[2] == 429
    hooks._calls.clear()


def test_hook_rotate_disable_and_edit(client):
    c = client
    task_id, token = hook_task(c, name="ротация")
    # Редактирование сохраняет адрес
    c.post(f"/tasks/{task_id}", data=form(name="ротация 2", action="save", hook_enabled="on"))
    with SessionLocal() as s:
        assert s.get(Task, task_id).hook_token == token
    # Новый адрес — старый перестаёт работать
    c.post(f"/tasks/{task_id}/hook/rotate")
    with SessionLocal() as s:
        new = s.get(Task, task_id).hook_token
    assert new and new != token
    assert c.post(f"/hooks/{token}").status_code == 404
    assert c.post(f"/hooks/{new}").status_code in (200, 202)
    # Отключение
    c.post(f"/tasks/{task_id}/hook/disable")
    assert c.post(f"/hooks/{new}").status_code == 404
    assert "Выключен" in c.get(f"/tasks/{task_id}").text
    # Снятие галочки в форме тоже отключает
    c.post(f"/tasks/{task_id}/hook/rotate")
    c.post(f"/tasks/{task_id}", data=form(name="ротация 3", action="save"))
    with SessionLocal() as s:
        assert s.get(Task, task_id).hook_token is None


def test_hook_runs_as_owner_and_respects_access(client):
    c = client
    c.post("/admin/users", data={"username": "hookowner", "password": "hookowner-123", "password2": "hookowner-123",
                                 "is_active": "on", "is_admin": "on"})
    login(c, "hookowner", "hookowner-123")
    task_id, token = hook_task(c, name="владелец")
    login(c, *ADMIN)
    with SessionLocal() as s:
        owner_id = s.get(Task, task_id).owner_id
    # Автор заблокирован — запуск записывается с ошибкой доступа
    c.post(f"/admin/users/{owner_id}", data={"username": "hookowner", "is_admin": "on"})
    c.cookies.clear()
    info = c.post(f"/hooks/{token}?wait=1").json()
    run = wait_run(info["run_id"])
    assert run.status == "error" and "заблокирован" in run.error and run.trigger == "webhook"
    login(c, *ADMIN)


def test_hook_rate_limit_per_task_capped_by_env(client, monkeypatch):
    c = client
    monkeypatch.setattr(settings, "hook_rate_limit_per_minute", 5)
    # Больше максимума и не число — ошибка
    r = c.post("/tasks", data=form(name="много", action="save", hook_enabled="on", hook_rate_limit="6"))
    assert r.status_code == 422 and "от 1 до 5" in r.text
    r = c.post("/tasks", data=form(name="текст", action="save", hook_enabled="on", hook_rate_limit="abc"))
    assert r.status_code == 422 and "целым числом" in r.text
    assert 'max="5"' in c.get("/tasks/new").text

    # Свой лимит задачи
    task_id, token = hook_task(c, name="свой лимит", hook_rate_limit="2")
    with SessionLocal() as s:
        assert s.get(Task, task_id).hook_rate_limit == 2
    assert "2 вызовов в минуту" in c.get(f"/tasks/{task_id}").text
    hooks._calls.clear()
    codes = [c.post(f"/hooks/{token}").status_code for _ in range(3)]
    assert codes[2] == 429 and 429 not in codes[:2]
    assert "не больше 2" in c.post(f"/hooks/{token}").json()["error"]

    # Пусто — действует максимум
    task_id, token = hook_task(c, name="по максимуму")
    with SessionLocal() as s:
        assert s.get(Task, task_id).hook_rate_limit is None
    assert "(максимум)" in c.get(f"/tasks/{task_id}").text
    hooks._calls.clear()
    codes = [c.post(f"/hooks/{token}").status_code for _ in range(6)]
    assert codes[5] == 429 and 429 not in codes[:5]

    # Максимум снизили после сохранения — действует меньшее значение
    task_id, token = hook_task(c, name="снижение", hook_rate_limit="4")
    monkeypatch.setattr(settings, "hook_rate_limit_per_minute", 1)
    assert "в задаче указано 4, но максимум сейчас 1" in c.get(f"/tasks/{task_id}").text
    hooks._calls.clear()
    assert [c.post(f"/hooks/{token}").status_code for _ in range(2)][1] == 429
    hooks._calls.clear()
