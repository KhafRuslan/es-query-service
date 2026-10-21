import json
from datetime import datetime, timedelta

from app.config import settings
from app.db import SessionLocal
from app.models import Run, Task, User

from .conftest import ADMIN, ES_REQUESTS, SEARCH_RESPONSE, WEBHOOK_REQUESTS, form, last_id, wait_run


def admin_title() -> str:
    with SessionLocal() as s:
        return s.query(User).filter(User.username == ADMIN[0]).one().title


def test_index_and_health(client):
    assert client.get("/").status_code == 200
    assert client.get("/health").json()["status"] == "ok"
    status = client.get("/api/status").json()
    local = next(c for c in status["clusters"] if c["name"] == "local")
    assert {"ok": True, "cluster": "test", "version": "8.17.0"}.items() <= local.items()


def test_run_now_stores_result_temporarily(client):
    r = client.post("/tasks", data=form(), follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/runs/")
    run_id = last_id(r)
    run = wait_run(run_id)
    assert run.status == "success" and run.result_file and run.share_token is None
    assert ES_REQUESTS[-1].url.path == "/logs/_search"
    assert json.loads(ES_REQUESTS[-1].content) == {"query": {"match_all": {}}}

    page = client.get(f"/runs/{run_id}")
    assert "Найдено" in page.text
    dl = client.get(f"/runs/{run_id}/download")
    assert dl.json() == SEARCH_RESPONSE
    assert "attachment" in dl.headers["content-disposition"]

    # Публичная ссылка создаётся вручную и отзывается
    client.post(f"/runs/{run_id}/share")
    token = wait_run(run_id).share_token
    assert client.get(f"/s/{token}").json() == SEARCH_RESPONSE
    client.post(f"/runs/{run_id}/unshare")
    assert client.get(f"/s/{token}").status_code == 404


def test_run_and_download(client):
    r = client.post("/tasks", data=form(name="Отчёт", action="download"))
    assert r.status_code == 200
    assert r.json() == SEARCH_RESPONSE
    assert "filename*=UTF-8''%D0%9E%D1%82%D1%87%D1%91%D1%82" in r.headers["content-disposition"]


def test_store_share_and_webhook(client):
    r = client.post("/tasks", data=form(
        store_enabled="on", ttl_value="2", ttl_unit="h", share_enabled="on",
        webhook_enabled="on", webhook_url="https://hook.example/x",
        webhook_headers="Authorization: Bearer abc"), follow_redirects=False)
    run = wait_run(last_id(r))
    assert run.share_token
    assert timedelta(minutes=119) < run.expires_at - run.started_at < timedelta(minutes=121)
    assert run.webhook_status.startswith("OK")
    hook = WEBHOOK_REQUESTS[-1]
    assert str(hook.url) == "https://hook.example/x"
    assert hook.headers["authorization"] == "Bearer abc"
    assert json.loads(hook.content) == SEARCH_RESPONSE

    shared = client.get(f"/s/{run.share_token}?download=1")
    assert shared.status_code == 200 and "attachment" in shared.headers["content-disposition"]

    # По истечении срока ссылка перестаёт работать
    with SessionLocal() as s:
        s.get(Run, run.id).expires_at = datetime(2000, 1, 1)
        s.commit()
    assert client.get(f"/s/{run.share_token}").status_code == 404


def test_es_error_is_recorded(client):
    r = client.post("/tasks", data=form(path="/missing/_field_caps"), follow_redirects=False)
    run = wait_run(last_id(r))
    assert run.status == "error" and run.es_status == 404 and "index_not_found" in run.error


def test_validation(client):
    r = client.post("/tasks", data=form(body="{bad json"))
    assert r.status_code == 422 and "Некорректный JSON" in r.text
    r = client.post("/tasks", data=form(path="/logs/_delete_by_query"))
    assert r.status_code == 422 and "только-чтение" in r.text
    r = client.post("/tasks", data=form(mode="cron", cron="* * *", store_enabled="on"))
    assert r.status_code == 422 and "5 полей" in r.text
    r = client.post("/tasks", data=form(mode="cron", cron="0 9 * * *"))
    assert r.status_code == 422 and "куда девать результат" in r.text
    r = client.post("/tasks", data=form(mode="once", run_at="2001-01-01T10:00", store_enabled="on"))
    assert r.status_code == 422 and "в будущем" in r.text


def test_path_cannot_escape_es_host(client):
    r = client.post("/tasks", data=form(path="//evil.example/_search", action="download"))
    assert r.status_code == 200
    assert ES_REQUESTS[-1].url.host == "localhost" and ES_REQUESTS[-1].url.path == "/evil.example/_search"


def test_scheduled_tasks(client):
    from app import scheduler

    r = client.post("/tasks", data=form(mode="cron", cron="*/5 * * * *", store_enabled="on", action="save"),
                    follow_redirects=False)
    cron_id = last_id(r)
    nxt = scheduler.next_run_time(cron_id)
    assert nxt is not None and nxt.minute % 5 == 0

    run_at = datetime.now(settings.tz) + timedelta(minutes=5)
    r = client.post("/tasks", data=form(mode="once", run_at=run_at.strftime("%Y-%m-%dT%H:%M"),
                                        store_enabled="on", action="save"), follow_redirects=False)
    once_id = last_id(r)
    assert scheduler.next_run_time(once_id) is not None

    # Пауза снимает задание из планировщика, повторное включение возвращает
    client.post(f"/tasks/{cron_id}/toggle")
    assert scheduler.next_run_time(cron_id) is None
    client.post(f"/tasks/{cron_id}/toggle")
    assert scheduler.next_run_time(cron_id) is not None

    client.post(f"/tasks/{once_id}/delete")
    assert scheduler.next_run_time(once_id) is None
    assert client.get(f"/tasks/{once_id}").status_code == 404


def test_once_job_executes_and_disables(client):
    from app import scheduler

    r = client.post("/tasks", data=form(mode="once", store_enabled="on", action="save",
                                        run_at=(datetime.now(settings.tz) + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M")),
                    follow_redirects=False)
    task_id = last_id(r)
    # Вызываем задание так, как это сделал бы планировщик
    client.portal.call(scheduler._run_job, task_id, "once")
    with SessionLocal() as s:
        task = s.get(Task, task_id)
        assert task.enabled is False
        runs = task.runs
        assert len(runs) == 1 and runs[0].status == "success" and runs[0].trigger == "once"
        assert runs[0].user_name == admin_title() and runs[0].cluster_name == "local" and runs[0].key_name == "local-key"


def test_rerun_existing_task(client):
    r = client.post("/tasks", data=form(action="save"), follow_redirects=False)
    task_id = last_id(r)
    r = client.post(f"/tasks/{task_id}/run", follow_redirects=False)
    assert r.status_code == 303
    run = wait_run(last_id(r))
    assert run.status == "success" and run.task_id == task_id and run.user_name == admin_title()
    assert admin_title() in client.get(f"/tasks/{task_id}").text
    assert client.get(f"/tasks/{task_id}").status_code == 200
    assert client.post(f"/tasks/{task_id}/download").json() == SEARCH_RESPONSE


def test_cross_origin_post_rejected(client):
    assert client.post("/tasks", data=form(), headers={"Origin": "http://evil.example"}).status_code == 403


def test_main_page_layout(client):
    task_id = last_id(client.post("/tasks", data=form(name="Главная-строка", action="save"), follow_redirects=False))
    wait_run(last_id(client.post(f"/tasks/{task_id}/run", follow_redirects=False)))
    page = client.get("/").text
    assert page.lstrip().startswith("<!doctype html>")
    # Боковое меню, шапка, сводка, поиск и строка задачи
    for fragment in ('class="sidebar"', "Новый запрос", "Управление", "Запуски", "Сохранённые результаты",
                     'id="es-status"', 'id="theme-toggle"', 'href="/account"', 'action="/logout"',
                     "Всего задач", "Ошибок за 24 часа", "Ближайший запуск", 'id="task-search"',
                     'class="task-row"', "Главная-строка", "успешно", "Последний запуск"):
        assert fragment in page, fragment
    row = page[page.index(f'href="/tasks/{task_id}"'):]
    assert 'data-search="главная-строка' in row
    client.post(f"/tasks/{task_id}/delete")
