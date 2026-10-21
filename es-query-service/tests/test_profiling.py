import json
import time

from sqlalchemy import select

from app import profiler
from app.db import SessionLocal
from app.models import QueryProfile, Run, Task
from app.profiler import analyze, fingerprint, query_kind, supports_profile

from .conftest import ADMIN, PROFILE_REQUESTS, form, last_id, login, wait_run


def wait_profile(task_id: int, timeout: float = 5) -> QueryProfile:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with SessionLocal() as s:
            task = s.get(Task, task_id)
            p = s.get(QueryProfile, profiler.task_fingerprint(task))
            if p is not None and p.status != "running":
                return p
        time.sleep(0.05)
    raise AssertionError("profile not finished")


def search_form(**kw):
    """Поисковая задача; тело уникально для названия, чтобы у тестов были разные отпечатки запросов."""
    name = kw.get("name", "test")
    data = {"path": "/logs/_search", "action": "save",
            "body": json.dumps({"query": {"term": {"level": name}}, "size": 5}, ensure_ascii=False)}
    data.update(kw)
    return form(**data)


# ================================================================ типы и отпечаток

def test_query_kinds():
    assert query_kind("/logs-*/_search") == "search"
    assert query_kind("/logs/_search?size=0") == "search"
    assert query_kind("/_msearch") == "search"
    assert query_kind("/idx/_search/template") == "search"
    assert query_kind("/idx/_count") == "count"
    assert query_kind("/_sql?format=json") == "sql"
    assert query_kind("/_query") == "sql"
    assert query_kind("/_cat/indices?format=json") == "other"
    assert query_kind("/idx/_mapping") == "other"
    assert supports_profile("/logs/_search?size=0") and supports_profile("/_msearch")
    assert not supports_profile("/idx/_search/template") and not supports_profile("/idx/_count")


def test_fingerprint_ignores_formatting():
    a = fingerprint(1, "POST", "/logs/_search", '{"query": {"match_all": {}}, "size": 5}')
    b = fingerprint(1, "POST", "/logs/_search", '{\n  "size": 5,\n  "query": {"match_all": {}}\n}')
    assert a == b
    assert a != fingerprint(1, "POST", "/logs/_search", '{"query": {"match_all": {}}, "size": 6}')
    assert a != fingerprint(2, "POST", "/logs/_search", '{"query": {"match_all": {}}, "size": 5}')
    assert a != fingerprint(1, "POST", "/other/_search", '{"query": {"match_all": {}}, "size": 5}')


# ================================================================ анализ профиля

def _profile(shard_ns: list[int], leaf="TermQuery", aggs_ns=0):
    return {"shards": [{
        "id": f"[n][i][{i}]",
        "searches": [{"query": [{"type": "BooleanQuery", "time_in_nanos": ns,
                                 "children": [{"type": leaf, "time_in_nanos": ns // 2}]}],
                      "rewrite_time": 0, "collector": []}],
        "aggregations": [{"type": "StringTermsAggregator", "time_in_nanos": aggs_ns}] if aggs_ns else [],
        "fetch": {"time_in_nanos": 1_000_000},
    } for i, ns in enumerate(shard_ns)]}


def test_analyze_light_query():
    resp = {"took": 15, "_shards": {"total": 2, "failed": 0}, "hits": {"total": {"value": 10}},
            "profile": _profile([2_000_000, 3_000_000])}
    m = analyze(resp, "/logs/_search", '{"query": {"bool": {"filter": [{"term": {"a": 1}}]}}}')
    assert m["complexity_level"] == "низкая" and m["speed_level"] == "быстрый"
    assert m["shards_profiled"] == 2 and m["query_nodes"] == 2 and m["query_depth"] == 2
    assert m["cluster_ms"] == 7.0 and m["slowest_shard"]["ms"] == 4.0
    assert m["recommendations"] == []


def test_analyze_heavy_query():
    body = {"query": {"bool": {"must": [{"wildcard": {"msg": {"value": "*err*"}}}, {"range": {"ts": {"gte": 1}}}]}},
            "size": 5000, "track_total_hits": True,
            "aggs": {"a": {"terms": {"field": "x", "size": 5000},
                           "aggs": {"b": {"terms": {"field": "y"}, "aggs": {"c": {"terms": {"field": "z"},
                                                                                   "aggs": {"d": {"avg": {"field": "v"}}}}}}}}}}
    # 30 шардов, один сильно медленнее остальных
    resp = {"took": 4200, "_shards": {"total": 30, "failed": 0}, "hits": {"total": {"value": 2_000_000}},
            "profile": _profile([20_000_000] * 29 + [900_000_000], leaf="WildcardQuery", aggs_ns=50_000_000)}
    m = analyze(resp, "/logs-*/_search", json.dumps(body))
    assert m["complexity_level"] in ("высокая", "очень высокая") and m["complexity_score"] >= 45
    assert m["speed_level"] == "медленный"
    assert "wildcard" in m["expensive"]
    text = " ".join(m["factors"])
    assert "Шаблон с * или ? в начале" in text and "Перекос" in text and "Затронуто шардов: 30" in text
    recs = " ".join(m["recommendations"])
    for fragment in ("ведущий символ", "search_after", "bool.filter", "track_total_hits", "composite", "вложенные"):
        assert fragment in recs, fragment


def test_analyze_msearch():
    body = '{"index": "a"}\n{"query": {"match_all": {}}}\n{"index": "b"}\n{"size": 0}\n'
    resp = {"took": 9, "responses": [
        {"_shards": {"total": 1}, "hits": {"total": {"value": 3}}, "profile": _profile([1_000_000])},
        {"_shards": {"total": 2}, "hits": {"total": {"value": 4}}, "profile": _profile([1_000_000, 1_000_000])}]}
    m = analyze(resp, "/_msearch", body)
    assert m["searches"] == 2 and m["shards_total"] == 3 and m["hits_total"] == 7 and m["shards_profiled"] == 3


def test_with_profile_body():
    assert json.loads(profiler.with_profile("/i/_search", "")) == {"profile": True}
    out = profiler.with_profile("/_msearch", '{"index":"a"}\n{"size":1}\n')
    lines = [json.loads(x) for x in out.splitlines()]
    assert lines == [{"index": "a"}, {"size": 1, "profile": True}]


# ================================================================ профилирование один раз на версию запроса

def test_profile_once_and_on_change(client):
    c = client
    before = len(PROFILE_REQUESTS)
    task_id = last_id(c.post("/tasks", data=search_form(name="ошибки"), follow_redirects=False))
    p = wait_profile(task_id)
    assert p.status == "done" and len(PROFILE_REQUESTS) == before + 1
    assert json.loads(PROFILE_REQUESTS[-1].content)["profile"] is True
    assert p.took_ms == 12 and p.complexity_level == "низкая" and p.speed_level == "быстрый"

    # Запуски не профилируют повторно, но сохраняют took
    for _ in range(3):
        run = wait_run(last_id(c.post(f"/tasks/{task_id}/run", follow_redirects=False)))
        assert run.status == "success" and run.es_took_ms == 3
    time.sleep(0.2)
    assert len(PROFILE_REQUESTS) == before + 1
    page = c.get(f"/tasks/{task_id}").text
    assert "Профиль запроса" in page and "низкая" in page and "Скорость по запускам" in page
    assert "По 3 последним успешным запускам" in page

    # Переформатирование тела — тот же запрос, профиль не строится
    c.post(f"/tasks/{task_id}", data=search_form(name="ошибки",
                                                 body='{\n  "size": 5,\n  "query": {"term": {"level": "ошибки"}}\n}'))
    time.sleep(0.2)
    assert len(PROFILE_REQUESTS) == before + 1

    # Запрос изменился — профиль строится заново
    c.post(f"/tasks/{task_id}", data=search_form(
        name="ошибки", body='{"query": {"wildcard": {"message": {"value": "*err*"}}}, "size": 5}'))
    p2 = wait_profile(task_id)
    assert p2.fingerprint != p.fingerprint and len(PROFILE_REQUESTS) == before + 2
    assert p2.complexity_score > p.complexity_score
    metrics = json.loads(p2.metrics)
    assert "wildcard" in metrics["expensive"] and any("ведущий символ" in r for r in metrics["recommendations"])

    # Полный профиль можно скачать
    raw = c.get(f"/tasks/{task_id}/profile/raw")
    assert raw.status_code == 200 and "shards" in raw.json()

    # Принудительное перепрофилирование
    c.post(f"/tasks/{task_id}/profile")
    wait_profile(task_id)
    assert len(PROFILE_REQUESTS) == before + 3

    # Неиспользуемые профили удаляются при очистке
    with SessionLocal() as s:
        assert s.get(QueryProfile, p.fingerprint) is not None
    profiler.cleanup()
    with SessionLocal() as s:
        assert s.get(QueryProfile, p.fingerprint) is None and s.get(QueryProfile, p2.fingerprint) is not None
    c.post(f"/tasks/{task_id}/delete")
    profiler.cleanup()
    with SessionLocal() as s:
        assert s.get(QueryProfile, p2.fingerprint) is None
    assert not profiler.profile_path(p2.fingerprint).exists()


def test_profile_after_first_run_when_missing(client):
    """Если профиль не построился при сохранении (например, его удалили), он строится после запуска."""
    c = client
    task_id = last_id(c.post("/tasks", data=search_form(name="без профиля"), follow_redirects=False))
    p = wait_profile(task_id)
    with SessionLocal() as s:
        s.delete(s.get(QueryProfile, p.fingerprint))
        s.commit()
    before = len(PROFILE_REQUESTS)
    wait_run(last_id(c.post(f"/tasks/{task_id}/run", follow_redirects=False)))
    assert wait_profile(task_id).status == "done" and len(PROFILE_REQUESTS) == before + 1
    c.post(f"/tasks/{task_id}/delete")


def test_msearch_and_unsupported_and_errors(client):
    c = client
    task_id = last_id(c.post("/tasks", data=form(
        path="/_msearch", body='{"index": "a"}\n{"query": {"match_all": {}}}\n{"index": "b"}\n{"size": 0}',
        action="save"), follow_redirects=False))
    p = wait_profile(task_id)
    assert p.status == "done" and json.loads(p.metrics)["searches"] == 2

    t2 = last_id(c.post("/tasks", data=form(path="/logs/_search/template", body='{"id": "tpl"}', action="save"),
                        follow_redirects=False))
    assert wait_profile(t2).status == "unsupported"
    assert "Profile API поддерживается только" in c.get(f"/tasks/{t2}").text

    t3 = last_id(c.post("/tasks", data=form(path="/broken/_search", action="save"), follow_redirects=False))
    p3 = wait_profile(t3)
    assert p3.status == "error" and "broken query" in p3.error
    assert "broken query" in c.get(f"/tasks/{t3}").text
    for tid in (task_id, t2, t3):
        c.post(f"/tasks/{tid}/delete")


def test_kind_tabs_and_no_profile_for_other_kinds(client):
    c = client
    before = len(PROFILE_REQUESTS)
    count_id = last_id(c.post("/tasks", data=form(name="подсчёт", path="/logs/_count", action="save"),
                              follow_redirects=False))
    search_id = last_id(c.post("/tasks", data=search_form(name="поиск-вкладка"), follow_redirects=False))
    wait_profile(search_id)
    wait_run(last_id(c.post(f"/tasks/{count_id}/run", follow_redirects=False)))
    time.sleep(0.2)
    assert len(PROFILE_REQUESTS) == before + 1  # только поисковый
    with SessionLocal() as s:
        assert s.scalar(select(Run.es_took_ms).where(Run.task_id == count_id)) is None

    page = c.get("/?kind=count").text
    assert "подсчёт" in page and "поиск-вкладка" not in page
    page = c.get("/?kind=search").text
    assert "поиск-вкладка" in page and "подсчёт" not in page
    assert "Поиск" in c.get("/").text and "Подсчёт" in c.get("/").text
    assert "Профиль запроса" not in c.get(f"/tasks/{count_id}").text
    assert c.post(f"/tasks/{count_id}/profile").status_code == 400
    for tid in (count_id, search_id):
        c.post(f"/tasks/{tid}/delete")


def test_profile_respects_access(client):
    c = client
    task_id = last_id(c.post("/tasks", data=search_form(name="закрытая"), follow_redirects=False))
    wait_profile(task_id)
    c.post("/admin/users", data={"username": "noaccess", "password": "noaccess-123", "password2": "noaccess-123",
                                 "is_active": "on"})
    login(c, "noaccess", "noaccess-123")
    assert c.get(f"/tasks/{task_id}/profile/raw").status_code == 404
    assert c.post(f"/tasks/{task_id}/profile").status_code == 404
    assert c.get(f"/tasks/{task_id}/profile/status").status_code == 404
    login(c, *ADMIN)
    c.post(f"/tasks/{task_id}/delete")
