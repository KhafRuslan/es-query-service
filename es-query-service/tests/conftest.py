import json
import os
import tempfile
import time

os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="es-query-service-test-")
os.environ["TIMEZONE"] = "Europe/Moscow"

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app import auth_routes, executor, security  # noqa: E402
from app import es as es_module  # noqa: E402
from app.db import SessionLocal  # noqa: E402
from app.es import Connection, es_pool  # noqa: E402
from app.main import app  # noqa: E402
from app.models import AuthSession, Cluster, ClusterKey, QueryProfile, Role, Run, Task, User  # noqa: E402

ADMIN = ("admin", "admin-pass-123")
ES_REQUESTS: list[httpx.Request] = []
WEBHOOK_REQUESTS: list[httpx.Request] = []
REAL_ASYNC_CLIENT = httpx.AsyncClient
BAD_KEY = "YmFkOmtleQ=="  # base64("bad:key")

SEARCH_RESPONSE = {
    "took": 3, "timed_out": False, "_shards": {"total": 1, "failed": 0},
    "hits": {"total": {"value": 2, "relation": "eq"}, "hits": [{"_id": "1"}, {"_id": "2"}]},
}


PROFILE_REQUESTS: list[httpx.Request] = []


def fake_profile(body: dict, shards: int = 2) -> dict:
    """Похожий на настоящий раздел "profile" ответа Elasticsearch."""
    text = json.dumps(body)
    leaf = "WildcardQuery" if "wildcard" in text else "TermQuery"
    return {"shards": [{
        "id": f"[node1][logs][{i}]",
        "searches": [{
            "query": [{"type": "BooleanQuery", "description": "+message:error", "time_in_nanos": 2_000_000 * (i + 1),
                       "children": [{"type": leaf, "description": "message:*err*", "time_in_nanos": 1_000_000}]}],
            "rewrite_time": 10_000,
            "collector": [{"name": "SimpleTopScoreDocCollector", "reason": "search_top_hits",
                           "time_in_nanos": 500_000}],
        }],
        "aggregations": [{"type": "StringTermsAggregator", "description": "levels", "time_in_nanos": 700_000}]
        if "aggs" in body else [],
        "fetch": {"type": "fetch", "time_in_nanos": 300_000},
    } for i in range(shards)]}


def fake_es(request: httpx.Request) -> httpx.Response:
    ES_REQUESTS.append(request)
    if request.headers.get("authorization") == f"ApiKey {BAD_KEY}":
        return httpx.Response(401, json={"error": "security_exception"})
    path = request.url.path
    if path == "/":
        return httpx.Response(200, json={"cluster_name": "test", "version": {"number": "8.17.0"}})
    if "/broken" in path:
        return httpx.Response(400, json={"error": {"type": "parsing_exception", "reason": "broken query"}})
    if path.endswith("/_msearch"):
        bodies = [json.loads(line) for line in request.content.decode().splitlines() if line.strip()][1::2]
        if any(b.get("profile") for b in bodies):
            PROFILE_REQUESTS.append(request)
        return httpx.Response(200, json={"took": 7, "responses": [
            {**SEARCH_RESPONSE, **({"profile": fake_profile(b)} if b.get("profile") else {})} for b in bodies]})
    if path.endswith("/_search"):
        body = json.loads(request.content) if request.content else {}
        if body.get("profile"):
            PROFILE_REQUESTS.append(request)
            return httpx.Response(200, json={**SEARCH_RESPONSE, "took": 12, "profile": fake_profile(body)})
        return httpx.Response(200, json=SEARCH_RESPONSE)
    if path.endswith("/_count"):
        return httpx.Response(200, json={"count": 5, "_shards": {"total": 1, "failed": 0}})
    return httpx.Response(404, json={"error": "index_not_found_exception"})


def fake_webhook(request: httpx.Request) -> httpx.Response:
    WEBHOOK_REQUESTS.append(request)
    return httpx.Response(200)


def fake_build_client(conn: Connection) -> httpx.AsyncClient:
    headers = {"Authorization": f"ApiKey {conn.api_key}"} if conn.api_key else {}
    return REAL_ASYNC_CLIENT(transport=httpx.MockTransport(fake_es), headers=headers)


@pytest.fixture(scope="session")
def app_client():
    es_module._build_client = fake_build_client
    with TestClient(app) as c:
        executor.httpx.AsyncClient = lambda **kw: REAL_ASYNC_CLIENT(transport=httpx.MockTransport(fake_webhook))
        yield c
    executor.httpx.AsyncClient = REAL_ASYNC_CLIENT


# ---------------------------------------------------------------- помощники

def login(c, username: str, password: str):
    c.cookies.clear()
    r = c.post("/login", data={"username": username, "password": password}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return r


def ensure_admin(c) -> None:
    if not auth_routes.users_exist():
        c.post("/setup/admin", data={"username": ADMIN[0], "password": ADMIN[1], "password2": ADMIN[1]})
    login(c, *ADMIN)


def ensure_local_cluster(c) -> None:
    with SessionLocal() as s:
        cid = s.scalar(select(Cluster.id).where(Cluster.name == "local"))
    if cid is None:
        r = c.post("/admin/clusters", data={"name": "local", "url": "http://localhost:9200", "key_name": "local-key",
                                            "is_default": "on", "action": "save"}, follow_redirects=False)
        assert r.status_code == 303, r.text
    else:
        c.post(f"/admin/clusters/{cid}/default")


def reset_all(c) -> None:
    """Пустая БД, как при первом запуске."""
    with SessionLocal() as s:
        for model in (Run, Task, QueryProfile, Role, ClusterKey, Cluster, AuthSession, User):
            s.query(model).delete()
        s.commit()
    auth_routes._has_users = False
    es_pool._clients.clear()
    security._failures.clear()
    c.cookies.clear()


@pytest.fixture
def client(app_client):
    """Администратор вошёл в систему, есть кластер "local" с ключом "local-key" (по умолчанию)."""
    ensure_admin(app_client)
    ensure_local_cluster(app_client)
    return app_client


def local_key_id() -> int:
    with SessionLocal() as s:
        return s.scalar(select(ClusterKey.id).join(Cluster).where(Cluster.name == "local"))


def form(**kw) -> dict:
    data = {"key_id": str(local_key_id()), "name": "test", "method": "POST", "path": "/logs/_search",
            "body": '{"query": {"match_all": {}}}', "mode": "now", "action": "run"}
    data.update(kw)
    return data


def last_id(r) -> int:
    return int(r.headers["location"].split("?")[0].rsplit("/", 1)[1])


def wait_run(run_id: int, timeout: float = 5) -> Run:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with SessionLocal() as s:
            run = s.get(Run, run_id)
            if run.status != "running" and not (run.webhook_status or "").startswith("Отправ"):
                return run
        time.sleep(0.05)
    raise AssertionError("run did not finish")
