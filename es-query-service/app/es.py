"""Клиент Elasticsearch поверх REST API (не зависит от версии кластера: ES 7/8/9, OpenSearch)."""

import asyncio
import base64
import json
import re
import ssl
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from .config import settings

ALLOWED_METHODS = ("GET", "POST", "PUT", "DELETE", "HEAD")

# Эндпоинты, на которые разрешён POST в режиме только-чтение
_READ_ONLY_POST = re.compile(
    r"(^|/)(_search|_count|_msearch|_sql|_field_caps|_validate/query|_explain|_render/template"
    r"|_eql/search|_terms_enum|_async_search|_pit|_mget|_esql)(/|$)"
)
_NDJSON = re.compile(r"(^|/)(_msearch|_msearch/template|_bulk)/?$")


class ESRequestError(Exception):
    pass


class ResultTooLarge(ESRequestError):
    pass


@dataclass
class ESResponse:
    status: int
    content: bytes
    content_type: str


def normalize_path(path: str) -> str:
    path = (path or "").strip()
    if not path:
        raise ValueError("Не указан путь запроса, например /my-index/_search")
    if re.search(r"\s|#|\\|://", path):
        raise ValueError("Путь не должен содержать пробелы, '#', '\\' или схему (http://)")
    # Схлопываем ведущие слэши, чтобы путь нельзя было превратить в адрес другого хоста
    return "/" + path.lstrip("/")


def _bare_path(path: str) -> str:
    return path.split("?", 1)[0]


def is_ndjson(path: str) -> bool:
    return bool(_NDJSON.search(_bare_path(path)))


def check_allowed(method: str, path: str) -> None:
    if method not in ALLOWED_METHODS:
        raise ValueError(f"Недопустимый метод {method}")
    if not settings.es_read_only:
        return
    if method == "GET":
        return
    if method == "POST" and _READ_ONLY_POST.search(_bare_path(path)):
        return
    raise ValueError(
        "Сервис работает в режиме только-чтение (ES_READ_ONLY=true): разрешены GET и POST "
        "на _search, _count, _msearch, _sql, _esql, _mget и т.п."
    )


def validate_body(path: str, body: str) -> str:
    body = (body or "").strip()
    if not body:
        return ""
    if is_ndjson(path):
        for n, line in enumerate(body.splitlines(), 1):
            if line.strip():
                try:
                    json.loads(line)
                except json.JSONDecodeError as e:
                    raise ValueError(f"Строка {n}: некорректный JSON ({e.msg})") from None
        return body + "\n"
    try:
        json.loads(body)
    except json.JSONDecodeError as e:
        raise ValueError(f"Некорректный JSON в теле запроса: {e.msg} (строка {e.lineno}, позиция {e.colno})") from None
    return body


@dataclass
class Connection:
    url: str
    api_key: str | None = None
    verify_tls: bool = True


def normalize_url(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    u = urlsplit(url)
    if u.scheme not in ("http", "https") or not u.netloc:
        raise ValueError("Адрес кластера должен начинаться с http:// или https://, например https://es.example.com:9200")
    if u.query or u.fragment:
        raise ValueError("Адрес кластера не должен содержать параметры (?...) и якорь (#...)")
    return url


def normalize_api_key(key: str | None) -> str | None:
    """Принимает ключ в виде base64 ("encoded" из Kibana), "id:api_key" или "ApiKey <base64>"."""
    key = (key or "").strip()
    if key.lower().startswith("apikey "):
        key = key[7:].strip()
    if not key:
        return None
    if ":" in key:
        key = base64.b64encode(key.encode()).decode()
    if re.search(r"\s", key):
        raise ValueError("API-ключ не должен содержать пробелы")
    return key


def _build_client(conn: Connection) -> httpx.AsyncClient:
    if not conn.verify_tls:
        verify: ssl.SSLContext | bool = False
    elif settings.es_ca_certs:
        verify = ssl.create_default_context(cafile=settings.es_ca_certs)
    else:
        verify = True
    headers = {"Accept": "application/json"}
    auth = None
    if conn.api_key:
        headers["Authorization"] = f"ApiKey {conn.api_key}"
    elif settings.es_username:
        auth = (settings.es_username, settings.es_password or "")
    return httpx.AsyncClient(
        headers=headers,
        auth=auth,
        verify=verify,
        timeout=httpx.Timeout(settings.es_timeout, connect=10.0),
        follow_redirects=False,
    )


async def probe(conn: Connection, client: httpx.AsyncClient | None = None) -> dict:
    """Проверяет подключение: возвращает ответ GET / или бросает ESRequestError с понятным текстом."""
    own = client is None
    client = client or _build_client(conn)
    try:
        resp = await client.get(conn.url + "/", timeout=10.0)
    except httpx.ConnectError as e:
        if "CERTIFICATE_VERIFY_FAILED" in str(e) or "SSL" in str(e):
            raise ESRequestError(
                "Не удалось проверить TLS-сертификат кластера. Включите «Не проверять TLS-сертификат» "
                f"или укажите CA-сертификат в ES_CA_CERTS. ({e})") from None
        raise ESRequestError(f"Не удалось подключиться к {conn.url}: {e}") from None
    except httpx.HTTPError as e:
        raise ESRequestError(f"Ошибка подключения к {conn.url}: {type(e).__name__}: {e}") from None
    finally:
        if own:
            await client.aclose()
    if resp.status_code == 401:
        raise ESRequestError("Кластер отклонил авторизацию (HTTP 401): проверьте API-ключ")
    if resp.status_code == 403:
        raise ESRequestError("Недостаточно прав (HTTP 403): у API-ключа нет доступа к кластеру")
    if resp.status_code >= 300:
        raise ESRequestError(f"Кластер ответил HTTP {resp.status_code}: {resp.text[:300]}")
    try:
        data = resp.json()
    except ValueError:
        raise ESRequestError(f"По адресу {conn.url} ответил не Elasticsearch") from None
    if not isinstance(data, dict) or "version" not in data:
        raise ESRequestError(f"По адресу {conn.url} ответил не Elasticsearch")
    return data


class ESPool:
    """HTTP-клиенты по id ключа доступа (кластер + API-ключ). Подключение можно сменить на лету через configure()."""

    def __init__(self) -> None:
        self._clients: dict[int, tuple[Connection, httpx.AsyncClient]] = {}
        self._retired: set[asyncio.Task] = set()
        self._status: dict[int, tuple[float, dict]] = {}

    @property
    def configured(self) -> bool:
        return bool(self._clients)

    def connection(self, key_id: int) -> Connection | None:
        entry = self._clients.get(key_id)
        return entry[0] if entry else None

    def configure(self, key_id: int, conn: Connection, client: httpx.AsyncClient | None = None) -> None:
        old = self._clients.get(key_id)
        if old and old[0] == conn and client is None:
            return
        self._status.pop(key_id, None)
        self._clients[key_id] = (conn, client or _build_client(conn))
        if old:
            self._retire(old[1])

    def remove(self, key_id: int) -> None:
        old = self._clients.pop(key_id, None)
        self._status.pop(key_id, None)
        if old:
            self._retire(old[1])

    def _retire(self, client: httpx.AsyncClient) -> None:
        # Старый клиент закрываем позже: им могут пользоваться выполняющиеся запросы
        t = asyncio.create_task(self._close_later(client))
        self._retired.add(t)
        t.add_done_callback(self._retired.discard)

    async def _close_later(self, client: httpx.AsyncClient) -> None:
        await asyncio.sleep(settings.es_timeout + 10)
        await client.aclose()

    async def close(self) -> None:
        for _, client in self._clients.values():
            await client.aclose()
        self._clients.clear()

    async def request(self, key_id: int | None, method: str, path: str, body: str = "") -> ESResponse:
        entry = self._clients.get(key_id) if key_id is not None else None
        if entry is None:
            raise ESRequestError("Ключ доступа не найден: выберите другой в настройках задачи")
        conn, client = entry
        path = normalize_path(path)
        check_allowed(method, path)
        url = conn.url + path
        content = body.encode("utf-8") if body else None
        headers = {}
        if content is not None:
            headers["Content-Type"] = "application/x-ndjson" if is_ndjson(path) else "application/json"

        limit = settings.max_result_mb * 1024 * 1024
        try:
            async with client.stream(method, url, content=content, headers=headers) as resp:
                chunks, size = [], 0
                async for chunk in resp.aiter_bytes():
                    size += len(chunk)
                    if size > limit:
                        raise ResultTooLarge(
                            f"Ответ превышает лимит {settings.max_result_mb} МБ (MAX_RESULT_MB). "
                            "Уменьшите size или используйте агрегации."
                        )
                    chunks.append(chunk)
                ctype = resp.headers.get("content-type", "application/json").split(";")[0].strip()
                return ESResponse(resp.status_code, b"".join(chunks), ctype)
        except httpx.HTTPError as e:
            raise ESRequestError(f"Ошибка соединения с Elasticsearch ({conn.url}): {type(e).__name__}: {e}") from e

    async def status(self, key_id: int, cache_seconds: float = 30) -> dict:
        """Доступность кластера через ключ: {"ok", "cluster", "version"} или {"ok": False, "error"}. Кэшируется."""
        cached = self._status.get(key_id)
        if cached and time.monotonic() - cached[0] < cache_seconds:
            return cached[1]
        try:
            info = await asyncio.wait_for(self.info(key_id), 8)
            result = {"ok": True, "cluster": info.get("cluster_name"),
                      "version": info.get("version", {}).get("number")}
        except asyncio.TimeoutError:
            result = {"ok": False, "error": "Кластер не ответил за 8 секунд"}
        except Exception as e:  # noqa: BLE001
            result = {"ok": False, "error": str(e) or type(e).__name__}
        self._status[key_id] = (time.monotonic(), result)
        return result

    async def info(self, key_id: int) -> dict:
        entry = self._clients.get(key_id)
        if entry is None:
            raise ESRequestError("Ключ доступа не найден")
        return await probe(*entry)


es_pool = ESPool()
