"""Типы запросов и профилирование поисковых запросов (Elasticsearch Profile API).

Профиль строится один раз для «отпечатка» запроса (кластер + метод + путь + тело в каноническом виде)
и переиспользуется всеми запусками. Изменился запрос — изменился отпечаток — профиль строится заново.
"""

import asyncio
import hashlib
import json
import logging
import re
from collections import Counter

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError

from .access import run_permission_error
from .config import settings
from .db import SessionLocal, utcnow
from .es import ESRequestError, es_pool, is_ndjson
from .models import (PROFILE_DONE, PROFILE_ERROR, PROFILE_RUNNING, PROFILE_UNSUPPORTED, QueryProfile, Task)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------- типы запросов

KIND_SEARCH, KIND_COUNT, KIND_SQL, KIND_OTHER = "search", "count", "sql", "other"
KIND_LABELS = {KIND_SEARCH: "Поиск", KIND_COUNT: "Подсчёт", KIND_SQL: "SQL / ES|QL", KIND_OTHER: "Прочее"}

_SEARCH = re.compile(r"(^|/)(_search|_msearch|_search/template|_msearch/template|_async_search|_eql/search"
                     r"|_knn_search|_search/scroll)(/|$)")
_COUNT = re.compile(r"(^|/)_count(/|$)")
_SQL = re.compile(r"(^|/)(_sql|_query)(/|$)")
_PROFILABLE = re.compile(r"(^|/)(_search|_msearch)/?$")


def _bare(path: str) -> str:
    return (path or "").split("?", 1)[0]


def query_kind(path: str) -> str:
    p = _bare(path)
    if _SEARCH.search(p):
        return KIND_SEARCH
    if _COUNT.search(p):
        return KIND_COUNT
    if _SQL.search(p):
        return KIND_SQL
    return KIND_OTHER


def supports_profile(path: str) -> bool:
    return bool(_PROFILABLE.search(_bare(path)))


# ---------------------------------------------------------------- отпечаток запроса

def _canonical_body(path: str, body: str) -> str:
    body = (body or "").strip()
    if not body:
        return ""
    try:
        if is_ndjson(path):
            return "\n".join(json.dumps(json.loads(line), sort_keys=True, separators=(",", ":"))
                             for line in body.splitlines() if line.strip())
        return json.dumps(json.loads(body), sort_keys=True, separators=(",", ":"))
    except json.JSONDecodeError:
        return body


def fingerprint(cluster_id: int | None, method: str, path: str, body: str) -> str:
    """Отпечаток запроса: форматирование тела и порядок ключей на него не влияют."""
    raw = json.dumps([cluster_id, method.upper(), path, _canonical_body(path, body)], ensure_ascii=False)
    return hashlib.sha256(raw.encode()).hexdigest()


def task_fingerprint(task: Task) -> str:
    return fingerprint(task.key.cluster_id if task.key else None, task.method, task.path, task.body)


# ---------------------------------------------------------------- запрос с профилированием

def with_profile(path: str, body: str) -> str:
    """Тело запроса с "profile": true (для _msearch — в каждом поисковом теле)."""
    if is_ndjson(path):
        lines = [line for line in (body or "").splitlines() if line.strip()]
        out = []
        for i, line in enumerate(lines):
            obj = json.loads(line)
            if i % 2 == 1:  # строки заголовков и тел чередуются
                obj["profile"] = True
            out.append(json.dumps(obj, ensure_ascii=False))
        return "\n".join(out) + "\n"
    obj = json.loads(body) if (body or "").strip() else {}
    obj["profile"] = True
    return json.dumps(obj, ensure_ascii=False)


# ---------------------------------------------------------------- анализ профиля

# Lucene-запросы, которые дорого обходятся кластеру
EXPENSIVE_LUCENE = {
    "WildcardQuery": "wildcard",
    "RegexpQuery": "regexp",
    "AutomatonQuery": "wildcard/regexp",
    "FuzzyQuery": "fuzzy",
    "PrefixQuery": "prefix",
    "MultiTermQueryConstantScoreWrapper": "prefix/wildcard",
    "MultiTermQueryConstantScoreBlendedWrapper": "prefix/wildcard",
    "ScriptQuery": "script",
    "ScriptScoreQuery": "script_score",
    "FunctionScoreQuery": "function_score",
    "ToParentBlockJoinQuery": "nested",
    "ESToParentBlockJoinQuery": "nested",
    "TermInSetQuery": "terms (много значений)",
}

# Вес дорогих конструкций в оценке сложности: на больших данных они растут вместе с объёмом индекса
EXPENSIVE_WEIGHT = {
    "script": 20, "script_score": 15, "function_score": 10, "regexp": 15, "wildcard/regexp": 15,
    "wildcard": 10, "prefix/wildcard": 10, "prefix": 5, "fuzzy": 10, "nested": 10, "terms (много значений)": 10,
}

RECOMMENDATIONS = {
    "leading_wildcard": "Шаблон с * или ? в начале перебирает весь словарь термов поля. Уберите ведущий символ "
                        "или используйте поле типа wildcard / ngram-анализатор.",
    "wildcard": "wildcard/prefix перебирают термы индекса. Для поиска по началу строки подойдёт index_prefixes "
                "или поле типа keyword с ограниченной кардинальностью.",
    "regexp": "Регулярные выражения — одни из самых дорогих запросов. По возможности замените на term/terms "
              "или поле с подготовленными значениями.",
    "fuzzy": "fuzzy строит автомат для каждого терма. Ограничьте fuzziness, prefix_length и max_expansions.",
    "script": "Скрипты выполняются для каждого документа. Вынесите вычисление на этап индексации "
              "(runtime → обычное поле, ingest pipeline).",
    "nested": "nested-запросы обходят скрытые вложенные документы. Проверьте, нужна ли вложенность, "
              "или денормализуйте данные.",
    "join": "has_child/has_parent — дорогие join-запросы. По возможности денормализуйте данные.",
    "large_terms": "terms с большим списком значений. Используйте terms lookup или сократите список.",
    "large_size": "Большой size загружает фазу fetch. Для выгрузки используйте search_after + PIT или scroll.",
    "deep_paging": "Глубокая пагинация (from + size) заставляет каждый шард сортировать from + size документов. "
                   "Используйте search_after.",
    "many_shards": "Запрос затрагивает много шардов. Сузьте шаблон индексов (например, по дате) "
                   "или добавьте фильтр по времени.",
    "skew": "Один шард работает заметно дольше остальных — возможен перекос данных или горячий узел.",
    "must_to_filter": "Условия term/terms/range в bool.must влияют на релевантность и не кэшируются. "
                      "Если оценка не нужна — перенесите их в bool.filter.",
    "track_total_hits": "track_total_hits: true заставляет точно считать все совпадения. "
                        "Уберите параметр или задайте порог (например, 10000).",
    "big_terms_agg": "terms-агрегация с большим size нагружает память и сеть. Используйте composite-агрегацию "
                     "с пагинацией.",
    "deep_aggs": "Глубоко вложенные агрегации растут комбинаторно. Сократите вложенность или число бакетов.",
    "slow": "Запрос выполняется долго. Ограничьте диапазон данных фильтром по времени и уменьшите число индексов.",
}


def _ns_to_ms(ns: int | float) -> float:
    return round((ns or 0) / 1_000_000, 2)


def _walk(nodes: list, depth: int = 1, acc: dict | None = None) -> dict:
    acc = acc if acc is not None else {"count": 0, "depth": 0, "types": Counter(), "descriptions": []}
    for n in nodes or []:
        acc["count"] += 1
        acc["depth"] = max(acc["depth"], depth)
        acc["types"][n.get("type", "?")] += 1
        if n.get("description"):
            acc["descriptions"].append(str(n["description"])[:300])
        _walk(n.get("children", []), depth + 1, acc)
    return acc


def _iter_body_nodes(node, path=()):
    """Обход тела запроса: (путь ключей, ключ, значение)."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield path, k, v
            yield from _iter_body_nodes(v, path + (k,))
    elif isinstance(node, list):
        for item in node:
            yield from _iter_body_nodes(item, path)


def _agg_depth(aggs: dict, depth: int = 1) -> int:
    best = 0
    for spec in (aggs or {}).values():
        if not isinstance(spec, dict):
            continue
        best = max(best, depth)
        sub = spec.get("aggs") or spec.get("aggregations")
        if isinstance(sub, dict):
            best = max(best, _agg_depth(sub, depth + 1))
    return best


def _static_checks(bodies: list[dict]) -> set[str]:
    """Проблемы, видимые по самому тексту запроса."""
    found: set[str] = set()
    for body in bodies:
        size = body.get("size", 10)
        frm = body.get("from", 0)
        if isinstance(size, int) and size > 1000:
            found.add("large_size")
        if isinstance(size, int) and isinstance(frm, int) and frm + size > 5000 and frm > 0:
            found.add("deep_paging")
        if body.get("track_total_hits") is True:
            found.add("track_total_hits")
        aggs = body.get("aggs") or body.get("aggregations")
        if isinstance(aggs, dict) and _agg_depth(aggs) > 3:
            found.add("deep_aggs")
        for path, key, value in _iter_body_nodes(body):
            if key in ("wildcard", "prefix") and isinstance(value, dict):
                for v in value.values():
                    pattern = v.get("value", v.get("wildcard")) if isinstance(v, dict) else v
                    if isinstance(pattern, str) and pattern[:1] in ("*", "?"):
                        found.add("leading_wildcard")
            elif key == "query_string" and isinstance(value, dict):
                q = str(value.get("query", ""))
                if re.search(r"(^|[\s:(])[*?]\w", q):
                    found.add("leading_wildcard")
            elif key in ("has_child", "has_parent"):
                found.add("join")
            elif key == "terms" and isinstance(value, dict) and "field" not in value:
                if any(isinstance(v, list) and len(v) > 500 for v in value.values()):
                    found.add("large_terms")
            elif key == "terms" and isinstance(value, dict) and isinstance(value.get("size"), int) \
                    and value["size"] > 1000 and "field" in value:
                found.add("big_terms_agg")
            elif key == "bool" and isinstance(value, dict):
                must = value.get("must")
                must = must if isinstance(must, list) else [must] if isinstance(must, dict) else []
                if any(isinstance(m, dict) and set(m) & {"term", "terms", "range"} for m in must):
                    found.add("must_to_filter")
    return found


def speed_level(took_ms: float | None) -> str | None:
    if took_ms is None:
        return None
    if took_ms < 100:
        return "быстрый"
    if took_ms < 1000:
        return "нормальный"
    if took_ms < 10_000:
        return "медленный"
    return "очень медленный"


def complexity_level(score: int) -> str:
    if score < 20:
        return "низкая"
    if score < 45:
        return "средняя"
    if score < 70:
        return "высокая"
    return "очень высокая"


def analyze(response: dict, path: str, body: str) -> dict:
    """Метрики скорости и сложности по ответу с профилем."""
    if is_ndjson(path):
        lines = [json.loads(line) for line in (body or "").splitlines() if line.strip()]
        bodies = [b for i, b in enumerate(lines) if i % 2 == 1]
        responses = response.get("responses") or []
        took = response.get("took")
    else:
        bodies = [json.loads(body)] if (body or "").strip() else [{}]
        responses = [response]
        took = response.get("took")

    shard_totals: list[tuple[str, float]] = []
    t = Counter()  # суммы по фазам, мс
    t_max = Counter()  # максимум по шарду, мс
    query_nodes = query_depth = agg_nodes = agg_depth = 0
    lucene = Counter()
    descriptions: list[str] = []
    hits_total = 0
    shards_total = shards_failed = 0
    timed_out = False

    for resp in responses:
        if not isinstance(resp, dict):
            continue
        timed_out = timed_out or bool(resp.get("timed_out"))
        sh = resp.get("_shards") or {}
        shards_total += sh.get("total", 0)
        shards_failed += sh.get("failed", 0)
        total = (resp.get("hits") or {}).get("total")
        hits_total += total.get("value", 0) if isinstance(total, dict) else (total or 0)
        for shard in (resp.get("profile") or {}).get("shards", []):
            phase = Counter()
            for search in shard.get("searches", []):
                q = _walk(search.get("query", []))
                query_nodes, query_depth = max(query_nodes, q["count"]), max(query_depth, q["depth"])
                lucene.update(q["types"])
                descriptions.extend(q["descriptions"])
                phase["query"] += _ns_to_ms(sum(n.get("time_in_nanos", 0) for n in search.get("query", [])))
                phase["rewrite"] += _ns_to_ms(search.get("rewrite_time", 0))
                phase["collector"] += _ns_to_ms(sum(c.get("time_in_nanos", 0) for c in search.get("collector", [])))
            a = _walk(shard.get("aggregations", []))
            agg_nodes, agg_depth = max(agg_nodes, a["count"]), max(agg_depth, a["depth"])
            phase["aggregations"] += _ns_to_ms(sum(n.get("time_in_nanos", 0) for n in shard.get("aggregations", [])))
            fetch = shard.get("fetch")
            if isinstance(fetch, dict):
                phase["fetch"] += _ns_to_ms(fetch.get("time_in_nanos", 0))
            work = phase["query"] + phase["rewrite"] + phase["aggregations"] + phase["fetch"]
            shard_totals.append((str(shard.get("id", "?")), round(work, 2)))
            for k, v in phase.items():
                t[k] += v
                t_max[k] = max(t_max[k], v)

    cluster_ms = round(t["query"] + t["rewrite"] + t["aggregations"] + t["fetch"], 2)
    profiled = len(shard_totals)
    issues = _static_checks(bodies)
    expensive = sorted({EXPENSIVE_LUCENE[k] for k in lucene if k in EXPENSIVE_LUCENE})
    for name in expensive:
        issues.add({"wildcard": "wildcard", "prefix": "wildcard", "prefix/wildcard": "wildcard",
                    "wildcard/regexp": "regexp", "regexp": "regexp", "fuzzy": "fuzzy", "script": "script",
                    "script_score": "script", "function_score": "script", "nested": "nested",
                    "terms (много значений)": "large_terms"}[name])

    # --- оценка сложности (0–100) и факторы
    factors: list[str] = []
    score = 0

    def add(points: int, text: str) -> None:
        nonlocal score
        score += points
        factors.append(text)

    if cluster_ms > 5000:
        add(35, f"Суммарное время работы шардов {cluster_ms:.0f} мс")
    elif cluster_ms > 500:
        add(25 if cluster_ms > 2000 else 15, f"Суммарное время работы шардов {cluster_ms:.0f} мс")
    elif cluster_ms > 50:
        add(5, f"Суммарное время работы шардов {cluster_ms:.0f} мс")
    if shards_total > 100 or profiled > 100:
        add(10, f"Затронуто шардов: {max(shards_total, profiled)}")
        issues.add("many_shards")
    elif shards_total > 20 or profiled > 20:
        add(5, f"Затронуто шардов: {max(shards_total, profiled)}")
    if query_nodes > 100:
        add(10, f"Дерево запроса: {query_nodes} узлов (глубина {query_depth})")
    elif query_nodes > 20:
        add(5, f"Дерево запроса: {query_nodes} узлов (глубина {query_depth})")
    for name in expensive:
        add(EXPENSIVE_WEIGHT.get(name, 10), f"Дорогая конструкция: {name}")
    if "leading_wildcard" in issues:
        add(15, "Шаблон с * или ? в начале")
    if "join" in issues:
        add(10, "join-запрос (has_child / has_parent)")
    if agg_nodes:
        pts = (5 if agg_nodes > 5 else 2) + (5 if agg_depth > 3 else 0)
        add(pts, f"Агрегации: {agg_nodes} (вложенность {agg_depth}), {t['aggregations']:.0f} мс")
    if "large_size" in issues or "deep_paging" in issues:
        add(10, "Большой size или глубокая пагинация")
    if "track_total_hits" in issues and hits_total > 100_000:
        add(5, f"Точный подсчёт {hits_total} совпадений (track_total_hits)")
    if profiled > 1:
        avg = sum(v for _, v in shard_totals) / profiled
        slowest = max(shard_totals, key=lambda x: x[1])
        if avg > 5 and slowest[1] > 3 * avg:
            add(5, f"Перекос: шард {slowest[0]} работает в {slowest[1] / avg:.1f} раза дольше среднего")
            issues.add("skew")
    if took and took > 1000:
        issues.add("slow")
    if timed_out:
        add(10, "Запрос прерван по таймауту")
    score = min(score, 100)

    slowest = max(shard_totals, key=lambda x: x[1]) if shard_totals else None
    order = ["leading_wildcard", "regexp", "script", "fuzzy", "wildcard", "nested", "join", "large_terms",
             "deep_paging", "large_size", "big_terms_agg", "deep_aggs", "many_shards", "skew", "must_to_filter",
             "track_total_hits", "slow"]
    return {
        "took_ms": took,
        "speed_level": speed_level(took),
        "complexity_score": score,
        "complexity_level": complexity_level(score),
        "factors": factors,
        "recommendations": [RECOMMENDATIONS[k] for k in order if k in issues],
        "hits_total": hits_total,
        "shards_total": shards_total,
        "shards_failed": shards_failed,
        "shards_profiled": profiled,
        "timed_out": timed_out,
        "cluster_ms": cluster_ms,
        "phases": [
            {"name": name, "total_ms": round(t[key], 2), "max_ms": round(t_max[key], 2)}
            for key, name in (("query", "Запрос (query)"), ("rewrite", "Переписывание (rewrite)"),
                              ("collector", "Сбор результатов (collector)"),
                              ("aggregations", "Агрегации"), ("fetch", "Загрузка документов (fetch)"))
            if t[key] or key in ("query", "fetch")
        ],
        "slowest_shard": {"id": slowest[0], "ms": slowest[1]} if slowest else None,
        "query_nodes": query_nodes,
        "query_depth": query_depth,
        "agg_nodes": agg_nodes,
        "agg_depth": agg_depth,
        "lucene_types": lucene.most_common(8),
        "expensive": expensive,
        "searches": len(bodies),
    }


# ---------------------------------------------------------------- выполнение профилирования

_background: set[asyncio.Task] = set()


def profile_path(fp: str):
    return settings.data_dir / "profiles" / f"{fp}.json"


def _claim(fp: str, cluster_id: int | None, force: bool, unsupported: bool) -> bool:
    """Помечает профиль как выполняющийся. False — профиль уже есть или строится."""
    status = PROFILE_UNSUPPORTED if unsupported else PROFILE_RUNNING
    with SessionLocal() as s:
        row = s.get(QueryProfile, fp)
        if row is None:
            s.add(QueryProfile(fingerprint=fp, cluster_id=cluster_id, status=status, requested_at=utcnow()))
            try:
                s.commit()
            except IntegrityError:
                return False  # параллельный запрос успел первым
            return not unsupported
        if row.status == PROFILE_RUNNING or (row.status in (PROFILE_DONE, PROFILE_UNSUPPORTED) and not force):
            return False
        # Ошибка в прошлый раз или принудительное перепрофилирование
        res = s.execute(update(QueryProfile).where(QueryProfile.fingerprint == fp,
                                                   QueryProfile.status == row.status)
                        .values(status=status, requested_at=utcnow(), error=None))
        s.commit()
        return res.rowcount == 1 and not unsupported


def _finish(fp: str, **fields) -> None:
    with SessionLocal() as s:
        s.execute(update(QueryProfile).where(QueryProfile.fingerprint == fp).values(finished_at=utcnow(), **fields))
        s.commit()


async def ensure_profile(task_id: int, actor_id: int | None, force: bool = False) -> None:
    """Строит профиль поискового запроса задачи, если для текущего отпечатка его ещё нет."""
    with SessionLocal() as s:
        task = s.get(Task, task_id)
        if task is None or query_kind(task.path) != KIND_SEARCH:
            return
        fp = task_fingerprint(task)
        key_id = task.key_id
        cluster_id = task.key.cluster_id if task.key else None
        method, path, body = task.method, task.path, task.body
    if not _claim(fp, cluster_id, force, unsupported=not supports_profile(path)):
        return

    log.info("Профилирование задачи %s (%s)", task_id, fp[:12])
    try:
        denied = run_permission_error(actor_id, key_id)
        if denied:
            raise ESRequestError(denied)
        from .executor import _sem  # общий лимит параллельных запросов к ES
        async with _sem():
            resp = await es_pool.request(key_id, method, path, with_profile(path, body))
        if resp.status >= 300:
            text = resp.content[:1000].decode("utf-8", "replace")
            raise ESRequestError(f"Elasticsearch вернул HTTP {resp.status}: {text}")
        data = json.loads(resp.content)
        metrics = analyze(data, path, body)
        raw = data.get("profile") if not is_ndjson(path) else [r.get("profile") for r in data.get("responses", [])]
        file = profile_path(fp)
        file.parent.mkdir(parents=True, exist_ok=True)
        await asyncio.to_thread(file.write_text, json.dumps(raw, ensure_ascii=False), "utf-8")
        _finish(fp, status=PROFILE_DONE, took_ms=metrics["took_ms"], complexity_score=metrics["complexity_score"],
                complexity_level=metrics["complexity_level"], speed_level=metrics["speed_level"],
                metrics=json.dumps(metrics, ensure_ascii=False))
        log.info("Профиль %s: сложность %s (%s), took %s мс", fp[:12], metrics["complexity_score"],
                 metrics["complexity_level"], metrics["took_ms"])
    except (ESRequestError, ValueError) as e:
        _finish(fp, status=PROFILE_ERROR, error=str(e)[:2000])
    except Exception as e:  # noqa: BLE001
        log.exception("Ошибка профилирования %s", fp[:12])
        _finish(fp, status=PROFILE_ERROR, error=f"{type(e).__name__}: {e}"[:2000])


def schedule_profile(task_id: int, actor_id: int | None, force: bool = False) -> None:
    """Профилирование в фоне (вызывать из event loop)."""
    t = asyncio.create_task(ensure_profile(task_id, actor_id, force))
    _background.add(t)
    t.add_done_callback(_background.discard)


def profiles_for(tasks: list[Task]) -> dict[int, QueryProfile]:
    """Профили задач по их текущему отпечатку: {task_id: QueryProfile}."""
    fps = {t.id: task_fingerprint(t) for t in tasks if query_kind(t.path) == KIND_SEARCH}
    if not fps:
        return {}
    with SessionLocal() as s:
        rows = {p.fingerprint: p for p in s.scalars(select(QueryProfile).where(
            QueryProfile.fingerprint.in_(set(fps.values()))))}
    return {tid: rows[fp] for tid, fp in fps.items() if fp in rows}


def reset_interrupted() -> None:
    with SessionLocal() as s:
        s.execute(update(QueryProfile).where(QueryProfile.status == PROFILE_RUNNING)
                  .values(status=PROFILE_ERROR, error="Профилирование прервано перезапуском сервиса"))
        s.commit()


def cleanup() -> None:
    """Удаляет профили, которые больше не соответствуют ни одной задаче."""
    with SessionLocal() as s:
        used = {task_fingerprint(t) for t in s.scalars(select(Task)) if query_kind(t.path) == KIND_SEARCH}
        stale = [fp for fp in s.scalars(select(QueryProfile.fingerprint).where(
            QueryProfile.status != PROFILE_RUNNING)) if fp not in used]
        if stale:
            s.execute(delete(QueryProfile).where(QueryProfile.fingerprint.in_(stale)))
            s.commit()
    for fp in stale:
        profile_path(fp).unlink(missing_ok=True)
