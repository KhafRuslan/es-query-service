from sqlalchemy import create_engine, text

from app.db import Base, migrate


def _tables(conn) -> set[str]:
    return {r[0] for r in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))}


def _columns(conn, table: str) -> set[str]:
    return {r[1] for r in conn.execute(text(f"PRAGMA table_info({table})"))}


def test_migration_from_v1_single_connection(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'v1.db'}")
    with eng.begin() as conn:  # схема первой версии (упрощённо)
        conn.execute(text("CREATE TABLE tasks (id INTEGER PRIMARY KEY, name VARCHAR(200))"))
        conn.execute(text("CREATE TABLE runs (id INTEGER PRIMARY KEY, task_id INTEGER)"))
        conn.execute(text("CREATE TABLE es_connection (id INTEGER PRIMARY KEY, url VARCHAR(2000), "
                          "api_key TEXT, verify_tls BOOLEAN, updated_at DATETIME)"))
        conn.execute(text("INSERT INTO es_connection VALUES (1, 'https://10.0.0.1:9200', 'a2V5', 0, NULL)"))
        conn.execute(text("INSERT INTO tasks VALUES (1, 'old task')"))
    Base.metadata.create_all(eng)
    migrate(eng)
    migrate(eng)  # повторный запуск ничего не ломает
    with eng.connect() as conn:
        cluster = conn.execute(text("SELECT id, name, url, verify_tls, is_default FROM clusters")).one()
        assert (cluster.name, cluster.url, bool(cluster.verify_tls), bool(cluster.is_default)) == \
            ("Основной", "https://10.0.0.1:9200", False, True)
        key = conn.execute(text("SELECT id, cluster_id, name, api_key FROM cluster_keys")).one()
        assert (key.cluster_id, key.name, key.api_key) == (cluster.id, "Основной ключ", "a2V5")
        assert conn.execute(text("SELECT key_id FROM tasks")).scalar() == key.id
        assert {"user_id", "user_name", "cluster_name", "key_name"} <= _columns(conn, "runs")
        assert "es_connection" not in _tables(conn)


def test_migration_from_v2_clusters_with_api_key(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'v2.db'}")
    with eng.begin() as conn:  # схема второй версии: ключ в кластере, задача ссылается на кластер
        conn.execute(text("CREATE TABLE clusters (id INTEGER PRIMARY KEY, name VARCHAR(100) UNIQUE, "
                          "url VARCHAR(2000), api_key TEXT, verify_tls BOOLEAN, is_default BOOLEAN, "
                          "created_at DATETIME, updated_at DATETIME)"))
        conn.execute(text("CREATE TABLE tasks (id INTEGER PRIMARY KEY, name VARCHAR(200), "
                          "cluster_id INTEGER REFERENCES clusters(id))"))
        conn.execute(text("CREATE TABLE runs (id INTEGER PRIMARY KEY, task_id INTEGER, cluster_name VARCHAR(100))"))
        conn.execute(text("INSERT INTO clusters VALUES (1, 'prod', 'https://prod:9200', 'cHJvZA==', 1, 1, NULL, NULL)"))
        conn.execute(text("INSERT INTO clusters VALUES (2, 'test', 'http://test:9200', NULL, 1, 0, NULL, NULL)"))
        conn.execute(text("INSERT INTO tasks VALUES (1, 'prod task', 1), (2, 'test task', 2)"))
    Base.metadata.create_all(eng)
    migrate(eng)
    migrate(eng)
    with eng.connect() as conn:
        assert "api_key" not in _columns(conn, "clusters")  # секрет больше не хранится в кластере
        keys = {r.cluster_id: r for r in conn.execute(text("SELECT id, cluster_id, api_key FROM cluster_keys"))}
        assert keys[1].api_key == "cHJvZA==" and keys[2].api_key is None and len(keys) == 2
        tasks = dict(conn.execute(text("SELECT id, key_id FROM tasks")).all())
        assert tasks == {1: keys[1].id, 2: keys[2].id}
        assert conn.execute(text("SELECT COUNT(*) FROM tasks WHERE cluster_id IS NOT NULL")).scalar() == 0
