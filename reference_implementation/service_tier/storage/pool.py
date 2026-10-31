"""PostgreSQL bağlantı havuzu."""
from __future__ import annotations

import logging
import threading
from contextlib import contextmanager
from typing import Iterator, Optional

import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.pool import ThreadedConnectionPool

from service_tier.config import get_settings

logger = logging.getLogger(__name__)

_pool: Optional[ThreadedConnectionPool] = None
_lock = threading.Lock()


def init_pool() -> None:
    """Havuzu kurar. Zaten kuruluysa bir şey yapmaz."""
    global _pool
    if _pool is not None:
        return
    settings = get_settings()
    with _lock:
        if _pool is not None:
            return
        _pool = ThreadedConnectionPool(
            settings.pg_min_conn,
            settings.pg_max_conn,
            **settings.dsn_kwargs(),
        )
        logger.info(
            "PostgreSQL havuzu hazır: %s@%s:%s/%s",
            settings.pg_user, settings.pg_host, settings.pg_port, settings.pg_database,
        )


def close_pool() -> None:
    global _pool
    with _lock:
        if _pool is not None:
            _pool.closeall()
            _pool = None


@contextmanager
def connection(*, commit: bool = False) -> Iterator[psycopg2.extensions.connection]:
    """Havuzdan bir bağlantı ödünç alır ve her durumda geri verir."""
    if _pool is None:
        init_pool()
    assert _pool is not None
    conn = _pool.getconn()
    try:
        yield conn
        if commit:
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        _pool.putconn(conn)


@contextmanager
def cursor(*, commit: bool = False, dict_rows: bool = True):
    """Sözlük satırları döndüren imleç."""
    with connection(commit=commit) as conn:
        factory = RealDictCursor if dict_rows else None
        with conn.cursor(cursor_factory=factory) as cur:
            yield cur


def ping() -> bool:
    """Veritabanı erişilebilir mi?"""
    try:
        with cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
        return True
    except Exception as exc:  # pragma: no cover - sağlık kontrolü
        logger.warning("PostgreSQL erişilemiyor: %s", exc)
        return False
