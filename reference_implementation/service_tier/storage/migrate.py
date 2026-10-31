"""Basit, ileri yönlü SQL migration çalıştırıcısı.

`migrations/` içindeki `NNN_ad.sql` dosyaları ada göre sıralanır ve
uygulanmamış olanlar tek transaction içinde çalıştırılır. Uygulanan sürümler
`schema_migrations` tablosuna yazılır, bu yüzden tekrar çalıştırmak güvenlidir.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import List

from service_tier.storage.pool import connection

logger = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"

_BOOTSTRAP = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     TEXT        PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""


def _migration_files() -> List[Path]:
    return sorted(MIGRATIONS_DIR.glob("*.sql"))


def applied_versions() -> List[str]:
    with connection(commit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(_BOOTSTRAP)
            cur.execute("SELECT version FROM schema_migrations ORDER BY version")
            return [row[0] for row in cur.fetchall()]


def run_migrations() -> List[str]:
    """Bekleyen migration'ları uygular ve uygulananların adlarını döndürür."""
    done = set(applied_versions())
    newly: List[str] = []

    for path in _migration_files():
        version = path.stem
        if version in done:
            continue
        sql = path.read_text(encoding="utf-8")
        with connection(commit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(sql)
                cur.execute(
                    "INSERT INTO schema_migrations (version) VALUES (%s)", (version,)
                )
        newly.append(version)
        logger.info("Migration uygulandı: %s", version)

    if not newly:
        logger.info("Şema güncel (%d migration)", len(done))
    return newly
