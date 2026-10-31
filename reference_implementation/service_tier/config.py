"""Ortam değişkenlerinden okunan uygulama ayarları."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from typing import List


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


def _env_list(name: str) -> List[str]:
    return [v.strip() for v in (os.environ.get(name) or "").split(",") if v.strip()]


# Not: her alan `default_factory` kullanır. Düz varsayılanlar sınıf tanımlanırken
# bir kez hesaplanır ve sonradan set edilen ortam değişkenlerini görmez.
@dataclass(frozen=True)
class Settings:
    # --- API ---
    api_keys: List[str] = field(default_factory=lambda: _env_list("API_KEYS"))
    cors_origins: List[str] = field(default_factory=lambda: _env_list("CORS_ORIGINS"))
    # Yönetim paneli anahtarı. Boşsa /admin uçları kapalıdır.
    admin_token: str = field(default_factory=lambda: os.environ.get("ADMIN_TOKEN", "").strip())
    # Panelin statik dosyalarını API'nin kendisi sunsun mu (nginx yoksa kullanışlı).
    serve_admin_ui: bool = field(default_factory=lambda: _env_bool("SERVE_ADMIN_UI", True))

    # --- PostgreSQL ---
    pg_host: str = field(default_factory=lambda: os.environ.get("PGHOST", "127.0.0.1"))
    pg_port: int = field(default_factory=lambda: _env_int("PGPORT", 5432))
    pg_database: str = field(default_factory=lambda: os.environ.get("PGDATABASE", "refimpl"))
    pg_user: str = field(default_factory=lambda: os.environ.get("PGUSER", "postgres"))
    pg_password: str = field(default_factory=lambda: os.environ.get("PGPASSWORD", ""))
    pg_min_conn: int = field(default_factory=lambda: _env_int("PG_MIN_CONN", 1))
    pg_max_conn: int = field(default_factory=lambda: _env_int("PG_MAX_CONN", 8))
    pg_connect_timeout: int = field(default_factory=lambda: _env_int("PGCONNECT_TIMEOUT", 5))

    # --- Önbellek ---
    cache_enabled: bool = field(default_factory=lambda: _env_bool("CACHE_ENABLED", True))
    cache_ttl_days: int = field(default_factory=lambda: _env_int("CACHE_TTL_DAYS", 7))

    # --- Job kuyruğu ---
    job_workers: int = field(default_factory=lambda: _env_int("JOB_WORKERS", 1))
    max_batch_items: int = field(default_factory=lambda: _env_int("MAX_BATCH_ITEMS", 500))
    max_job_items: int = field(default_factory=lambda: _env_int("MAX_JOB_ITEMS", 50000))

    # --- Tarama motoru (goscan) ---
    # Karar mantığı Go tarafında çalışıyor; gelen istekler buraya gider.
    # Python motoru (`refimpl/`) kaynak olarak duruyor ve altın küme
    # değerlendirmesi hâlâ onu kullanıyor, ama istek yolunda değil.
    goscan_url: str = field(
        default_factory=lambda: os.environ.get("GOSCAN_URL", "http://127.0.0.1:8390").strip()
    )
    # Tek toplu tarama isteği için üst süre. Büyük envanterlerde (50 bin kalem)
    # tarama dakikalar sürebiliyor; kısa bir zaman aşımı işi yarıda keser.
    goscan_timeout_seconds: float = field(
        default_factory=lambda: _env_float("GOSCAN_TIMEOUT_SECONDS", 900.0)
    )

    # --- Model ---
    warm_model_on_startup: bool = field(
        default_factory=lambda: _env_bool("WARM_MODEL_ON_STARTUP", True)
    )

    # --- CVE veri güncellemesi ---
    # 0 = kapalı. Resmi cvelistV5 deposundan yalnızca değişen kayıtlar çekilir.
    cve_sync_interval_hours: float = field(
        default_factory=lambda: _env_float("CVE_SYNC_INTERVAL_HOURS", 12.0)
    )
    cve_sync_on_startup: bool = field(
        default_factory=lambda: _env_bool("CVE_SYNC_ON_STARTUP", False)
    )

    @property
    def auth_enabled(self) -> bool:
        return bool(self.api_keys)

    def dsn_kwargs(self) -> dict:
        return {
            "host": self.pg_host,
            "port": self.pg_port,
            "dbname": self.pg_database,
            "user": self.pg_user,
            "password": self.pg_password,
            "connect_timeout": self.pg_connect_timeout,
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
