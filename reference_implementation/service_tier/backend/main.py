"""
CVE Scanner API — uygulama adı + sürümden CVE açıklarını bulur.

Çalıştırma (reference implementation):
    uvicorn service_tier.backend.main:app --host 127.0.0.1 --port 8000
"""
from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from service_tier.backend.routers import health, jobs, scan, scans
from service_tier.backend.services import cve_updater
from service_tier.backend.services.goscan import GoscanUnavailable
from service_tier.backend.services import scanner as scanner_service
from service_tier.backend.services import worker
from service_tier.config import get_settings
from service_tier.storage import pool
from service_tier.storage.jobs import requeue_stale_jobs
from service_tier.storage.migrate import run_migrations

logger = logging.getLogger(__name__)

def _configure_logging() -> None:
    """Console logging only (seam: the original also wrote `logs/api.log` next to
    the production tree)."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
        handlers=[logging.StreamHandler()],
        force=True,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    _configure_logging()
    settings = get_settings()

    pool.init_pool()
    run_migrations()

    if not settings.api_keys:
        from service_tier.storage import api_keys as key_store

        if not key_store.any_active():
            logger.warning(
                "Tanımlı API anahtarı yok — kimlik doğrulama KAPALI. "
                "Panelden anahtar üretin ya da API_KEYS ayarlayın."
            )
    if not settings.admin_token:
        logger.warning("ADMIN_TOKEN boş — yönetim paneli kapalı")

    requeued = requeue_stale_jobs()
    if requeued:
        logger.info("%d yarım kalmış job kuyruğa geri alındı", requeued)

    # Karar mantığı değiştiğinde eski önbellek kayıtları erişilemez olur; TTL'i
    # de geçmişlerse temizlenir. Önbellek anahtarı model + mantık damgasıdır,
    # bu yüzden bir kod düzeltmesinden sonra API eski kararı döndürmez.
    try:
        from service_tier.storage import cache as scan_cache

        removed = scan_cache.purge_stale(
            scanner_service.engine_version(), settings.cache_ttl_days
        )
        if removed:
            logger.info("%d eskimiş önbellek kaydı silindi", removed)
    except Exception:
        logger.warning("Önbellek temizliği yapılamadı", exc_info=True)

    if settings.warm_model_on_startup:
        try:
            scanner_service.warm_up()
        except Exception as exc:
            # Model yoksa API yine ayağa kalksın; /health durumu 'degraded' gösterir.
            logger.error("Model yüklenemedi: %s", exc)

    worker.start(settings.job_workers)
    cve_updater.start(settings.cve_sync_interval_hours, settings.cve_sync_on_startup)
    try:
        yield
    finally:
        cve_updater.stop()
        worker.stop()
        pool.close_pool()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="CVE Scanner API",
        version="2.1.0",
        summary="Uygulama adı ve sürümüne göre CVE açıklarını tespit eder.",
        description=(
            "BiLSTM-CRF tabanlı çıkarım + bulanık ürün eşleme + sürüm aralığı "
            "karşılaştırması. Tarama istekleri varsayılan olarak kuyruğa alınır ve "
            "bir `job_id` döner; sonuçlar PostgreSQL'de önbelleklenir."
        ),
        lifespan=lifespan,
    )

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_methods=["GET", "POST", "DELETE"],
            allow_headers=["*"],
        )

    @app.middleware("http")
    async def record_usage(request: Request, call_next):
        """Her tarama/job isteğini süre ve durumla kaydeder (panel grafikleri)."""
        started = time.perf_counter()
        response = await call_next(request)
        if request.url.path.startswith(("/scan", "/jobs")):
            from service_tier.storage import api_keys as key_store

            caller = getattr(request.state, "caller", None)
            key_store.log_request(
                api_key_id=getattr(caller, "key_id", None),
                path=request.url.path,
                method=request.method,
                status_code=response.status_code,
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        return response

    # Tarama motoru (goscan) ayakta değilse istek 503 döner, 500 değil: bu bir
    # kod hatası değil bağımlılık kesintisidir ve çağıran tarafın yeniden
    # denemesi anlamlıdır. Yedeğe düşme YOK — sessizce başka bir motorla karar
    # vermek, iki motoru aynı anda üretimde tutmak demek olurdu.
    @app.exception_handler(GoscanUnavailable)
    async def _engine_unavailable(request: Request, exc: GoscanUnavailable):
        logger.error("Tarama motoruna ulaşılamadı: %s", exc)
        return JSONResponse(
            status_code=503,
            content={"detail": f"Tarama motoru şu anda erişilemiyor: {exc}"},
        )

    app.include_router(health.router)
    app.include_router(scan.router)
    app.include_router(jobs.router)
    app.include_router(scans.router)  # scan-retrieval endpoints of the admin router (Table 8)

    # Seam: the management panel (admin-ui static files, key management, corpus
    # browser, logs, sync trigger) is not part of this package.

    return app


app = create_app()
