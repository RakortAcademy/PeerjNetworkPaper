"""Sağlık kontrolü — kimlik doğrulaması gerektirmez."""
from __future__ import annotations

from fastapi import APIRouter

from service_tier.backend.schemas import HealthResponse
from service_tier.backend.services import scanner as scanner_service
from service_tier.storage import cache, pool

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    from service_tier.backend.services import goscan

    db_ok = pool.ping()
    # Motor ayakta değilse hiçbir tarama yapılamaz — yedeğe düşme YOK, bu
    # yüzden ayaktalık `ok` demenin ön koşulu.
    engine_ok = goscan.available()
    # Seam: the corpus store module  is not part of this
    # package; the engine reports its own corpus state through /health.
    cve_stats: dict = {}
    cve_db_ok = engine_ok

    return HealthResponse(
        status="ok" if (db_ok and engine_ok and cve_db_ok) else "degraded",
        model_loaded=scanner_service.model_ready(),
        model_version=scanner_service.model_version(),
        database=db_ok,
        cve_db=cve_db_ok,
        cve_store=cve_stats,
        cache=cache.stats() if db_ok else {},
    )
