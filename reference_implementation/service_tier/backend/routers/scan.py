"""
Tarama uçları.

Varsayılan davranış **asenkron**: istek kuyruğa alınır ve hemen bir `job_id`
döner. Sonuç `GET /jobs/{job_id}/result` ile alınır. Bu, büyük envanterlerde
istemcinin bağlantıyı açık tutmasını gerektirmez.

`wait=true` ile senkron çalışır — önbellekte olan sorgular birkaç milisaniyede
döndüğü için tekil kontrollerde kullanışlıdır.
"""
from __future__ import annotations

import logging
import time
from typing import List, Optional, Tuple, Union

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from starlette.concurrency import run_in_threadpool

from service_tier.backend.schemas import (
    ScanItem,
    ScanQueued,
    ScanRequest,
    ScanResponse,
    ScanResult,
)
from service_tier.backend.security import Caller, require_api_key
from refimpl.planning import planner
from service_tier.backend.services import scanner as scanner_service
from service_tier.config import get_settings
from service_tier.storage import jobs as job_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scan", tags=["scan"])


def _to_result(item: ScanItem, raw: dict, cached: bool) -> ScanResult:
    return ScanResult(
        product=item.product,
        version=item.version,
        vendor=item.vendor,
        operating_system=item.operating_system,
        platform=item.platform,
        ambiguous_product=bool(raw.get("ambiguous_product")),
        status=raw.get("status", "NOT_FOUND"),
        safety_score=int(raw.get("safety_score") or 0),
        scanned_cves=int(raw.get("scanned_cves") or 0),
        threats=raw.get("threats") or [],
        uncertain_items=raw.get("uncertain_items") or [],
        safe_reasons=raw.get("safe_reasons") or [],
        decision_summary=raw.get("decision_summary"),
        recommended_upgrade=raw.get("recommended_upgrade"),
        risk_summary=raw.get("risk_summary"),
        support=raw.get("support"),
        scanned_cve_ids=raw.get("scanned_cve_ids") or [],
        model_version=raw.get("model_version"),
        cached=cached,
    )


def _scan_items(items: List[ScanItem], use_cache: bool) -> Tuple[List[ScanResult], dict]:
    """Listeyi plana çevirip tarar; sonuçlar girdi sırasında döner.

    Plan iki tekrarı da ele alır: birebir yinelenen kayıtlar tek kez taranıp
    kopyalanır, aynı ürünün farklı sürümleri ise ayrı ayrı karar alır ama
    pahalı hazırlığı paylaşır.
    """
    plan = planner.build_plan(items)
    # Gruplar paralel taranır; ölçümde sürenin %56'sı PostgreSQL beklemesi ve
    # o bölüm gerçekten üst üste biniyor (bkz. `scan_groups`).
    scanned = scanner_service.scan_groups(plan.groups, plan.unique_items, use_cache)

    results: List[ScanResult] = []
    emitted: set = set()
    for item, idx in zip(items, plan.assignment):
        raw, cached = scanned[idx]
        # Aynı sonucu ikinci kez veren kalem taranmamıştır; çağıran bunu
        # ayırt edebilsin diye `cached` işaretlenir.
        is_copy = idx in emitted
        emitted.add(idx)
        results.append(_to_result(item, raw, cached or is_copy))
    return results, plan.summary()


@router.post(
    "",
    response_model=Union[ScanQueued, ScanResponse],
    summary="Uygulama(lar) için CVE taraması",
    responses={
        202: {"model": ScanQueued, "description": "Kuyruğa alındı — job_id ile sorgulayın"},
        200: {"model": ScanResponse, "description": "wait=true ile senkron sonuç"},
    },
)
async def scan(
    request: ScanRequest,
    response: Response,
    caller: Caller = Depends(require_api_key),
    wait: bool = Query(
        False,
        description="true ise sonucu bekler; false (varsayılan) job_id döndürür",
    ),
):
    """Tek kalem (`{"product": ..., "version": ...}`) ya da çoklu
    (`{"items": [...]}`) gövde kabul eder."""
    items = request.normalized_items()
    if not items:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="'items' listesi ya da 'product' + 'version' alanları gerekli",
        )

    settings = get_settings()

    if not wait:
        if len(items) > settings.max_job_items:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Bir istek en fazla {settings.max_job_items} kalem alabilir",
            )
        payload = [
            {
                "product": i.product,
                "version": i.version,
                "platform": i.platform or "",
                "vendor": i.vendor or "",
                "operating_system": i.operating_system or "",
            }
            for i in items
        ]
        job_id = await run_in_threadpool(job_store.create_job, payload)
        response.status_code = status.HTTP_202_ACCEPTED
        return ScanQueued(
            job_id=job_id,
            status="PENDING",
            total=len(items),
            poll_url=f"/jobs/{job_id}",
            result_url=f"/jobs/{job_id}/result",
        )

    if len(items) > settings.max_batch_items:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=(
                f"Senkron tarama en fazla {settings.max_batch_items} kalem alır "
                f"({len(items)} gönderildi). Daha büyük listeler için wait parametresini "
                f"kullanmayın; istek kuyruğa alınır."
            ),
        )

    started = time.perf_counter()
    # Tarama senkron ve CPU/GPU-bağımlı; event loop'u bloke etmemek için ayrı thread.
    results, plan_summary = await run_in_threadpool(_scan_items, items, request.use_cache)
    return ScanResponse(
        results=results,
        elapsed_ms=int((time.perf_counter() - started) * 1000),
        cached_count=sum(1 for r in results if r.cached),
        inventory=plan_summary,
    )
