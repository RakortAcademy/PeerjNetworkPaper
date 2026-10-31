"""Asenkron toplu tarama uçları."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Response, status
from starlette.concurrency import run_in_threadpool

from service_tier.config import get_settings
from service_tier.backend.schemas import (
    JobCreateRequest,
    JobCreateResponse,
    JobItemResult,
    JobResultResponse,
    JobStatusResponse,
)
from service_tier.backend.security import require_api_key
from service_tier.storage import jobs as job_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/jobs", tags=["jobs"], dependencies=[Depends(require_api_key)])


def _job_or_404(job_id: str) -> dict:
    job = job_store.get_job(job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job bulunamadı")
    return job


@router.post("", response_model=JobCreateResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_job(request: JobCreateRequest) -> JobCreateResponse:
    """Toplu taramayı kuyruğa alır. Sonuç `GET /jobs/{id}/result` ile alınır."""
    settings = get_settings()
    if len(request.items) > settings.max_job_items:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Bir job en fazla {settings.max_job_items} kalem alır",
        )

    items = [
        {"product": i.product, "version": i.version, "platform": i.platform or ""}
        for i in request.items
    ]
    job_id = await run_in_threadpool(job_store.create_job, items)
    return JobCreateResponse(job_id=job_id, status="PENDING", total=len(items))


@router.get("/{job_id}", response_model=JobStatusResponse)
async def job_status(job_id: str) -> JobStatusResponse:
    job = await run_in_threadpool(_job_or_404, job_id)
    return JobStatusResponse(job_id=str(job["id"]), **{
        k: job[k]
        for k in ("status", "total", "completed", "failed", "attempts", "error",
                  "created_at", "started_at", "finished_at")
    })


@router.get(
    "/{job_id}/result",
    response_model=JobResultResponse,
    responses={202: {"description": "Job hâlâ çalışıyor — daha sonra tekrar deneyin"}},
)
async def job_result(job_id: str, response: Response) -> JobResultResponse | Response:
    job = await run_in_threadpool(_job_or_404, job_id)

    if job["status"] in ("PENDING", "RUNNING"):
        # Henüz bitmedi: istemci polling yapabilsin diye 202 döndür.
        return Response(status_code=status.HTTP_202_ACCEPTED)

    rows = await run_in_threadpool(job_store.get_job_items, job_id)
    return JobResultResponse(
        job_id=str(job["id"]),
        status=job["status"],
        total=job["total"],
        completed=job["completed"],
        failed=job["failed"],
        items=[JobItemResult(**row) for row in rows],
    )
