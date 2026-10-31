"""Scan-result retrieval: summary without finding lists, then paginated findings.

These are the three retrieval endpoints of the production admin router
(`backend/routers/admin.py`, functions `list_scans`, `scan_detail`,
`scan_findings`), copied verbatim with their prefix, authentication dependency
and query validation. The rest of that router (API-key management, manual
scans, corpus browser, logs, feed trigger) is not part of this package. The
response-size failure that motivated the split is described in the manuscript,
Section 7, "Response Size Is a Transport Constraint" (Table 8); the slicing
itself is performed in the store (`service_tier/storage/cache.py`,
`get_scan_summary` / `get_scan_findings`).
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from starlette.concurrency import run_in_threadpool

from service_tier.backend.schemas import FindingPage, ScanDetail, ScanListResponse
from service_tier.backend.security import require_admin
from service_tier.storage import cache

router = APIRouter(prefix="/admin", tags=["scans"], dependencies=[Depends(require_admin)])


@router.get("/scans", response_model=ScanListResponse)
async def list_scans(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    status: Optional[str] = Query(None, pattern="^(THREAT|SAFE|UNCERTAIN|NOT_FOUND)$"),
    search: Optional[str] = Query(None, max_length=120),
) -> ScanListResponse:
    """Önbellekteki tarama sonuçlarını en yeniden eskiye listeler."""
    data = await run_in_threadpool(cache.list_scans, limit, offset, status, search)
    return ScanListResponse(**data)


@router.get("/scans/{scan_id}", response_model=ScanDetail)
async def scan_detail(scan_id: int) -> ScanDetail:
    """Bir taramanın özeti — bulgu sayıları dahil, listeler hariç.

    Listeler `/admin/scans/{id}/findings` ile sayfalanır; tek tarama binlerce
    bulgu taşıyabiliyor ve tamamını göndermek tarayıcıyı kilitliyordu.
    """
    row = await run_in_threadpool(cache.get_scan_summary, scan_id)
    if not row:
        raise HTTPException(status_code=404, detail="Tarama kaydı bulunamadı")
    return ScanDetail(**row)


@router.get("/scans/{scan_id}/findings", response_model=FindingPage)
async def scan_findings(
    scan_id: int,
    bucket: str = Query("threats", pattern="^(threats|uncertain|safe)$"),
    limit: int = Query(25, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> FindingPage:
    """Taramanın bulgularından tek sayfa (tehdit / kesin değil / etkilemiyor)."""
    page = await run_in_threadpool(cache.get_scan_findings, scan_id, bucket, limit, offset)
    if page is None:
        raise HTTPException(status_code=404, detail="Tarama kaydı bulunamadı")
    return FindingPage(**page)
