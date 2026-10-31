"""Arka plan job worker'ı.

Kuyruktaki job'lar sırayla alınır ve kalemleri tek tek taranır. Her kalemin
sonucu anında veritabanına yazılır; bu yüzden uzun bir job'ın ilerleyişi
`GET /jobs/{id}` ile izlenebilir ve süreç yeniden başlarsa tamamlanan kalemler
korunur.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Dict, List

from service_tier.storage import jobs as job_store

logger = logging.getLogger(__name__)

_IDLE_SLEEP = 2.0

_threads: List[threading.Thread] = []
_stop = threading.Event()


class _Item:
    """`planner` alan adlarıyla çalışır; job kalemi satırını ona uydurur."""

    __slots__ = ("product", "version", "platform", "vendor", "operating_system", "position")

    def __init__(self, row: dict) -> None:
        self.product = row["product"]
        self.version = row["version"]
        self.platform = row.get("platform") or None
        self.vendor = row.get("vendor") or None
        self.operating_system = row.get("operating_system") or None
        self.position = row["position"]


def _process_job(job_id: str) -> None:
    from refimpl.planning import planner
    from service_tier.backend.services import scanner as scanner_service

    # Yalnızca sonuçlanmamış kalemler gelir; yeniden başlatmadan sonra job
    # kaldığı yerden sürer, tamamlanan kalemler yeniden taranmaz.
    rows = job_store.pending_items(job_id)
    if not rows:
        job_store.finish_job(job_id)
        return

    items = [_Item(r) for r in rows]
    plan = planner.build_plan(items)
    logger.info(
        "Job %s başladı — %d kalem (%d benzersiz, %d yinelenen, %d ürün grubu)",
        job_id, plan.total, len(plan.unique_items), plan.duplicates, plan.products,
    )

    # Benzersiz kalem indeksi -> (sonuç, önbellekten_mi)
    outcomes: Dict[int, tuple] = {}
    # Benzersiz kalem indeksi -> o sonucu paylaşan girdi konumları
    targets = plan.targets_of()

    for group in plan.groups:
        if _stop.is_set():
            logger.info("Job %s kapanış nedeniyle yarıda bırakıldı", job_id)
            return
        sample = plan.unique_items[group.sample_index]
        try:
            scanned = scanner_service.scan_versions(
                sample.product,
                group.versions,
                sample.platform,
                vendor=sample.vendor,
                operating_system=sample.operating_system,
            )
            for target, outcome in zip(group.targets, scanned):
                outcomes[target] = outcome
        except Exception as exc:
            # Bir ürün grubu çökerse yalnızca o gruptaki kalemler hata alır;
            # job'ın geri kalanı taranmaya devam eder.
            logger.exception("Job %s ürün '%s' başarısız", job_id, sample.product)
            for target in group.targets:
                outcomes[target] = (None, str(exc))

        # Grup biter bitmez yazılır: süreç bu noktadan sonra ölürse bu kalemler
        # kalıcıdır ve yeniden başlatmada tekrar taranmaz.
        _persist_group(job_id, items, targets, group, outcomes)
        job_store.heartbeat(job_id)

    job_store.finish_job(job_id)
    logger.info("Job %s tamamlandı", job_id)


def _persist_group(
    job_id: str,
    items: List["_Item"],
    targets: Dict[int, List[int]],
    group,
    outcomes: Dict[int, tuple],
) -> None:
    """Bir ürün grubunun sonuçlarını, yinelenen kopyalar dahil, veritabanına yazar."""
    for unique_idx in group.targets:
        outcome = outcomes.get(unique_idx)
        if outcome is None:
            continue
        result, flag = outcome
        for offset in targets.get(unique_idx, ()):
            position = items[offset].position
            try:
                if result is None:
                    job_store.save_item_result(job_id, position, error=str(flag))
                else:
                    # Yinelenen kalemler taranmadı; sonuç kopyalandı.
                    is_copy = offset != targets[unique_idx][0]
                    job_store.save_item_result(
                        job_id, position, result=result, cached=bool(flag) or is_copy
                    )
            except Exception:
                logger.exception("Job %s kalem %s yazılamadı", job_id, position)


def _worker_loop(name: str) -> None:
    logger.info("Worker %s çalışıyor", name)
    while not _stop.is_set():
        try:
            job_id = job_store.claim_next_job()
        except Exception as exc:
            logger.warning("Kuyruk okunamadı: %s", exc)
            _stop.wait(_IDLE_SLEEP)
            continue

        if not job_id:
            _stop.wait(_IDLE_SLEEP)
            continue

        try:
            _process_job(job_id)
        except Exception as exc:
            # Job'ı hemen FAILED yapma: kalemlerin sonuçları zaten kalıcı, geçici
            # bir hatadan sonra kalan kalemlerle yeniden denenebilir. Deneme
            # sınırı dolduysa gerçekten başarısız sayılır.
            logger.exception("Job %s çöktü", job_id)
            try:
                if job_store.requeue_job(job_id):
                    logger.warning("Job %s yeniden denenmek üzere kuyruğa alındı", job_id)
                else:
                    job_store.finish_job(job_id, error=str(exc))
            except Exception:
                logger.exception("Job %s durumu yazılamadı", job_id)

    logger.info("Worker %s durdu", name)


def start(n_workers: int) -> None:
    """Worker thread'lerini başlatır."""
    if _threads:
        return
    _stop.clear()
    for i in range(max(1, n_workers)):
        name = f"job-worker-{i + 1}"
        t = threading.Thread(target=_worker_loop, args=(name,), name=name, daemon=True)
        t.start()
        _threads.append(t)


def stop(timeout: float = 10.0) -> None:
    """Worker'lara durma sinyali verir ve bitmelerini bekler."""
    _stop.set()
    deadline = time.monotonic() + timeout
    for t in _threads:
        t.join(timeout=max(0.0, deadline - time.monotonic()))
    _threads.clear()
