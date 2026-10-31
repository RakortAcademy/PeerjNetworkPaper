"""
Otomatik CVE güncellemesi.

Arka planda dönen bir zamanlayıcı, `CVE_SYNC_INTERVAL_HOURS` aralığıyla resmi
cvelistV5 deposunu çeker ve yalnızca değişen kayıtları veritabanına yazar.
Panelden elle de tetiklenebilir (`POST /admin/sync`).

Aynı anda tek bir güncelleme çalışır; ikinci istek reddedilir.
"""
from __future__ import annotations

import logging
import threading
from typing import Callable, List, Optional, Tuple

logger = logging.getLogger(__name__)

_thread: Optional[threading.Thread] = None
_stop = threading.Event()
_running = threading.Lock()


def is_running() -> bool:
    return _running.locked()


# Seam: the production module called five concrete acquisition functions here
# (cvelistV5 ingest under the lock, then NVD CPE, OSV, KEV/EPSS and endoflife.date
# through `_sync_source`). Those modules (feed acquisition modules for cvelistV5, NVD, OSV,
# `risk.py`, `lifecycle.py`) acquire public feeds into the corpus store and are
# not part of this package; feeds are registered instead. Scheduler, trigger,
# start/stop and the error isolation of `_sync_source` are the original code.
FEEDS: List[Tuple[str, Callable[[], dict], str]] = []


def register_feed(label: str, run: Callable[[], dict], count_key: str) -> None:
    """Register a feed refresher; the first registered feed is the primary one."""
    FEEDS.append((label, run, count_key))


def _run_once(full: bool = False) -> None:
    if not FEEDS:
        logger.info("Kayıtlı besleme modülü yok — güncelleme atlandı")
        return
    if not _running.acquire(blocking=False):
        logger.info("CVE güncellemesi zaten çalışıyor, atlanıyor")
        return
    try:
        label, run, count_key = FEEDS[0]
        result = run() or {}
        logger.info("%s güncellemesi tamamlandı — %d satır", label, result.get(count_key, 0))
    except Exception:
        logger.exception("CVE güncellemesi başarısız")
    finally:
        _running.release()

    # Yardımcı kaynaklar ayrı ayrı denenir ve HİÇBİRİ taramayı durdurmaz.
    for label, run, count_key in FEEDS[1:]:
        _sync_source(label, run, count_key)


def _sync_source(label: str, run, count_key: str) -> None:
    """Yardımcı kaynağı günceller; hatası yalnızca uyarı üretir.

    NVD sık sık 503 döndürüyor, OSV indirmesi ağ hatasıyla düşebiliyor. Bunlar
    için taramayı ya da zamanlayıcıyı durdurmak orantısız.
    """
    try:
        result = run() or {}
        logger.info(
            "%s güncellemesi tamamlandı — %d satır", label, result.get(count_key, 0)
        )
    except Exception:
        logger.warning("%s güncellemesi başarısız (tarama etkilenmez)", label, exc_info=True)


def trigger(full: bool = False) -> bool:
    """Güncellemeyi arka planda başlatır. Zaten çalışıyorsa False döner."""
    if is_running():
        return False
    threading.Thread(
        target=_run_once, kwargs={"full": full}, name="cve-sync-manual", daemon=True
    ).start()
    return True


def _scheduler_loop(interval_hours: float, run_on_start: bool) -> None:
    logger.info("CVE güncelleme zamanlayıcısı çalışıyor (her %.1f saatte bir)", interval_hours)
    if run_on_start:
        _run_once()
    while not _stop.wait(interval_hours * 3600):
        _run_once()
    logger.info("CVE güncelleme zamanlayıcısı durdu")


def start(interval_hours: float, run_on_start: bool = False) -> None:
    """Zamanlayıcıyı başlatır. `interval_hours <= 0` ise kapalıdır."""
    global _thread
    if _thread is not None or interval_hours <= 0:
        if interval_hours <= 0:
            logger.info("Otomatik CVE güncellemesi kapalı (CVE_SYNC_INTERVAL_HOURS=0)")
        return
    _stop.clear()
    _thread = threading.Thread(
        target=_scheduler_loop,
        args=(interval_hours, run_on_start),
        name="cve-sync-scheduler",
        daemon=True,
    )
    _thread.start()


def stop(timeout: float = 5.0) -> None:
    global _thread
    _stop.set()
    if _thread is not None:
        _thread.join(timeout=timeout)
        _thread = None
