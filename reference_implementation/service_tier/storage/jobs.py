"""Job kuyruğunun PostgreSQL kalıcılığı.

Job'lar ve kalemleri veritabanında tutulur; API yeniden başlasa bile durum ve
sonuçlar okunabilir kalır. Yarım kalmış (RUNNING) job'lar açılışta PENDING'e
döndürülür, böylece worker onları baştan alır.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional, Sequence

from psycopg2.extras import Json, execute_values

from service_tier.storage.pool import cursor

logger = logging.getLogger(__name__)


def create_job(items: Sequence[Dict[str, str]]) -> str:
    """Yeni bir job ve kalemlerini yazar; job id döndürür."""
    job_id = str(uuid.uuid4())
    with cursor(commit=True) as cur:
        cur.execute(
            "INSERT INTO jobs (id, status, total) VALUES (%s, 'PENDING', %s)",
            (job_id, len(items)),
        )
        execute_values(
            cur,
            """
            INSERT INTO job_items
                (job_id, position, product, version, platform, vendor, operating_system)
            VALUES %s
            """,
            [
                (
                    job_id, i, it["product"], it["version"],
                    it.get("platform") or "", it.get("vendor") or "",
                    it.get("operating_system") or "",
                )
                for i, it in enumerate(items)
            ],
        )
    return job_id


def claim_next_job() -> Optional[str]:
    """Sıradaki PENDING job'ı RUNNING'e çevirip id'sini döndürür.

    `FOR UPDATE SKIP LOCKED` sayesinde birden çok worker aynı job'ı almaz.
    """
    with cursor(commit=True) as cur:
        cur.execute(
            """
            WITH next_job AS (
                SELECT id FROM jobs
                 WHERE status = 'PENDING'
                 ORDER BY created_at
                 FOR UPDATE SKIP LOCKED
                 LIMIT 1
            )
            UPDATE jobs
               SET status = 'RUNNING',
                   started_at = coalesce(jobs.started_at, now()),
                   attempts = jobs.attempts + 1,
                   heartbeat_at = now()
              FROM next_job
             WHERE jobs.id = next_job.id
         RETURNING jobs.id
            """
        )
        row = cur.fetchone()
    return str(row["id"]) if row else None


def pending_items(job_id: str) -> List[Dict[str, Any]]:
    """Job'ın henüz sonuçlanmamış kalemleri."""
    with cursor() as cur:
        cur.execute(
            """
            SELECT position, product, version, platform, vendor, operating_system
              FROM job_items
             WHERE job_id = %s AND result IS NULL AND error IS NULL
             ORDER BY position
            """,
            (job_id,),
        )
        return [dict(r) for r in cur.fetchall()]


def save_item_result(
    job_id: str,
    position: int,
    *,
    result: Optional[Dict[str, Any]] = None,
    cached: bool = False,
    error: Optional[str] = None,
) -> None:
    """Bir kalemin sonucunu yazar ve job sayaçlarını günceller."""
    with cursor(commit=True) as cur:
        cur.execute(
            """
            UPDATE job_items
               SET status = %s, result = %s, cached = %s, error = %s
             WHERE job_id = %s AND position = %s
            """,
            (
                (result or {}).get("status") if result else None,
                Json(result) if result is not None else None,
                cached,
                error,
                job_id,
                position,
            ),
        )
        column = "failed" if error else "completed"
        cur.execute(
            f"UPDATE jobs SET {column} = {column} + 1 WHERE id = %s", (job_id,)
        )


def finish_job(job_id: str, error: Optional[str] = None) -> None:
    with cursor(commit=True) as cur:
        cur.execute(
            """
            UPDATE jobs
               SET status = %s, error = %s, finished_at = now()
             WHERE id = %s
            """,
            ("FAILED" if error else "DONE", error, job_id),
        )


def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    with cursor() as cur:
        cur.execute("SELECT * FROM jobs WHERE id = %s", (job_id,))
        row = cur.fetchone()
    return dict(row) if row else None


def get_job_items(job_id: str) -> List[Dict[str, Any]]:
    with cursor() as cur:
        cur.execute(
            """
            SELECT position, product, version, platform, vendor, operating_system,
                   status, cached, result, error
              FROM job_items
             WHERE job_id = %s
             ORDER BY position
            """,
            (job_id,),
        )
        return [dict(r) for r in cur.fetchall()]


MAX_JOB_ATTEMPTS = 5


def requeue_stale_jobs() -> int:
    """Açılışta yarım kalan RUNNING job'ları kuyruğa geri alır.

    Süreç öldüğünde job veritabanında RUNNING kalır. Tamamlanmış kalemlerin
    sonuçları `job_items` içinde durduğu için job baştan değil KALDIĞI YERDEN
    devam eder — `pending_items` yalnızca sonuçlanmamış kalemleri verir.

    `started_at` korunur (job gerçekten o an başladı) ve deneme sınırını aşan
    job'lar sonsuza dek dönmesin diye FAILED işaretlenir.
    """
    with cursor(commit=True) as cur:
        cur.execute(
            """
            UPDATE jobs
               SET status = 'FAILED',
                   error = 'Deneme sınırı aşıldı — job yarıda kaldı',
                   finished_at = now()
             WHERE status = 'RUNNING' AND attempts >= %s
            """,
            (MAX_JOB_ATTEMPTS,),
        )
        cur.execute(
            """
            UPDATE jobs
               SET status = 'PENDING', heartbeat_at = NULL
             WHERE status = 'RUNNING'
            """
        )
        return cur.rowcount or 0


def requeue_job(job_id: str) -> bool:
    """Yarıda kalan bir job'ı yeniden denenmek üzere kuyruğa koyar.

    Geçici bir hata (DB bağlantısı, model yüklemesi) koca bir envanter job'ını
    kalıcı olarak FAILED yapmamalı. Deneme sınırına ulaşılmışsa False döner ve
    çağıran job'ı gerçekten başarısız sayar.
    """
    with cursor(commit=True) as cur:
        cur.execute(
            """
            UPDATE jobs
               SET status = 'PENDING', heartbeat_at = NULL
             WHERE id = %s AND attempts < %s
            """,
            (job_id, MAX_JOB_ATTEMPTS),
        )
        return bool(cur.rowcount)


def heartbeat(job_id: str) -> None:
    """RUNNING job'ın ilerlediğini işaretler (izleme için)."""
    with cursor(commit=True) as cur:
        cur.execute("UPDATE jobs SET heartbeat_at = now() WHERE id = %s", (job_id,))


def queue_stats() -> Dict[str, Any]:
    """Kuyruk durumu — panel için."""
    with cursor() as cur:
        cur.execute(
            """
            SELECT status, count(*) AS n, coalesce(sum(total), 0) AS items
              FROM jobs
             GROUP BY status
            """
        )
        by_status = {r["status"]: {"jobs": int(r["n"]), "items": int(r["items"])}
                     for r in cur.fetchall()}
        cur.execute(
            """
            SELECT count(*) AS n
              FROM jobs
             WHERE created_at > now() - interval '24 hours'
            """
        )
        last_day = int((cur.fetchone() or {}).get("n") or 0)
    return {"by_status": by_status, "last_24h": last_day}


def recent_jobs(limit: int = 20) -> List[Dict[str, Any]]:
    with cursor() as cur:
        cur.execute(
            """
            SELECT id, status, total, completed, failed, created_at, finished_at
              FROM jobs
             ORDER BY created_at DESC
             LIMIT %s
            """,
            (limit,),
        )
        return [dict(r) for r in cur.fetchall()]
