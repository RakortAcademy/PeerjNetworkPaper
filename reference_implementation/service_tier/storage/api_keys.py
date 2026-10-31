"""
API anahtarı deposu.

Anahtarın kendisi asla saklanmaz; yalnızca SHA-256 özeti tutulur. Bu yüzden
düz anahtar sadece oluşturulduğu anda bir kez döndürülür — kaybedilirse
yenisi üretilmelidir. Panelde tanımak için ilk karakterler (prefix) ayrıca
saklanır.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime
from typing import Any, Dict, List, Optional

from service_tier.storage.pool import cursor

logger = logging.getLogger(__name__)

KEY_PREFIX = "demo_"
_PREFIX_DISPLAY_LEN = len(KEY_PREFIX) + 6


def hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def generate_key() -> str:
    """Yeni bir anahtar üretir (URL-güvenli, 32 bayt entropi)."""
    return f"{KEY_PREFIX}{secrets.token_urlsafe(32)}"


def create(
    name: str,
    note: str = "",
    expires_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Yeni anahtar oluşturur. Düz anahtar YALNIZCA burada döner."""
    raw = generate_key()
    with cursor(commit=True) as cur:
        cur.execute(
            """
            INSERT INTO api_keys (name, key_hash, key_prefix, note, expires_at)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id, name, key_prefix, active, note, request_count,
                      created_at, last_used_at, expires_at
            """,
            (name.strip(), hash_key(raw), raw[:_PREFIX_DISPLAY_LEN], note.strip(), expires_at),
        )
        row = dict(cur.fetchone())
    row["key"] = raw  # bir kereye mahsus
    logger.info("Yeni API anahtarı oluşturuldu: %s (%s)", row["name"], row["key_prefix"])
    return row


def verify(raw_key: str) -> Optional[Dict[str, Any]]:
    """Anahtar geçerliyse kaydı döndürür ve kullanım sayacını artırır."""
    if not raw_key:
        return None
    with cursor(commit=True) as cur:
        cur.execute(
            """
            UPDATE api_keys
               SET last_used_at = now(), request_count = request_count + 1
             WHERE key_hash = %s
               AND active
               AND (expires_at IS NULL OR expires_at > now())
         RETURNING id, name, key_prefix
            """,
            (hash_key(raw_key),),
        )
        row = cur.fetchone()
    return dict(row) if row else None


def list_keys(include_revoked: bool = True) -> List[Dict[str, Any]]:
    where = "" if include_revoked else "WHERE active"
    with cursor() as cur:
        cur.execute(
            f"""
            SELECT id, name, key_prefix, active, note, request_count,
                   created_at, last_used_at, expires_at, revoked_at
              FROM api_keys
              {where}
             ORDER BY created_at DESC
            """
        )
        return [dict(r) for r in cur.fetchall()]


def revoke(key_id: int) -> bool:
    """Anahtarı devre dışı bırakır (silmez — kullanım geçmişi korunur)."""
    with cursor(commit=True) as cur:
        cur.execute(
            """
            UPDATE api_keys
               SET active = FALSE, revoked_at = now()
             WHERE id = %s AND active
            """,
            (key_id,),
        )
        return (cur.rowcount or 0) > 0


def delete(key_id: int) -> bool:
    with cursor(commit=True) as cur:
        cur.execute("DELETE FROM api_keys WHERE id = %s", (key_id,))
        return (cur.rowcount or 0) > 0


def any_active() -> bool:
    """Veritabanında kullanılabilir en az bir anahtar var mı?"""
    try:
        with cursor() as cur:
            cur.execute(
                """
                SELECT 1 FROM api_keys
                 WHERE active AND (expires_at IS NULL OR expires_at > now())
                 LIMIT 1
                """
            )
            return cur.fetchone() is not None
    except Exception:
        return False


# --- kullanım kaydı --------------------------------------------------------

def log_request(
    api_key_id: Optional[int],
    path: str,
    method: str,
    status_code: int,
    item_count: int = 0,
    duration_ms: int = 0,
) -> None:
    """İsteği kaydeder. Kayıt başarısız olursa istek yine de tamamlanır."""
    try:
        with cursor(commit=True) as cur:
            cur.execute(
                """
                INSERT INTO api_requests
                    (api_key_id, path, method, status_code, item_count, duration_ms)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (api_key_id, path[:200], method, status_code, item_count, duration_ms),
            )
    except Exception as exc:
        logger.debug("İstek kaydı yazılamadı: %s", exc)


def usage_summary(days: int = 7) -> Dict[str, Any]:
    """Panel için istek istatistikleri."""
    with cursor() as cur:
        cur.execute(
            """
            SELECT count(*)                                          AS requests,
                   coalesce(sum(item_count), 0)                      AS items,
                   coalesce(round(avg(duration_ms)), 0)              AS avg_ms,
                   count(*) FILTER (WHERE status_code >= 400)        AS errors
              FROM api_requests
             WHERE created_at > now() - (%s || ' days')::interval
            """,
            (str(days),),
        )
        totals = dict(cur.fetchone() or {})

        cur.execute(
            """
            SELECT date_trunc('day', created_at)::date AS day,
                   count(*)                            AS requests,
                   coalesce(sum(item_count), 0)        AS items
              FROM api_requests
             WHERE created_at > now() - (%s || ' days')::interval
             GROUP BY 1
             ORDER BY 1
            """,
            (str(days),),
        )
        daily = [
            {"day": r["day"].isoformat(), "requests": int(r["requests"]), "items": int(r["items"])}
            for r in cur.fetchall()
        ]

        cur.execute(
            """
            SELECT k.id, k.name, k.key_prefix, count(r.id) AS requests
              FROM api_keys k
              LEFT JOIN api_requests r
                     ON r.api_key_id = k.id
                    AND r.created_at > now() - (%s || ' days')::interval
             GROUP BY k.id, k.name, k.key_prefix
             ORDER BY requests DESC
             LIMIT 10
            """,
            (str(days),),
        )
        per_key = [dict(r) for r in cur.fetchall()]

    return {
        "days": days,
        "requests": int(totals.get("requests") or 0),
        "items": int(totals.get("items") or 0),
        "avg_ms": int(totals.get("avg_ms") or 0),
        "errors": int(totals.get("errors") or 0),
        "daily": daily,
        "per_key": per_key,
    }
