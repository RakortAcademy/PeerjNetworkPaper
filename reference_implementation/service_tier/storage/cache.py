"""Tarama sonucu önbelleği.

Aynı ürün + sürüm (+ platform) daha önce tarandıysa modeli tekrar çalıştırmak
yerine kayıtlı sonuç döndürülür. Anahtar, normalize edilmiş ürün adı üzerinden
kurulur; böylece "Google Chrome" ve "google  chrome" aynı satıra düşer.

Önbellek `model_version` ile etiketlenir: model yeniden eğitildiğinde anahtar
değişir ve eski kararlar kendiliğinden geçersiz olur.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

from psycopg2.extras import Json

from service_tier.config import get_settings
from service_tier.storage.pool import cursor

logger = logging.getLogger(__name__)


def cache_key(product: str, version: str, platform: Optional[str]) -> tuple[str, str, str]:
    from refimpl.fuzzy.matcher import normalize_product_name

    key = (normalize_product_name(product) or product or "").strip().lower()
    return key, (version or "").strip(), (platform or "").strip().lower()


def lookup(
    product: str,
    version: str,
    platform: Optional[str],
    model_version: str,
) -> Optional[Dict[str, Any]]:
    """Geçerli bir önbellek kaydı varsa sonucu döndürür, yoksa None."""
    settings = get_settings()
    if not settings.cache_enabled:
        return None

    key, ver, plat = cache_key(product, version, platform)
    try:
        with cursor(commit=True) as cur:
            cur.execute(
                """
                UPDATE scan_results
                   SET hit_count = hit_count + 1
                 WHERE product_key = %s AND version = %s
                   AND platform = %s AND model_version = %s
                   AND updated_at > now() - (%s || ' days')::interval
             RETURNING result
                """,
                (key, ver, plat, model_version, str(settings.cache_ttl_days)),
            )
            row = cur.fetchone()
    except Exception as exc:
        logger.warning("Önbellek okunamadı (%s %s): %s", product, version, exc)
        return None

    if not row:
        return None
    result = row["result"]
    return json.loads(result) if isinstance(result, str) else result


def store(
    product: str,
    version: str,
    platform: Optional[str],
    model_version: str,
    result: Dict[str, Any],
) -> None:
    """Tarama sonucunu önbelleğe yazar (aynı anahtar varsa günceller)."""
    settings = get_settings()
    if not settings.cache_enabled:
        return

    key, ver, plat = cache_key(product, version, platform)
    try:
        with cursor(commit=True) as cur:
            cur.execute(
                """
                INSERT INTO scan_results (
                    product_key, version, platform, model_version, product,
                    status, safety_score, threat_count, scanned_cves, result
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT ON CONSTRAINT scan_results_key DO UPDATE SET
                    product      = EXCLUDED.product,
                    status       = EXCLUDED.status,
                    safety_score = EXCLUDED.safety_score,
                    threat_count = EXCLUDED.threat_count,
                    scanned_cves = EXCLUDED.scanned_cves,
                    result       = EXCLUDED.result,
                    updated_at   = now()
                """,
                (
                    key,
                    ver,
                    plat,
                    model_version,
                    product,
                    result.get("status", "UNKNOWN"),
                    int(result.get("safety_score") or 0),
                    len(result.get("threats") or []),
                    int(result.get("scanned_cves") or 0),
                    Json(result),
                ),
            )
    except Exception as exc:
        # Önbellek yazımı taramayı bloke etmemeli.
        logger.warning("Önbelleğe yazılamadı (%s %s): %s", product, version, exc)


def purge_stale(engine_version: str, ttl_days: int) -> int:
    """Başka bir motor sürümünden kalan ve TTL'i geçmiş kayıtları siler.

    Karar mantığı ya da model her değiştiğinde eski kayıtlar erişilemez hâle
    gelir ama tabloda durmaya devam eder. Yalnızca TTL'i de geçmiş olanlar
    silinir: koda geri dönülürse (rollback) yakın tarihli önbellek korunur.
    """
    with cursor(commit=True) as cur:
        cur.execute(
            """
            DELETE FROM scan_results
             WHERE model_version <> %s
               AND updated_at < now() - (%s || ' days')::interval
            """,
            (engine_version, str(max(1, ttl_days))),
        )
        return cur.rowcount or 0


def stats() -> Dict[str, Any]:
    """Önbellek boyutu ve isabet sayıları."""
    try:
        with cursor() as cur:
            cur.execute(
                """
                SELECT count(*)                         AS entries,
                       coalesce(sum(hit_count), 0)      AS hits,
                       max(updated_at)                  AS newest
                  FROM scan_results
                """
            )
            row = cur.fetchone() or {}
        return {
            "entries": int(row.get("entries") or 0),
            "hits": int(row.get("hits") or 0),
            "newest": row.get("newest").isoformat() if row.get("newest") else None,
        }
    except Exception as exc:
        return {"error": str(exc)}


def status_breakdown() -> Dict[str, int]:
    """Önbellekteki taramaların durum dağılımı (THREAT/SAFE/...)."""
    try:
        with cursor() as cur:
            cur.execute("SELECT status, count(*) AS n FROM scan_results GROUP BY status")
            return {r["status"]: int(r["n"]) for r in cur.fetchall()}
    except Exception:
        return {}


def list_scans(
    limit: int = 50,
    offset: int = 0,
    status: Optional[str] = None,
    search: Optional[str] = None,
) -> Dict[str, Any]:
    """Taranmış kayıtları listeler (panelde gösterim için).

    `result` JSON'ı büyük olduğundan listede taşınmaz; yalnızca özet alanlar
    ve tehdit sayısı döner. Ayrıntı için `get_scan` kullanılır.
    """
    where, params = [], {"limit": limit, "offset": offset}
    if status:
        where.append("status = %(status)s")
        params["status"] = status.upper()
    if search:
        where.append("(product ILIKE %(q)s OR version ILIKE %(q)s)")
        params["q"] = f"%{search.strip()}%"
    clause = f"WHERE {' AND '.join(where)}" if where else ""

    with cursor() as cur:
        cur.execute(f"SELECT count(*) AS n FROM scan_results {clause}", params)
        total = int((cur.fetchone() or {}).get("n") or 0)

        cur.execute(
            f"""
            SELECT id, product, version, platform, status, safety_score,
                   threat_count, scanned_cves, hit_count, model_version,
                   created_at, updated_at
              FROM scan_results
              {clause}
             ORDER BY updated_at DESC
             LIMIT %(limit)s OFFSET %(offset)s
            """,
            params,
        )
        rows = [dict(r) for r in cur.fetchall()]

    return {"total": total, "limit": limit, "offset": offset, "items": rows}


FINDING_BUCKETS = {
    "threats": "threats",
    "uncertain": "uncertain_items",
    "safe": "safe_reasons",
}


def get_scan_summary(scan_id: int) -> Optional[Dict[str, Any]]:
    """Bir taramanın özeti — CVE listeleri HARİÇ.

    Tek bir tarama binlerce bulgu taşıyabilir (yüksek CVE sayılı bir ürün
    megabaytlarca JSON üretir). Bunu tek parça göndermek tarayıcıyı kilitler;
    listeler `get_scan_findings` ile sayfa sayfa okunur.

    Sayımlar JSONB dizilerinin uzunluğundan okunur — gövde belleğe alınmaz.
    """
    with cursor() as cur:
        cur.execute(
            """
            SELECT id, product, version, platform, status, safety_score,
                   threat_count, scanned_cves, hit_count, model_version,
                   created_at, updated_at,
                   result - 'threats' - 'uncertain_items' - 'safe_reasons'
                       - 'scanned_cve_ids' AS summary,
                   coalesce(jsonb_array_length(result->'threats'), 0)        AS n_threats,
                   coalesce(jsonb_array_length(result->'uncertain_items'), 0) AS n_uncertain,
                   coalesce(jsonb_array_length(result->'safe_reasons'), 0)    AS n_safe
              FROM scan_results
             WHERE id = %s
            """,
            (scan_id,),
        )
        row = cur.fetchone()
    if not row:
        return None
    out = dict(row)
    summary = out.pop("summary", None) or {}
    if isinstance(summary, str):
        summary = json.loads(summary)
    out["decision_summary"] = summary.get("decision_summary")
    out["vendor"] = summary.get("vendor")
    out["operating_system"] = summary.get("operating_system")
    out["product_cleaned"] = summary.get("product_cleaned")
    out["ambiguous_product"] = bool(summary.get("ambiguous_product"))
    out["cve_candidates_total"] = summary.get("cve_candidates_total")
    # Yükseltme önerisi özetle birlikte gelir: panelde bulguları açmadan önce
    # görülmesi gereken tek satır bu.
    out["recommended_upgrade"] = summary.get("recommended_upgrade")
    out["risk_summary"] = summary.get("risk_summary")
    out["support"] = summary.get("support")
    out["counts"] = {
        "threats": int(out.pop("n_threats")),
        "uncertain": int(out.pop("n_uncertain")),
        "safe": int(out.pop("n_safe")),
    }
    return out


def get_scan_findings(
    scan_id: int,
    bucket: str = "threats",
    limit: int = 25,
    offset: int = 0,
) -> Optional[Dict[str, Any]]:
    """Bir taramanın bulgularından tek sayfa.

    Dilimleme PostgreSQL tarafında yapılır (`jsonb_array_elements` + LIMIT):
    Megabaytlarca gövdeyi Python'a çekip orada kesmek sunucuyu da yorardı.
    """
    field = FINDING_BUCKETS.get(bucket)
    if not field:
        return None

    with cursor() as cur:
        cur.execute(
            f"""
            SELECT coalesce(jsonb_array_length(result->%(field)s), 0) AS total
              FROM scan_results WHERE id = %(id)s
            """,
            {"field": field, "id": scan_id},
        )
        row = cur.fetchone()
        if row is None:
            return None
        total = int(row["total"])

        cur.execute(
            """
            SELECT elem
              FROM scan_results,
                   LATERAL jsonb_array_elements(result->%(field)s) WITH ORDINALITY AS t(elem, ord)
             WHERE scan_results.id = %(id)s
             ORDER BY t.ord
             LIMIT %(limit)s OFFSET %(offset)s
            """,
            {"field": field, "id": scan_id, "limit": limit, "offset": offset},
        )
        items = [r["elem"] for r in cur.fetchall()]

    return {
        "scan_id": scan_id,
        "bucket": bucket,
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": items,
    }


def scan_id_for(
    product: str, version: str, platform: Optional[str], model_version: str
) -> Optional[int]:
    """Önbellekteki kaydın id'si — manuel taramadan sonra sayfalamak için."""
    key, ver, plat = cache_key(product, version, platform)
    with cursor() as cur:
        cur.execute(
            """
            SELECT id FROM scan_results
             WHERE product_key = %s AND version = %s AND platform = %s
               AND model_version = %s
            """,
            (key, ver, plat, model_version),
        )
        row = cur.fetchone()
    return int(row["id"]) if row else None


def get_scan(scan_id: int) -> Optional[Dict[str, Any]]:
    """Tek bir taramanın TAM sonucu — listeler dahil.

    Yalnızca dışa aktarma gibi bilinçli tam-veri ihtiyaçları için; panel bunu
    kullanmaz (bkz. `get_scan_summary` / `get_scan_findings`).
    """
    with cursor() as cur:
        cur.execute(
            """
            SELECT id, product, version, platform, status, safety_score,
                   threat_count, scanned_cves, hit_count, model_version,
                   created_at, updated_at, result
              FROM scan_results
             WHERE id = %s
            """,
            (scan_id,),
        )
        row = cur.fetchone()
    if not row:
        return None
    row = dict(row)
    if isinstance(row.get("result"), str):
        row["result"] = json.loads(row["result"])
    return row
