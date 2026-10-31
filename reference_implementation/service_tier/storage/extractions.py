"""Model çıkarımlarının kalıcı önbelleği.

Bir CVE'nin ürün/sürüm çıkarımı yalnızca **açıklama metnine** ve **model
sürümüne** bağlıdır; taranan müşteri sürümüyle ilgisi yoktur. Bu yüzden çıkarım
bir kez yapılıp kalıcı olarak saklanabilir: "1.0.0'ı taradım, şimdi 1.1.0'ı
tarıyorum" durumunda aynı CVE'ler modelden yeniden geçmez.

Önbellek süreç ömrüyle sınırlı değildir — yeniden başlatmadan sonra da geçerli
kalır. Model terfi ettiğinde `model_version` değiştiği için eski kayıtlar
kendiliğinden kullanılmaz olur.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, List, Sequence, Tuple

from psycopg2.extras import Json, execute_values

from service_tier.storage.pool import cursor

logger = logging.getLogger(__name__)


def description_hash(description: str) -> str:
    """Açıklamanın kısa özeti — CVE revize edilirse önbellek geçersiz olsun."""
    return hashlib.sha256((description or "").encode("utf-8")).hexdigest()[:16]


def fetch(
    pairs: Sequence[Tuple[str, str]],
    model_version: str,
) -> Dict[str, Dict[str, Any]]:
    """Önbellekteki çıkarımları döndürür: {cve_id: payload}.

    `pairs` (cve_id, description) ikilileridir; açıklama özeti tutmayan kayıtlar
    (CVE metni güncellenmiş) yokmuş gibi davranılır.
    """
    if not pairs:
        return {}
    wanted = {cid: description_hash(desc) for cid, desc in pairs}

    with cursor() as cur:
        cur.execute(
            """
            SELECT cve_id, description_hash, payload
              FROM cve_extractions
             WHERE model_version = %s AND cve_id = ANY(%s)
            """,
            (model_version, list(wanted)),
        )
        rows = cur.fetchall()

    out: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        if r["description_hash"] == wanted.get(r["cve_id"]):
            out[r["cve_id"]] = r["payload"]
    return out


def store(
    entries: Sequence[Tuple[str, str, Dict[str, Any]]],
    model_version: str,
) -> int:
    """Yeni çıkarımları yazar. `entries`: (cve_id, description, payload)."""
    if not entries:
        return 0
    rows: List[Tuple] = [
        (cid, model_version, description_hash(desc), Json(payload))
        for cid, desc, payload in entries
    ]
    with cursor(commit=True) as cur:
        execute_values(
            cur,
            """
            INSERT INTO cve_extractions (cve_id, model_version, description_hash, payload)
            VALUES %s
            ON CONFLICT (cve_id, model_version) DO UPDATE
               SET description_hash = EXCLUDED.description_hash,
                   payload = EXCLUDED.payload,
                   created_at = now()
            """,
            rows,
        )
        return cur.rowcount or 0


def stats() -> Dict[str, Any]:
    with cursor() as cur:
        cur.execute(
            """
            SELECT model_version, count(*) AS n
              FROM cve_extractions
             GROUP BY model_version ORDER BY n DESC
            """
        )
        by_model = {r["model_version"]: int(r["n"]) for r in cur.fetchall()}
    return {"total": sum(by_model.values()), "by_model": by_model}


def purge_other_models(keep: str) -> int:
    """Terfi sonrası eski model sürümünün çıkarımlarını siler."""
    with cursor(commit=True) as cur:
        cur.execute("DELETE FROM cve_extractions WHERE model_version <> %s", (keep,))
        return cur.rowcount or 0
