"""
Kimlik doğrulama.

İki ayrı yetki düzeyi vardır:

  API anahtarı   Müşterilere dağıtılır; tarama ve job uçlarını açar. Anahtarlar
                 veritabanında tutulur (`storage.api_keys`), panelden üretilir.
                 `API_KEYS` ortam değişkeni ek olarak statik anahtar tanımlar —
                 veritabanı henüz kurulmadan ilk erişim için.

  Admin token    Yönetim panelinin kullandığı tek anahtar (`ADMIN_TOKEN`).
                 Anahtar üretme/iptal ve istatistik uçlarını açar.
"""
from __future__ import annotations

import hmac
import logging
from dataclasses import dataclass
from typing import Optional

from fastapi import Header, HTTPException, Request, status

from service_tier.config import get_settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Caller:
    """Doğrulanmış istek sahibi."""

    key_id: Optional[int]
    name: str


def _extract_key(x_api_key: Optional[str], authorization: Optional[str]) -> str:
    candidate = (x_api_key or "").strip()
    if candidate:
        return candidate
    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer":
            return token.strip()
    return ""


def _matches_static(candidate: str, keys: list[str]) -> bool:
    # compare_digest: anahtar karşılaştırmasını zamanlama saldırılarına kapatır.
    return any(hmac.compare_digest(candidate, k) for k in keys)


async def require_api_key(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
) -> Caller:
    """Tarama/job uçları için anahtar doğrular ve çağıranı döndürür."""
    settings = get_settings()
    candidate = _extract_key(x_api_key, authorization)

    if candidate and settings.api_keys and _matches_static(candidate, settings.api_keys):
        caller = Caller(key_id=None, name="static")
        request.state.caller = caller
        return caller

    if candidate:
        from service_tier.storage import api_keys as key_store

        record = key_store.verify(candidate)
        if record:
            caller = Caller(key_id=record["id"], name=record["name"])
            request.state.caller = caller
            return caller

    # Hiçbir anahtar tanımlı değilse (ne env ne veritabanı) auth kapalıdır;
    # bu yalnızca ilk kurulum/yerel geliştirme içindir.
    if not settings.api_keys:
        from service_tier.storage import api_keys as key_store

        if not key_store.any_active():
            caller = Caller(key_id=None, name="anonymous")
            request.state.caller = caller
            return caller

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Geçersiz veya eksik API anahtarı",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def require_admin(
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
    authorization: Optional[str] = Header(None),
) -> None:
    """Yönetim uçları için admin token doğrular."""
    settings = get_settings()
    if not settings.admin_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ADMIN_TOKEN tanımlı değil — yönetim paneli kapalı",
        )

    candidate = _extract_key(x_admin_token, authorization)
    if not candidate or not hmac.compare_digest(candidate, settings.admin_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Geçersiz yönetim anahtarı",
        )
