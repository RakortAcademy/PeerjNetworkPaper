"""
goscan istemcisi — tarama motoruna giden tek kapı.

Karar mantığı artık Go tarafında çalışıyor. Python motoru (`refimpl/`) kaynak
olarak duruyor ve altın küme değerlendirmesi hâlâ onu kullanıyor, ama gelen
İSTEKLER buradan geçer.

Neden: paralellik. Python motoru yorumlayıcı kilidi (GIL) yüzünden çok
çekirdeği kullanamaz; darboğaz donanım değil (makale §9.3, §9.5).

**Yedeğe düşme yok.** goscan erişilemezse istek hata döner. Sessizce Python'a
düşmek iki motoru aynı anda üretimde tutmak demektir; bugün ikisini aynı hizaya
getirmek üç ayrı düzeltme aldı ve sessiz ayrışma bu mimarinin tek gerçek riski.
Açık hata, sessiz yanlış karardan iyidir.
"""
from __future__ import annotations

import json
import logging
import threading
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)


class GoscanUnavailable(RuntimeError):
    """goscan'e ulaşılamadı ya da hata döndü."""


_health: Optional[Dict[str, Any]] = None
_health_lock = threading.Lock()


def _base_url() -> str:
    from service_tier.config import get_settings

    return get_settings().goscan_url.rstrip("/")


def _post(path: str, payload: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    url = f"{_base_url()}{path}"
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise GoscanUnavailable(f"goscan {exc.code}: {detail}") from exc
    except Exception as exc:  # bağlantı hatası, zaman aşımı, bozuk JSON
        raise GoscanUnavailable(f"goscan'e ulaşılamadı ({url}): {exc}") from exc


def health(refresh: bool = False) -> Dict[str, Any]:
    """goscan'in durumu ve sürüm damgaları.

    Sonuç önbelleklenir: her taramada HTTP çağrısı yapmak, tarama başına sabit
    bir gecikme eklerdi. `refresh=True` ya da `reset()` ile yenilenir.
    """
    global _health
    if _health is not None and not refresh:
        return _health
    with _health_lock:
        if _health is not None and not refresh:
            return _health
        url = f"{_base_url()}/health"
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                data = json.load(resp)
        except Exception as exc:
            # Önbellekteki ESKİ değer de düşürülür. Bırakılsaydı motor
            # çöktükten sonra /health "model yüklü" demeye devam ederdi —
            # tarama 503 verirken sağlık raporunun "iyi" görünmesi, izlemenin
            # kesintiyi kaçırması demek.
            _health = None
            raise GoscanUnavailable(f"goscan sağlık kontrolü başarısız ({url}): {exc}") from exc
        _health = data
        return data


def reset() -> None:
    """Sürüm damgalarını yeniden okutur (goscan yeniden başlatıldıysa)."""
    global _health
    with _health_lock:
        _health = None


def available() -> bool:
    try:
        return health(refresh=True).get("status") == "ok"
    except GoscanUnavailable:
        return False


def scan_items(
    items: Sequence[Dict[str, Any]], timeout: float = 900.0
) -> List[Dict[str, Any]]:
    """Kalemleri goscan'e verir ve sonuçları AYNI sırada döndürür.

    Sıra sözleşmenin parçası: çağıran taraf sonuçları indeksle kendi
    kalemlerine bağlıyor.
    """
    if not items:
        return []
    data = _post("/scan", {"items": list(items)}, timeout)
    results = data.get("results") or []
    if len(results) != len(items):
        raise GoscanUnavailable(
            f"goscan {len(items)} kalem için {len(results)} sonuç döndürdü"
        )
    return results
