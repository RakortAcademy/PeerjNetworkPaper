"""Tarama servisi — motor ile önbelleği birleştiren tek giriş noktası.

Kararı **goscan** (Go) veriyor; bu katman önbelleği, sürüm damgalarını ve
istek/yanıt biçimini yönetir. Python motoru (`refimpl/`) kaynak olarak duruyor —
altın küme değerlendirmesi ve eğitim hâlâ onu kullanıyor — ama istek yolunda
değil.

Neden: paralellik — Python motoru yorumlayıcı kilidi yüzünden çok çekirdeği
kullanamaz (makale §9.3, §9.5).

goscan erişilemezse istek HATA döner, sessizce Python'a düşülmez — bkz.
`services/goscan.py`.
"""
from __future__ import annotations

import hashlib
import logging
import threading
from typing import Any, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)


def _local_model_path():
    """Seam: checkpoint location from CVE_MODEL_PATH / REFIMPL_MODEL_PATH instead of
    the serving directory of the production tree (not included)."""
    import os
    from pathlib import Path

    for name in ("CVE_MODEL_PATH", "REFIMPL_MODEL_PATH"):
        raw = (os.environ.get(name) or "").strip()
        if raw:
            p = Path(raw).expanduser()
            if p.is_dir():
                p = p / "bilstm_crf.pth"
            return p if p.is_file() else None
    return None


_model_version: Optional[str] = None
_version_lock = threading.Lock()


def model_version() -> str:
    """Yüklü checkpoint'i tanımlayan kısa sürüm damgası.

    Önbellek anahtarının parçasıdır: model yeniden eğitildiğinde damga değişir
    ve eski kararlar kendiliğinden kullanılmaz olur.

    Damga dosya ADINDAN değil İÇERİĞİNDEN türetilir; aksi halde aynı ağırlıklar
    başka bir yola kopyalandığında (ör. yedekten servise terfi) sürüm değişir ve
    hâlâ geçerli olan tüm önbellek gereksiz yere çöpe gider.

    Değer önce goscan'den sorulur: kararı o veriyor, yani önbellek anahtarında
    onun KULLANDIĞI damga olmalı. İki taraf farklı bir checkpoint'e bakıyorsa
    bunu gizlemek yerine görünür kılmak gerekir. goscan erişilemezse yerel
    dosyadan hesaplanır — /health'in yine de bir şey söyleyebilmesi için.
    """
    global _model_version
    if _model_version is not None:
        return _model_version
    with _version_lock:
        if _model_version is not None:
            return _model_version
        from service_tier.backend.services import goscan

        try:
            reported = str(goscan.health().get("model_version") or "").strip()
        except goscan.GoscanUnavailable:
            reported = ""
        if reported:
            _model_version = reported
            return _model_version

        path = _local_model_path()
        if path is None:
            _model_version = "none"
        else:
            digest = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    digest.update(chunk)
            _model_version = digest.hexdigest()[:16]
        return _model_version


_logic_version: Optional[str] = None


def logic_version() -> str:
    """Karar mantığının sürüm damgası — çalışan goscan ikilisinin özeti.

    Önbellek anahtarı yalnızca model dosyasının hash'ini taşıdığında, KOD
    değişiklikleri önbelleği geçersiz kılmıyordu: karar mantığındaki bir
    düzeltmeden sonra API eski kararı döndürmeye devam ediyordu (bir ürünün
    kapısı düzeltildi ama API hâlâ "etkilenmiyor" diyordu).

    Karar artık Go'da verildiği için damga da ORADAN gelir; Python kaynak dosyalarının
    özetini kullanmak yanlış olurdu — goscan yeniden derlendiğinde eski
    kararlar geçersizleşmezdi.
    """
    global _logic_version
    if _logic_version is not None:
        return _logic_version
    with _version_lock:
        if _logic_version is not None:
            return _logic_version
        from service_tier.backend.services import goscan

        _logic_version = str(goscan.health().get("engine_version") or "unknown")
        return _logic_version


def engine_version() -> str:
    """Önbellek anahtarı: model ağırlıkları + karar mantığı.

    İkisinden biri değiştiğinde eski kararlar kendiliğinden kullanılmaz olur.
    """
    return f"{model_version()}.{logic_version()}"


def reset_model_version() -> None:
    """Model dosyası ya da goscan değiştiyse damgaları yeniden hesaplatır."""
    global _model_version, _logic_version
    from service_tier.backend.services import goscan

    with _version_lock:
        _model_version = None
        _logic_version = None
    goscan.reset()


def warm_up() -> None:
    """goscan'e bağlanır ve sürüm damgalarını okur.

    Model artık Go sürecinde yüklü; burada yüklenecek bir şey yok. Bağlantı yine
    de açılışta denenir: sorun varsa ilk müşteri isteğinde değil, servis
    kalkarken görülmeli.
    """
    from service_tier.backend.services import goscan

    try:
        info = goscan.health(refresh=True)
    except goscan.GoscanUnavailable as exc:
        logger.error("goscan'e bağlanılamadı: %s", exc)
        return
    logger.info(
        "goscan hazır — model %s, motor %s, çıkarım %s",
        info.get("model_version"), info.get("engine_version"),
        "açık" if info.get("model_loaded") else "kapalı",
    )


def model_ready() -> bool:
    """Tarama motoru istek karşılayabilir durumda mı?"""
    from service_tier.backend.services import goscan

    try:
        return bool(goscan.health().get("model_loaded"))
    except goscan.GoscanUnavailable:
        return False


def cache_scope(
    platform: Optional[str] = None,
    vendor: Optional[str] = None,
    operating_system: Optional[str] = None,
) -> Optional[str]:
    """Önbellek anahtarının kapsam parçası.

    Satıcı/OS kararı değiştirdiği için anahtarın parçasıdır; aynı ürün+sürüm
    farklı bağlamda farklı sonuç verebilir.
    """
    return "|".join(filter(None, [platform, vendor, operating_system])) or None


def scan(
    product: str,
    version: str,
    platform: Optional[str] = None,
    *,
    vendor: Optional[str] = None,
    operating_system: Optional[str] = None,
    use_cache: bool = True,
) -> Tuple[Dict[str, Any], bool]:
    """Bir ürün+sürüm tarar.

    Returns: (sonuç, önbellekten_mi)
    """
    from service_tier.storage import cache

    ev = engine_version()
    scope = cache_scope(platform, vendor, operating_system)

    if use_cache:
        cached = cache.lookup(product, version, scope, ev)
        if cached is not None:
            return cached, True

    result = _scan_via_goscan(
        [(product, version)], platform, vendor, operating_system
    )[0]
    cache.store(product, version, scope, ev, result)
    return result, False


def _scan_via_goscan(
    pairs: Sequence[Tuple[str, str]],
    platform: Optional[str],
    vendor: Optional[str],
    operating_system: Optional[str],
) -> List[Dict[str, Any]]:
    """Ürün+sürüm çiftlerini goscan'e verir ve sonuçları AYNI sırada döndürür."""
    from service_tier.backend.services import goscan
    from service_tier.config import get_settings

    items = [
        {
            "product": product,
            "version": version,
            "vendor": vendor or "",
            "operating_system": operating_system or "",
            "platform": platform or "",
        }
        for product, version in pairs
    ]
    results = goscan.scan_items(items, timeout=get_settings().goscan_timeout_seconds)
    # Çağıranın verdiği bağlam yanıtta korunur: goscan yalnızca kendisine
    # geçirileni geri yazar ve `platform` ile `operating_system` ayrımı
    # önbellek kapsamının parçası.
    for result, (product, version) in zip(results, pairs):
        result.setdefault("product", product)
        result.setdefault("version", version)
        if platform:
            result["platform"] = platform
        if vendor:
            result["vendor"] = vendor
        if operating_system:
            result["operating_system"] = operating_system
    return results


# NOT — `SCAN_WORKERS` ayarı buradan KALDIRILDI ve artık okunmuyor.
#
# Python tarafında iş parçacığı paralelliği kazanç sağlamadı (GIL ve
# PostgreSQL'in aynı çekirdekleri kullanması). Karar mantığı Go'ya taşındığı için o kısıt ortadan kalktı:
# paralellik artık goscan'in goroutine havuzunda ve orada gerçekten kazandırıyor.
# Eşzamanlılık goscan'in `-workers` bayrağıyla ayarlanır.


def scan_groups(
    groups: Sequence[Any],
    unique_items: Sequence[Any],
    use_cache: bool = True,
) -> List[Optional[Tuple[Dict[str, Any], bool]]]:
    """Plan gruplarını tarar; sonuçlar `unique_items` sırasında döner.

    Önbellekte olmayan TÜM kalemler **tek** goscan isteğinde gider. Bunun nedeni
    paralelliğin artık Go tarafında olması: goscan kalemleri kendi içinde ürüne
    göre gruplayıp goroutine'lere yayıyor ve hazırlığı (aday arama + çıkarım)
    ürün başına bir kez yapıyor. Python'dan grup grup istek atmak bu kazancın
    üstüne bir de istek başına gidiş-dönüş eklerdi.

    Tek istek olduğu için grup düzeyinde hata yalıtımı da Go tarafında: bir ürün
    düşerse yalnızca o kalem `scan_failed` notuyla döner, kalan envanter taranır.
    """
    out: List[Optional[Tuple[Dict[str, Any], bool]]] = [None] * len(unique_items)
    if not groups:
        return out

    from service_tier.storage import cache

    ev = engine_version()
    pending: List[Tuple[int, Any, str]] = []  # (hedef indeks, örnek kalem, sürüm)

    for group in groups:
        sample = unique_items[group.sample_index]
        scope = cache_scope(sample.platform, sample.vendor, sample.operating_system)
        for version, target in zip(group.versions, group.targets):
            if use_cache:
                hit = cache.lookup(sample.product, version, scope, ev)
                if hit is not None:
                    out[target] = (hit, True)
                    continue
            pending.append((target, sample, version))

    if not pending:
        return out

    logger.info("Tarama %d kalem, tek goscan isteği", len(pending))
    from service_tier.backend.services import goscan
    from service_tier.config import get_settings

    items = [
        {
            "product": sample.product,
            "version": version,
            "vendor": sample.vendor or "",
            "operating_system": sample.operating_system or "",
            "platform": sample.platform or "",
        }
        for _, sample, version in pending
    ]
    results = goscan.scan_items(items, timeout=get_settings().goscan_timeout_seconds)

    for (target, sample, version), result in zip(pending, results):
        if sample.platform:
            result["platform"] = sample.platform
        if sample.vendor:
            result["vendor"] = sample.vendor
        if sample.operating_system:
            result["operating_system"] = sample.operating_system
        scope = cache_scope(sample.platform, sample.vendor, sample.operating_system)
        cache.store(sample.product, version, scope, ev, result)
        out[target] = (result, False)
    return out


def scan_versions(
    product: str,
    versions: Sequence[str],
    platform: Optional[str] = None,
    *,
    vendor: Optional[str] = None,
    operating_system: Optional[str] = None,
    use_cache: bool = True,
) -> List[Tuple[Dict[str, Any], bool]]:
    """Aynı ürünün birden çok sürümünü tek hazırlıkla tarar.

    Aday CVE araması ve model çıkarımı sürümden bağımsızdır; ürün başına bir kez
    yapılıp tüm sürümlerde kullanılır (ölçümde 3-4 kat). Önbellekte bulunan
    sürümler modele hiç uğramaz — yalnızca eksik olanlar için hazırlık kurulur.

    Returns: `versions` ile aynı sırada (sonuç, önbellekten_mi) listesi.
    """
    from service_tier.storage import cache

    ev = engine_version()
    scope = cache_scope(platform, vendor, operating_system)

    out: List[Optional[Tuple[Dict[str, Any], bool]]] = [None] * len(versions)
    todo: List[int] = []

    for i, version in enumerate(versions):
        if use_cache:
            hit = cache.lookup(product, version, scope, ev)
            if hit is not None:
                out[i] = (hit, True)
                continue
        todo.append(i)

    if todo:
        # Eksik sürümlerin tamamı TEK istekte gider: goscan aynı ürünün
        # sürümlerini kendi içinde gruplayıp hazırlığı (aday arama + çıkarım)
        # bir kez yapıyor. Sürüm başına ayrı istek o kazancı yok ederdi.
        fresh = _scan_via_goscan(
            [(product, versions[i]) for i in todo], platform, vendor, operating_system
        )
        for i, result in zip(todo, fresh):
            cache.store(product, versions[i], scope, ev, result)
            out[i] = (result, False)

    return [entry for entry in out if entry is not None]
