"""
ThreatScanner — uygulama adı + sürüm için uçtan uca CVE tarama motoru.

Akış:
    1. Ürün adı normalize edilir           (model.fuzzy)
    2. Aday CVE'ler aranıp sıralanır       (model.search)
    3. Her CVE için ürün + sürüm çıkarılır (model.extraction — BiLSTM-CRF)
    4. Ürün eşleşmesi fuzzy ile doğrulanır (model.fuzzy)
    5. Sürüm kısıtı karşılaştırılır        (model.versioning)
    6. Politika + uygulanabilirlik kapıları THREAT'i filtreler
       (model.policy, model.applicability)

Sonuç durumları: THREAT | SAFE | UNCERTAIN | NOT_FOUND
"""
from __future__ import annotations

import logging
import os
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from refimpl import applicability as app_gates
from refimpl import disambiguation as disambig
from refimpl import identity as product_identity
from refimpl import prioritization
from refimpl.fuzzy.matcher import FuzzyMatcher, normalize_product_name
from refimpl.rationale import (
    build_product_decision_summary,
    explain_cve_row,
    uncertain_row,
)
from refimpl.search import (
    Candidate,
    load_cve_bounds,
    rank_cves_by_relevance,
    score_cve_relevance,
    search_cves,
)
from refimpl.versioning.parser import (
    clean_version_string,
    is_build_of,
    parse_version,
    version_scheme_mismatch,
)
from refimpl.versioning.range_matcher import check_version_in_range

logger = logging.getLogger(__name__)


# ('threat' | 'safe' | 'uncertain' | 'ignored', detay ya da None)
ScanOutcome = Tuple[str, Optional[Dict[str, Any]]]

#: "Değer verilmedi" ile "çözüm None çıktı" ayrımı için. İkisini karıştırmak
#: önceden hesaplanmış None sonucu yeniden hesaplatırdı.
_MISSING = object()


def _model_version_tag() -> str:
    """Çıkarım önbelleğinin anahtarı — model değişince eski kayıtlar düşer.

    Reference implementation: the digest is the SHA-256 of the loaded checkpoint
    file's bytes (first 16 hex characters), computed by `refimpl.engine_identity`
    exactly as the production service tier computed it. Empty when no checkpoint
    is loaded, which disables the extraction cache without changing decisions.
    """
    try:
        from refimpl.engine_identity import model_version

        return model_version()
    except Exception:
        return ""


def _min_relevance_score() -> float:
    try:
        return float(os.environ.get("CVE_MIN_RELEVANCE_SCORE", "12"))
    except (TypeError, ValueError):
        return 12.0


def _max_cves_cap() -> int:
    """Bir taramada incelenecek aday üst sınırı. 0 = sınırsız (varsayılan).

    Kapak eskiden zorunluydu çünkü her aday modelden geçiyordu. Artık iki şey
    değişti: yapısal sınırı olan CVE'ler saf sürüm karşılaştırmasıyla
    çözülüyor (modele uğramadan) ve model çıkarımları kalıcı olarak
    önbelleklendiği için her CVE ömründe bir kez işleniyor.

    Kapak açıkken yüksek CVE sayılı ürünler (ör. işletim sistemi çekirdekleri)
    ciddi biçimde EKSİK raporlanır: kapağın üstündeki adaylar hiç incelenmez.
    """
    try:
        return max(0, int(os.environ.get("CVE_MAX_SCANNED", "0")))
    except (TypeError, ValueError):
        return 0


# CVE kayıtlarında sürüm alanları serbest metindir ve zaman zaman sürüm yerine
# başka şey taşır (ör. "https://aka.ms/OfficeSecurityReleases", "unspecified").
# Bunları sürüm sanıp karşılaştırmak anlamsız THREAT/SAFE üretir.
_VERSION_LIKE_RE = re.compile(r"^[vV]?\d[\w.\-+:]*$")

# Linux kernel CNA'sı sürüm sınırı olarak GIT COMMIT HASH'i bildirir
# ("3c68d44a2b49a0ac9165faa9c191e1e618c8a8d5"). Rakamla başlayan bir hash
# yukarıdaki sürüm kalıbına uyuyor; sürüm sanılınca "4.14.0 iki hash arasında"
# gibi anlamsız karşılaştırmalar THREAT üretir; bu tür ürünlerde uydurma
# tehditlerin büyük kısmı bu yoldan gelir.
#
# Ayırt edici kural: nokta içermeyen, 12+ karakterlik, en az bir a-f harfi
# taşıyan saf onaltılık dizge. Saf rakamdan oluşan build numaraları
# ("202401011200") bu kurala takılmaz.
_COMMIT_HASH_RE = re.compile(r"^[0-9a-f]{12,40}$")


def _looks_like_commit_hash(text: str) -> bool:
    lowered = text.lower()
    return bool(
        "." not in lowered
        and _COMMIT_HASH_RE.match(lowered)
        and re.search(r"[a-f]", lowered)
    )


def _clean_bound(value: Optional[str]) -> str:
    """Sürüm gibi görünmeyen sınır değerlerini eler."""
    text = (value or "").strip()
    if not text or len(text) > 40:
        return ""
    if _looks_like_commit_hash(text):
        return ""
    return text if _VERSION_LIKE_RE.match(text) else ""


def _resolve_exact_version(
    version: str, pv: Any, bounds: Dict[str, str]
) -> Optional[Tuple[str, str, str, str]]:
    """Üst sınır yok, elde TAM SÜRÜM var: eşitlik kıyası.

    CNA'ların bir bölümü etkilenen sürümleri aralık yerine tek tek sayar
    ("BrightwaveOS 4.8.3, 4.6.7"). Bu satırlar sınır taşımadığı için karar motoruna
    hiç ulaşmıyor, etkilenen sürümleri kayıtlı olan ürünler UNCERTAIN dönüyordu.

    Sürüm listede yoksa SAFE denir — ama yalnızca `defaultStatus` 'affected'
    DEĞİLSE. 'affected' olduğunda liste bir örnektir, sayılmayan sürümler de
    etkilenmiştir ve aynı çıkarım kaçan tehdit üretirdi; orada karar metne
    bırakılır.
    """
    exact = _clean_bound(bounds.get("version"))
    if not exact:
        return None
    pe = parse_version(exact)
    if pe is None:
        return None
    if pv == pe:
        return ("THREAT", f"{version} == {exact} (listed as affected)", "eq", exact)
    if str(bounds.get("default_status") or "").lower() == "affected":
        return None
    return ("SAFE", f"{version} != {exact} (not in affected list)", "neq", exact)


def _resolve_single_range(
    version: str, bounds: Dict[str, str]
) -> Optional[Tuple[str, str, str, str]]:
    """CVE veritabanındaki yapısal sürüm sınırlarıyla deterministik karar.

    Arama tuple'ı `less_than`/`greater_equal`'i düşürdüğü için matcher metinden
    türetmeye çalışıp başlık-only açıklamalarda başarısız oluyordu (yanlış UNCERTAIN).
    Bound + parse edilebilir müşteri sürümü varsa burada net karar verilir.

    Döner: (verdict, reason, constraint_type, constraint_version) ya da None.
    """
    pv = parse_version(version)
    if pv is None:
        return None  # müşteri sürümü parse edilemiyor → karar verme

    upper = _clean_bound(bounds.get("less_than"))
    upper_excl = bool(upper)
    if not upper:
        upper = _clean_bound(bounds.get("less_than_or_equal"))
    if not upper:
        return _resolve_exact_version(version, pv, bounds)

    pu = parse_version(upper)
    if pu is None:
        return None

    # Kapsayıcı sınırda ("5.2.8 ve altı") müşterinin derleme numarası taşıyan
    # sürümü (5.2.8.3141) o sürümün İÇİNDEdir; saf sayısal kıyas onu üstte
    # görüp etkilenmiyor sayıyordu.
    below_upper = (pv < pu) if upper_excl else (pv <= pu or is_build_of(version, upper))
    if not below_upper:
        op = ">=" if upper_excl else ">"
        ct = "lt" if upper_excl else "le"
        return ("SAFE", f"{version} {op} {upper} (fixed)", ct, upper)

    lower = _clean_bound(bounds.get("greater_equal"))
    lower_excl = False
    if not lower:
        # NVD `versionStartExcluding`: sınırın KENDİSİ etkilenmiyor. CPE
        # verisinde geçiyor, CNA kayıtlarında karşılığı yok. `greater_equal`
        # gibi işlemek tam sınırdaki sürümü yanlışlıkla tehdit gösterirdi.
        lower = _clean_bound(bounds.get("greater_than"))
        lower_excl = bool(lower)
    pl = parse_version(lower) if lower else None
    # Geçerli bir etkilenen aralık lower < upper gerektirir. Bazı DB satırları bitiş
    # sürümünü greater_equal'e de kopyalar (greater_equal == less_than) ve [X, X)
    # gibi boş bir aralık üretir; bu, X'ten küçük her sürümü yanlışlıkla SAFE yapar.
    # Böyle bozuk alt sınırı düşür ve CVE'yi "upper öncesi" olarak değerlendir.
    if pl is not None and pl >= pu:
        pl = None
    if pl is not None and (pv <= pl if lower_excl else pv < pl):
        op = "<=" if lower_excl else "<"
        return (
            "SAFE",
            f"{version} {op} {lower} (affected range starts at {lower})",
            "range",
            f"({lower}, {upper})" if lower_excl else f"[{lower}, {upper})",
        )
    if pl is not None:
        op = "<" if lower_excl else "<="
        span = f"({lower}, {upper})" if lower_excl else f"[{lower}, {upper})"
        return ("THREAT", f"{lower} {op} {version} < {upper}", "range", span)
    ct = "lt" if upper_excl else "le"
    return ("THREAT", f"{version} < {upper}", ct, upper)


def _same_branch(version: str, bound: str) -> bool:
    """İki sürüm aynı bakım dalında mı (aynı major)?"""
    pv, pb = parse_version(version), parse_version(bound)
    return pv is not None and pb is not None and pv.major == pb.major


def _branch_specific_ranges(
    version: str, ranges: Sequence[Dict[str, str]]
) -> Sequence[Dict[str, str]]:
    """Çok dallı CVE'lerde müşterinin dalına ait aralıkları seçer.

    Satıcılar bir açığı bakım dalı başına ayrı satırlarla bildirir (Tomcat
    11.0.x, 10.1.x, 9.0.x). Bu satırların bir kısmı ALT SINIRSIZ gelir
    ("<= 11.0.14"); böyle bir satırı başka bir dalın sürümüyle kıyaslamak
    9.0.90'ı da "11.0.14'ten küçük" sayar ve yanlış THREAT üretir.

    Bu yüzden birden çok aralık varsa önce müşterinin major sürümüyle aynı
    daldakiler denenir; o dalda aralık yoksa hepsi değerlendirilir (tek dallı
    ürünlerde davranış değişmez).
    """
    if len(ranges) <= 1:
        return ranges
    same = [
        b for b in ranges
        if _same_branch(version, _clean_bound(b.get("less_than"))
                        or _clean_bound(b.get("less_than_or_equal"))
                        or _clean_bound(b.get("greater_equal"))
                        # Tam sürüm satırları da bir dala aittir; dışarıda
                        # bırakılırsa müşterinin dalındaki eşitlik kaçar.
                        or _clean_bound(b.get("version")))
    ]
    return same or ranges


def _resolve_with_structured_bounds(
    version: str,
    ranges: Sequence[Dict[str, str]],
) -> Optional[Tuple[str, str, str, str]]:
    """CVE'nin etkilenen aralıklarına bakarak karar verir.

    Bir CVE genellikle birden çok bakım dalını etkiler. Sürüm herhangi bir
    aralığa düşüyorsa ürün etkilenmiştir; bu yüzden ilk THREAT sonucu kazanır.
    Hiçbiri kapsamıyorsa, kararlaştırılabilmiş aralıklardan biri SAFE der.

    Aralıktan gelen SAFE ("sürüm düzeltmeden sonra") tam sürüm listesinden gelen
    SAFE'ten ("sürüm listede yok") daha güçlüdür; ikincisi yalnızca elde aralık
    yokken kullanılır.
    """
    if not ranges:
        return None

    safe_result: Optional[Tuple[str, str, str, str]] = None
    weak_safe: Optional[Tuple[str, str, str, str]] = None
    for bounds in _branch_specific_ranges(version, ranges):
        resolved = _resolve_single_range(version, bounds)
        if resolved is None:
            continue
        if resolved[0] == "THREAT":
            return resolved
        if resolved[2] == "neq":
            if weak_safe is None:
                weak_safe = resolved
        elif safe_result is None:
            safe_result = resolved
    return safe_result or weak_safe


def _catalog_family(product_normalized: str, clean_product: str) -> Tuple[Optional[str], bool]:
    """Katalogdaki ürün ailesi: (tek karşılık, ürünü kendi adıyla tanıyor mu).

    İkisi de aynı sorgudan çıkıyor; ayrı ayrı sormak taramaya ikinci bir
    veritabanı gidişi ekliyordu.
    """
    try:
        from refimpl import store as cve_repo

        names = cve_repo.product_family_names(product_normalized)
    except Exception:
        logger.debug("Ürün ailesi okunamadı", exc_info=True)
        return None, False
    exact = product_normalized in names
    return _sole_family_of(names, product_normalized, clean_product), exact


def _sole_family_of(
    names: Sequence[str], product_normalized: str, clean_product: str
) -> Optional[str]:
    """Envanterdeki kısa adın katalogdaki TEK karşılığı.

    Envanterler ürün adını CVE kataloğundan kısa yazar: "Acme" ↔ "Acme NAC".
    Kimlik tokenı kıyaslaması bunu farklı ürün sayıyor (CVE'de fazladan "nac"
    var) ve tüm adayları eliyordu — Acme'nin 2026 CVE'leri bu yüzden
    bulunamıyordu.

    Kısa adı spesifik bir ürüne bağlamak yalnızca katalogda TEK karşılığı varsa
    güvenlidir. "MySQL" 17, "Chrome" 9 farklı ürüne çözülüyor; oralarda bağlamak
    bir bileşenin açığını tüm aileye yaymak olurdu. Jenerik adlar ("Word" →
    'word balloon', 'word cash' …) zaten hem çok karşılıklı hem de jenerik
    kapısından geçemez.
    """
    if not product_normalized or disambig.is_generic_product_name(clean_product):
        return None
    if len(names) != 1:
        return None
    only = names[0]
    return only if only != product_normalized else None


def _identity_covers(name: str, target: str) -> bool:
    """`name`, `target`ın tüm ayırt edici tokenlarını taşıyor mu?

    Platform tokenları aranmaz — ürün kimliğinin parçası değiller: envanter
    "Proseware Driftguard Backup For Mac" yazarken CVE yalnızca "Proseware
    Driftguard Backup" der ve "mac" tokenı CVE adında hiç geçmez.
    """
    have = disambig.identity_tokens(name)
    return all(
        t in have
        for t in disambig.identity_tokens(target)
        if t not in _PLATFORM_IDENTITY_TOKENS
    )


#: Ürün kimliğinin parçası OLMAYAN platform/mimari tokenları.
_PLATFORM_IDENTITY_TOKENS: frozenset = frozenset({
    "windows", "win", "win32", "win64", "mac", "macos", "osx", "linux",
    "unix", "android", "ios", "ipados", "x64", "x86", "arm64", "aarch64",
    "32bit", "64bit",
})


def _specificity_reject(
    match_name: str, clean_product: str, product_normalized: str, exact_catalog: bool
) -> Optional[str]:
    """Eşleşen CVE adı, envanterdeki addan DAHA SPESİFİK bir ürünü mü işaret ediyor?

    İki ayrı denetim:

    1. Jenerik adlarda CVE'nin adı da BİREBİR tutmalı. "Music Player" zaten
       belirsiz bir ad; CVE'nin "Halcyon Music Player" demesi başka bir
       satıcının ürününü kastettiği anlamına gelir. Kapsama ölçütü burada
       yetmiyor — "halcyon music player" kimlik olarak "music player"ı kapsıyor.

    2. Katalog ürünü KENDİ adıyla tanıyorsa (`exact_catalog`), CVE en az o
       kadar spesifik olmalı. "Inkwell Notes" katalogda kendi adıyla var;
       "Litware Inkwell 2024" CVE'si daha genel bir ürünü adlandırıyor ve
       not uygulamasına tehdit olarak yazılmamalı.

    Denetim İKİ eşleşme yoluna da (katalog + model çıkarımı) uygulanır;
    yalnızca katalog yoluna bağlansa eşleşmeler çıkarım yoluna kaçar.

    İki istisna: bitişik ürün ailesi ("Woodgrove BrightwaveLinux" ↔
    "Brightwave") token düzeyinde kapsamıyor, ve platform tokenları kimliğin
    parçası değil.
    """
    if not match_name:
        return None
    if disambig.is_generic_product_name(clean_product) and (
        normalize_product_name(match_name) != product_normalized
    ):
        return "jenerik ad, CVE daha spesifik"
    if (
        exact_catalog
        and not disambig.same_compound_family(match_name, clean_product)
        and not _identity_covers(match_name, clean_product)
    ):
        return "katalog spesifikliği"
    return None


def _max_detailed_rows() -> int:
    """Kaç CVE kaydının uzun açıklama metnini taşıyacağı. 0 = sınırsız."""
    try:
        return max(0, int(os.environ.get("CVE_MAX_DETAIL_ROWS", "300")))
    except (TypeError, ValueError):
        return 300


def _trim_payload(result: Dict[str, Any]) -> None:
    """Sonucun boyutunu makul tutar — HİÇBİR CVE düşürülmeden.

    Aday üst sınırı kalktıktan sonra çok CVE'li ürünler binlerce tehdit
    döndürebilir ve her kaydın CVE açıklaması birkaç KB; bu ne HTTP yanıtına
    ne de `scan_results` JSONB sütununa sığar.

    Bu yüzden CVE'lerin KENDİSİ değil, yalnızca ilk N'den sonrakilerin uzun
    açıklama METNİ düşürülür. Sayılar, CVE kimlikleri, sürüm kuralları ve
    gerekçeler olduğu gibi kalır; ayrıntı isteyen /admin/cves/{id} ile bakar.
    Kayıtlar en ağır CVSS'ten hafife sıralanır ki metin taşıyanlar en kritik
    olanlar olsun.
    """
    keep = _max_detailed_rows()
    if keep <= 0:
        return

    for bucket in ("threats", "uncertain_items", "safe_reasons"):
        rows = result.get(bucket) or []
        if len(rows) <= keep:
            continue
        # Tehditler zaten ÖNCELİĞE göre sıralı (`prioritization.attach`); burada
        # yeniden sıralamak o sırayı bozar ve aktif sömürülen açığın metnini
        # kırpıp önemsiz birininkini bırakabilirdi. Diğer kovalarda risk
        # sinyali yok, şiddete göre sıralanırlar.
        if not (rows[0].get("risk")):
            rows.sort(key=lambda r: (-(r.get("cvss_score") or 0), r.get("cve_id") or ""))
        for row in rows[keep:]:
            # İki ayrı açıklama kopyası taşınıyor; ikisi de kırpılır.
            for field_name in ("description", "reference_cve_description"):
                if row.get(field_name):
                    row[field_name] = ""
            row["description_omitted"] = True
            row.pop("decision_explanation", None)
        result[f"{bucket}_detailed"] = keep


def _prioritize_by_version(
    ranked: List[Candidate],
    bounds: Dict[str, List[Dict[str, str]]],
    version: str,
    resolutions: Optional[Dict[str, Any]] = None,
) -> List[Candidate]:
    """Sürümü etkilenen aralığa düşen CVE'leri öne alır.

    İlgililik sıralaması yeniliği ağırlıklandırır; tek başına kullanıldığında
    kapak (`CVE_MAX_SCANNED`) sorulan sürümü gerçekten etkileyen eski CVE'leri
    keser. Yapısal sınırı olan ve sürümü kapsayan adaylar öne çekilir; kova
    içindeki göreli ilgililik sırası korunur.

    Hesaplanan sınır çözümleri `resolutions` sözlüğüne YAZILIR. Aynı hesap
    sonradan `_apply_gates` içinde her aday için yeniden yapılıyordu; maliyet
    aday sayısı × aralık sayısı kadar tekrarlanıyordu.
    """
    if not bounds or parse_version(version) is None:
        return ranked

    store = resolutions if resolutions is not None else {}

    def bucket(row: Candidate) -> int:
        b = bounds.get(row.cve_id)
        resolved = _resolve_with_structured_bounds(version, b) if b else None
        store[row.cve_id] = resolved
        if resolved is None:
            # Yapısal sınır yok: karar metinden çıkarıma kalır, çoğu kez UNCERTAIN.
            return 2
        # Etkileniyor → en öne; etkilenmiyor → kesin SAFE verdiği için sınırsızların önünde.
        return 0 if resolved[0] == "THREAT" else 1

    return [row for _, row in sorted(enumerate(ranked), key=lambda t: (bucket(t[1]), t[0]))]


@dataclass
class _ProductContext:
    """Bir ürünün sürümden BAĞIMSIZ tarama hazırlığı.

    Aday arama ve CRF çıkarımı yalnızca ürün adına bağlıdır; sürüm karşılaştırması
    bunların yanında bedavadır. Bu bağlam bir kez kurulup aynı ürünün tüm
    sürümlerinde yeniden kullanılır (`check_many`).
    """

    product: str
    clean_product: str
    product_normalized: str
    platform: Optional[str]
    operating_system: Optional[str]
    customer_vendor: Optional[str]
    generic_unresolved: bool = False
    #: Kayıt bir ürün değil, kurulu bir güncelleme/yama paketi.
    update_package: bool = False
    relevance_rejected: bool = False
    top_score: float = 0.0
    ranked: List[Candidate] = field(default_factory=list)
    bounds_map: Dict[str, Any] = field(default_factory=dict)
    # cve_id → model çıkarımı; sürümler arasında paylaşılır.
    extracted: Dict[str, Any] = field(default_factory=dict)
    # Ölçüm: kaç çıkarım önbellekten geldi, kaçı için model çalıştı.
    reused_extractions: int = 0
    model_calls: int = 0
    # Envanterdeki kısa adın katalogdaki TEK karşılığı (varsa) — bkz. _sole_family.
    sole_family: Optional[str] = None
    # Katalog bu ürünü KENDİ adıyla tanıyor — bkz. _specificity_reject.
    exact_catalog: bool = False


class ThreatScanner:
    """Ürün + sürüm için CVE tarayıcısı.

    Model ve CVE indeksi ilk kullanımda yüklenir ve örnek boyunca bellekte kalır;
    bu yüzden uygulama ömrü boyunca tek bir örnek paylaşmak gerekir (`get_scanner`).
    """

    def __init__(
        self,
        extractor: Any = None,
        fuzzy_threshold: float = 0.8,
        model_path: Optional[str] = None,
    ) -> None:
        self._extractor = extractor
        # Reference implementation: checkpoint location is passed explicitly (or
        # read from REFIMPL_MODEL_PATH by the extractor); there is no serving dir.
        self._model_path = model_path
        self._fuzzy: Optional[FuzzyMatcher] = None
        self._fuzzy_threshold = fuzzy_threshold
        self._init_lock = threading.Lock()
        # GPU çıkarımı tek seferde tek çağrı kaldırır: paralel taramada birden
        # çok iş parçacığı aynı modeli çağırırsa hem sonuç bozulur hem bellek
        # taşar. Veritabanı ve karar mantığı paralel kalır, yalnızca model
        # sıraya girer.
        self._model_lock = threading.Lock()

    # ---------------------------------------------------------------- yükleme

    def load(self) -> None:
        """BiLSTM-CRF modelini ve fuzzy eşleştiriciyi yükler (idempotent)."""
        if self._extractor is not None and self._fuzzy is not None:
            return
        with self._init_lock:
            if self._fuzzy is None:
                self._fuzzy = FuzzyMatcher(threshold=self._fuzzy_threshold)
            if self._extractor is None:
                from refimpl.extraction.extractor import BiLSTMCRFExtractor

                self._extractor = BiLSTMCRFExtractor(model_dir=self._model_path)

    @property
    def ready(self) -> bool:
        return self._extractor is not None and self._fuzzy is not None

    # ------------------------------------------------------------ tekil kontrol

    def _fuzzy_best_match(
        self, cve_info: Dict[str, Any], product_normalized: str
    ) -> Tuple[bool, Optional[float]]:
        """CVE ürün adının en iyi segment eşleşmesi. 'A, B and C' gibi çok ürünlü
        alanlarda her segment ayrı denenir."""
        import re

        raw_app = (cve_info.get("app_name") or "").strip()
        if not raw_app:
            return False, None

        segments = [
            s.strip()
            for s in re.split(r",|\s+and\s+", raw_app, flags=re.IGNORECASE)
            if s.strip().lower() not in ("n/a", "")
        ]
        if not segments:
            segments = [raw_app]

        best: Optional[float] = None
        for segment in segments:
            seg_norm = normalize_product_name(segment)
            if not seg_norm or len(seg_norm) < 3:
                continue
            match = self._fuzzy.match(seg_norm, [product_normalized])
            if match.get("matched"):
                score = match.get("score")
                if score is not None and (best is None or score > best):
                    best = score
        return (best is not None), best

    def _match_product(
        self,
        cve_info: Dict[str, Any],
        product_normalized: str,
        catalog_product: str,
        customer_product: str = "",
        sole_family: Optional[str] = None,
    ) -> Tuple[bool, Optional[float]]:
        """Ürün eşleşmesi: önce katalog (yapısal) adı, sonra model çıkarımı.

        Katalog adı hem satıcılı ("Google Chrome") hem satıcısız ("Chrome")
        biçimde denenir: CVE kayıtları ikisini ayrı alanlarda tutar, envanter
        adı ise genelde birleşiktir; tek biçim denemek eşleşmeyi kaçırır.
        """
        if catalog_product:
            # Kardeş bileşen çakışması varsa (Word ↔ Excel) katalog adı
            # eşleşse bile bu CVE bu ürüne ait değildir.
            if disambig.component_conflict(catalog_product, customer_product):
                return False, None

            candidates = [catalog_product]
            # "Google Chrome" → "Chrome": envanter yalnızca ürün adını taşıyorsa.
            # Kuyruk parçası ekli adlarda yanıltır ("Google ChromeOS" → "ChromeOS",
            # "chrome" ile 0.86 benzer), bu yüzden yalnızca kimlik tokenları
            # envanterle örtüşen kuyruk aday olur.
            head, _, tail = catalog_product.partition(" ")
            if tail and not disambig.names_conflict(
                tail, customer_product or product_normalized
            ):
                candidates.append(tail)
            # Yıl/edisyon/paket biçimleri: "Microsoft Office 2016" ↔ "Microsoft Word".
            candidates.extend(disambig.match_aliases(catalog_product))

            targets = [product_normalized]
            targets.extend(disambig.match_aliases(customer_product or product_normalized))

            best_score: Optional[float] = None
            for name in candidates:
                normalized = normalize_product_name(name)
                if not normalized:
                    continue
                match = self._fuzzy.match(normalized, targets)
                if match.get("matched"):
                    score = match.get("score")
                    if best_score is None or (score or 0) > best_score:
                        best_score = score

            # Dizi benzerliği tür kelimeleri yüzünden eşiği geçemiyor
            # ("MySQL Server" ↔ "MySQL" = 0.59). CVE adı envanterdeki ürünü
            # kimlik tokenları düzeyinde kapsıyorsa eşleşme kabul edilir.
            if best_score is None and disambig.covers_product(
                catalog_product, customer_product or product_normalized
            ):
                best_score = 0.85

            # Bitişik yazılmış ürün ailesi: "BrightwaveLinux" ↔ "Brightwave
            # Agent". Katalog adı tek token olduğu için ne dizi benzerliği ne de
            # token kapsaması eşleşiyor; ortak kökten sonrası yalnızca platform
            # eki olduğunda aynı üründür. BrightwaveOS ↔ BrightwaveRouter bu
            # kuraldan geçmez (kalan "os"/"router" platform eki değil).
            #
            # Adayların TAMAMI denenir: katalog adı satıcıyla birleşik gelebiliyor
            # ("Woodgrove BrightwaveLinux") ve satıcı ön eki ortak kökü bozuyor.
            if best_score is None:
                target_name = customer_product or product_normalized
                if any(disambig.same_compound_family(c, target_name) for c in candidates):
                    best_score = 0.82

            # Envanter adı kataloğa göre kısa yazılmış ve katalogda tek karşılığı
            # var ("Acme" → "Acme NAC"). Ters yön (CVE daha spesifik) normalde
            # reddedilir; belirsizlik olmadığı ölçüldüğü için burada kabul edilir.
            if best_score is None and sole_family:
                # Katalog adı satıcıyla birleşik gelebiliyor ("Acme Systems Inc.
                # Acme NAC"), o yüzden eşitlik değil kimlik-token kapsaması
                # aranır: ailenin tokenları katalog adında geçiyor mu?
                family_tokens = disambig.identity_tokens(sole_family)
                if family_tokens and family_tokens <= disambig.identity_tokens(catalog_product):
                    best_score = 0.8

            # Kimlik çelişkisi katalog eşleşmesini GEÇERSİZ kılar. Bu denetim
            # eskiden yalnızca adın KUYRUĞUNA uygulanıyordu; katalog adının
            # kendisi doğrudan bulanık eşlemeye giriyordu ve ALT-DİZE yöntemi
            # "google chrome"u "google chromeos" içinde bulup %86,7 ile kabul
            # ediyordu. Sonuç: bir işletim sistemi çekirdeği açığı, aynı kökü
            # taşıyan tarayıcının taramasında tehdit çıkar.
            #
            # Reddetme ERKEN DÖNMEZ: katalog adı tutmasa bile modelin metinden
            # çıkardığı ad eşleşebilir. Bir ürünün CVE'leri katalogda
            # `quill-plus-plus` yazıyor (çelişkili) ama model "Quill++"
            # çıkarıyor ve doğru eşleşme oradan geliyor.
            if best_score is not None and disambig.names_conflict(
                catalog_product, customer_product or product_normalized
            ):
                best_score = None

            if best_score is not None:
                # Katalog adı eşleşti; sonraki aşamalar bu adı ve kaynağı görsün.
                cve_info["app_name"] = catalog_product
                cve_info["product_match_source"] = "catalog"
                return True, best_score

        matched, score = self._fuzzy_best_match(cve_info, product_normalized)
        if matched:
            cve_info["product_match_source"] = "extracted"
        return matched, score

    def _version_verdict(
        self,
        cve_id: str,
        description: str,
        cve_info: Dict[str, Any],
        product_normalized: str,
        customer_ver: Any,
        version_str: str,
        match_score: Optional[float],
    ) -> ScanOutcome:
        """Ürün eşleşmesi kabul edildi; kalan karar sürüm kısıtına bakar."""
        has_upper = cve_info.get("less_than") or cve_info.get("less_than_or_equal")
        has_lower = cve_info.get("greater_equal")
        has_exact = cve_info.get("app_version")

        if not (has_upper or has_lower or has_exact):
            return "uncertain", uncertain_row(
                cve_id,
                description,
                "CVE açıklamasından sürüm kısıtı (</<=/>=) çıkarılamadı.",
                affected_product=cve_info.get("app_name"),
                your_version=version_str,
            )

        if cve_info.get("version_scheme") == "date":
            return "uncertain", uncertain_row(
                cve_id,
                description,
                "CVE sürümü tarih formatında; semver karşılaştırması yapılamadı.",
                affected_product=cve_info.get("app_name"),
                your_version=version_str,
            )

        constraint_str = has_upper or has_lower or has_exact
        cve_ver = parse_version(constraint_str) if constraint_str else None
        if cve_ver is not None and customer_ver is not None:
            # Build numarası (ör. 8684) ile semver (1.6) kıyaslanamaz.
            if cve_info.get("version_scheme") == "build" and customer_ver.major < 100:
                if customer_ver.minor != 0 or customer_ver.patch != 0:
                    return "uncertain", uncertain_row(
                        cve_id,
                        description,
                        "CVE build numarası ile müşteri semver formatı uyuşmuyor.",
                        affected_product=cve_info.get("app_name"),
                        your_version=version_str,
                    )
            if version_scheme_mismatch(customer_ver, cve_ver):
                row = uncertain_row(
                    cve_id,
                    description,
                    "CVE ve müşteri sürüm şemaları farklı (karşılaştırılamıyor).",
                    affected_product=cve_info.get("app_name"),
                    your_version=version_str,
                )
                # Şema uyuşmazlığı "risk bilinmiyor"dan çok "kıyaslanamaz"dır:
                # CVE'nin sürüm numaralandırması müşterininkiyle aynı sistemde
                # değil. Nihai durum belirlenirken bu ayrım gerekiyor.
                row["non_comparable"] = True
                return "uncertain", row

        range_result = check_version_in_range(version_str, cve_info)
        if range_result.get("reason") == "Invalid customer version format":
            return "uncertain", uncertain_row(
                cve_id,
                description,
                "Müşteri sürüm formatı parse edilemedi.",
                affected_product=cve_info.get("app_name"),
                your_version=version_str,
            )

        if cve_info.get("greater_equal") and (
            cve_info.get("less_than") or cve_info.get("less_than_or_equal")
        ):
            upper = cve_info.get("less_than") or cve_info.get("less_than_or_equal")
            constraint_type = "range"
            constraint_version = f"{cve_info.get('greater_equal')} .. {upper}"
        elif cve_info.get("less_than_or_equal"):
            constraint_type, constraint_version = "le", cve_info["less_than_or_equal"]
        elif cve_info.get("less_than"):
            constraint_type, constraint_version = "lt", cve_info["less_than"]
        elif cve_info.get("greater_equal"):
            constraint_type, constraint_version = "ge", cve_info["greater_equal"]
        else:
            constraint_type = "eq"
            constraint_version = cve_info.get("app_version") or ""

        row = {
            "cve_id": cve_id,
            "description": description,
            "affected_product": cve_info.get("app_name") or product_normalized,
            "product_normalized": product_normalized,
            "constraint_type": constraint_type,
            "constraint_version": constraint_version,
            "your_version": version_str,
            "match_score": match_score,
            "reason": range_result.get("reason", ""),
            "decision_source": "range_matcher",
            "product_match_source": cve_info.get("product_match_source"),
        }
        if range_result.get("vulnerable"):
            return "threat", explain_cve_row(row, "THREAT")
        return "safe", explain_cve_row(row, "SAFE")

    def check_single_cve(
        self,
        cve_id: str,
        description: str,
        product_normalized: str,
        customer_ver: Any,
        version_str: str,
        jsonl_version: str = "",
        catalog_product: str = "",
        customer_product: str = "",
        cve_info: Optional[Dict[str, Any]] = None,
        sole_family: Optional[str] = None,
        clean_product: str = "",
        exact_catalog: bool = False,
    ) -> ScanOutcome:
        """Tek bir CVE'nin bu ürün+sürüme uygulanıp uygulanmadığına karar verir.

        `catalog_product` CVE kaydının yapısal `affected.product` alanıdır.
        Varsa ürün kimliği için önce o kullanılır: CNA tarafından bildirilmiş
        kanonik addır ve serbest metinden çıkarımdan daha güvenilirdir. Model
        çıkarımı yalnızca bu alan yoksa ya da tutmazsa devreye girer.

        `cve_info` verilirse model yeniden çalıştırılmaz; `check()` tüm
        adayları tek toplu çağrıda çıkarıp buraya geçirir.
        """
        from refimpl.extraction.constraints import merge_constraints_into_cve_info
        from refimpl.policy import enforce_outcome_policy

        if cve_info is None:
            cve_info = self._extractor.extract(description, cve_id)
        cve_info = merge_constraints_into_cve_info(
            cve_info,
            description,
            jsonl_version=jsonl_version or None,
            customer_major=getattr(customer_ver, "major", None),
        )

        matched, match_score = self._match_product(
            cve_info, product_normalized, catalog_product, customer_product, sole_family
        )
        if not matched:
            # CVE başka bir ürüne ait — bu envanter kalemini ilgilendirmiyor.
            return "ignored", None

        if _specificity_reject(
            (cve_info.get("app_name") or "").strip(),
            clean_product or customer_product or product_normalized,
            product_normalized,
            exact_catalog,
        ):
            # CVE daha spesifik bir ürünü adlandırıyor — bu kalem o ürün değil.
            return "ignored", None

        outcome, data = self._version_verdict(
            cve_id,
            description,
            cve_info,
            product_normalized,
            customer_ver,
            version_str,
            match_score,
        )
        if data is not None:
            data.setdefault("product_normalized", product_normalized)
        return enforce_outcome_policy(outcome, data)

    # ----------------------------------------------------------- ürün taraması

    def check(
        self,
        product: str,
        version: str,
        platform: Optional[str] = None,
        vendor: Optional[str] = None,
        operating_system: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Bir ürün+sürüm için tüm aday CVE'leri tarar ve nihai kararı döndürür.

        `vendor` ve `operating_system` envanterden geliyorsa belirsiz adları
        çözmekte kullanılır: "Calendar" tek başına onlarca satıcıda bulunur,
        satıcı ya da OS bilgisiyle hangi ürün olduğu belirlenir.
        """
        ctx = self._prepare(product, platform, vendor, operating_system)
        return self._decide(ctx, version)

    def check_many(
        self,
        product: str,
        versions: Sequence[str],
        platform: Optional[str] = None,
        vendor: Optional[str] = None,
        operating_system: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Aynı ürünün birden çok sürümünü tarar — hazırlık bir kez yapılır.

        Ölçüm: bir taramanın süresinin tamamına yakını sürümden BAĞIMSIZ iki
        adımda geçiyor — aday CVE araması ve adayların CRF ile çıkarımı.
        Sürüm karşılaştırması bunların yanında bedava.
        Envanterlerde aynı uygulamanın onlarca sürümü bulunduğu için bu iki
        adımı ürün başına tek sefere indirmek doğrudan N kat kazanç demektir.

        Sonuçlar `versions` ile aynı sırada döner.
        """
        ctx = self._prepare(product, platform, vendor, operating_system)
        return [self._decide(ctx, v) for v in versions]

    def _prepare(
        self,
        product: str,
        platform: Optional[str] = None,
        vendor: Optional[str] = None,
        operating_system: Optional[str] = None,
    ) -> "_ProductContext":
        """Sürümden bağımsız hazırlık: ad temizleme, satıcı çözümü, aday arama."""
        self.load()

        # OS-ailesi platform (windows/macos/...) bir ARAMA terimi DEĞİL, yalnızca son
        # aşamada CVE filtresidir; sorguya eklenirse alakasız OS-üreticisi CVE'lerini
        # (ör. 'macos' → tüm Apple CVE'leri) çeker.
        platform = platform or operating_system
        plat_is_os = bool(platform) and platform.strip().lower() in app_gates.OS_FAMILY_PATTERNS
        # Envanterler ham dosya/paket adları taşır ("TOMCAT9.EXE x64 setup",
        # "org.apache.tomcat:tomcat-catalina"); temizlenmezse hiçbir CVE ürünüyle
        # eşleşmez. Kullanıcının verdiği ad yanıtta olduğu gibi korunur.
        clean_product = disambig.clean_inventory_name(product) or product
        search_name = clean_product if (not platform or plat_is_os) else f"{clean_product} {platform}"
        product_normalized = normalize_product_name(search_name)

        # Çağıranın açıkça verdiği satıcı/OS ile katalogdan TAHMİN edilen satıcı
        # ayrı tutulur: jenerik bir ad ("Calendar") için katalog tahmini yanlış
        # olabilir, o yüzden belirsizlik kararında yalnızca verilen bilgi sayılır.
        supplied_vendor = (vendor or "").strip().lower() or None
        if not supplied_vendor and disambig.is_generic_product_name(clean_product):
            # İşletim sisteminden satıcı çıkarımı YALNIZCA jenerik adlar içindir:
            # macOS'taki "Calendar" Apple'ın takvimidir. Her ürüne uygulandığında
            # "Windows üzerindeki Google Chrome"un satıcısı Microsoft olur ve
            # Chrome'un TÜM CVE'leri satıcı kapısından elenir — gerçek tehditler
            # sessizce SAFE'e döner. Üstelik arama da satıcıya göre genişlediği
            # için aday sayısı gereksiz yere büyür.
            supplied_vendor = disambig.infer_vendor_from_os(operating_system or platform)

        customer_vendor = supplied_vendor
        if not customer_vendor:
            try:
                from refimpl.vendors import infer_vendor

                customer_vendor = infer_vendor(product, platform)
            except Exception:
                customer_vendor = None

        # Jenerik ad + çağırandan gelen satıcı/OS yok → hangi ürün olduğu belirlenemez.
        generic_unresolved = (
            disambig.is_generic_product_name(clean_product) and not supplied_vendor
        )
        # Kurulu YAMA kaydı ürün değildir; taranırsa yamanın kendisi açık
        # olarak raporlanır (bkz. `is_update_package`).
        update_package = disambig.is_update_package(product)

        ctx = _ProductContext(
            product=product,
            clean_product=clean_product,
            product_normalized=product_normalized,
            platform=platform,
            operating_system=operating_system,
            customer_vendor=customer_vendor,
            update_package=update_package,
            generic_unresolved=generic_unresolved,
        )

        if generic_unresolved or update_package:
            # Satıcı/OS olmadan "Calendar" gibi bir ad için CVE eşlemek, başka bir
            # satıcının ürününü müşteriye tehdit diye göstermek demektir.
            # Yama kayıtlarında ise eşleşecek bir ürün zaten yok.
            return ctx

        ctx.ranked = rank_cves_by_relevance(
            search_cves(product_normalized, vendor=customer_vendor or ""), product_normalized
        )
        if not ctx.ranked:
            return ctx

        ctx.top_score = score_cve_relevance(ctx.ranked[0], product_normalized)
        if ctx.top_score < _min_relevance_score():
            # En iyi aday bile ürünle ilgisiz → envanterdeki ürün DB'de yok sayılır.
            ctx.relevance_rejected = True
            return ctx

        ctx.bounds_map = load_cve_bounds(
            [r.cve_id for r in ctx.ranked], product_normalized=product_normalized
        )
        ctx.sole_family, ctx.exact_catalog = _catalog_family(
            product_normalized, clean_product
        )
        return ctx

    def _extract_into(self, ctx: "_ProductContext", candidates: Sequence[Candidate]) -> None:
        """Eksik çıkarımları doldurur — önce kalıcı önbellek, kalanı model.

        Çıkarım yalnızca CVE metnine ve model sürümüne bağlı olduğu için taramalar
        arasında paylaşılabilir: "1.0.0'ı taradım, şimdi 1.1.0" durumunda aynı
        CVE'ler modelden yeniden geçmez. Önbellek kalıcıdır (PostgreSQL), yani
        süreç yeniden başlasa da korunur.

        Önbellek erişilemezse tarama durmaz; model doğrudan çalışır.
        """
        pending = list(candidates)
        model_version = _model_version_tag()

        if model_version:
            try:
                from refimpl import extraction_cache as extractions

                hits = extractions.fetch(
                    [(c.cve_id, c.description) for c in pending], model_version
                )
                if hits:
                    ctx.extracted.update(hits)
                    ctx.reused_extractions += len(hits)
                    pending = [c for c in pending if c.cve_id not in hits]
            except Exception:
                logger.debug("Çıkarım önbelleği okunamadı; model çalışacak", exc_info=True)

        if not pending:
            return

        with self._model_lock:
            fresh = self._extractor.extract_batch(
                [c.description for c in pending], [c.cve_id for c in pending]
            )
        ctx.extracted.update(zip((c.cve_id for c in pending), fresh))
        ctx.model_calls += len(pending)

        if model_version:
            try:
                from refimpl import extraction_cache as extractions

                extractions.store(
                    [(c.cve_id, c.description, info) for c, info in zip(pending, fresh)],
                    model_version,
                )
            except Exception:
                logger.debug("Çıkarım önbelleğine yazılamadı", exc_info=True)

    def _decide(self, ctx: "_ProductContext", version: str) -> Dict[str, Any]:
        """Hazırlanmış ürün bağlamını tek bir sürüme uygular."""
        # Envanter sürüm alanı sürüm dışında da şey taşıyabiliyor (AnyDesk
        # "ad 9.7.3" yazıyor). Ayrıştırılamayınca karar UNCERTAIN'e düşüyordu.
        version = clean_version_string(version) or version
        product = ctx.product
        product_normalized = ctx.product_normalized
        platform = ctx.platform
        customer_vendor = ctx.customer_vendor

        result: Dict[str, Any] = {
            "status": "SAFE",
            "product": product,
            "product_normalized": product_normalized,
            "product_cleaned": ctx.clean_product if ctx.clean_product != product else None,
            "version": version,
            "platform": platform,
            "vendor": customer_vendor,
            "operating_system": ctx.operating_system,
            "threats": [],
            "safe_reasons": [],
            "uncertain_items": [],
            "scanned_cves": 0,
            "scanned_cve_ids": [],
            "safety_score": 100,
            "n_safe": 0,
            "n_uncertain": 0,
            "n_ignored": 0,
            "outcome_histogram": {},
            "decision_summary": None,
        }

        if ctx.update_package:
            # Kurulu bir yama, açığın kendisi değil çözümüdür. Ürün sanıldığında
            # adı "Windows" ile eşleşiyor ve güncelleyicinin sürümü (8.94.0.0)
            # Windows derleme numaralarıyla kıyaslanıyordu: tek kayıt 2.391
            # tehdit üretti, 110'u "aktif sömürülüyor" etiketliydi.
            result["status"] = "NOT_FOUND"
            result["safety_score"] = 0
            result["update_package"] = True
            result["decision_summary"] = {
                "summary_tr": (
                    f"'{product}' bir uygulama değil, kurulu bir güncelleme/yama "
                    f"kaydı. Yamaların kendi CVE'leri olmaz; taranacak ürün "
                    f"işletim sisteminin kendisidir."
                )
            }
            return result

        if ctx.generic_unresolved:
            result["status"] = "UNCERTAIN"
            result["safety_score"] = 50
            result["ambiguous_product"] = True
            result["decision_summary"] = {
                "summary_tr": (
                    f"'{product}' adı tek başına hangi ürün olduğunu belirlemiyor; "
                    f"birçok satıcıda aynı adla uygulama var. Doğru tarama için "
                    f"vendor ya da operating_system bilgisi gerekli."
                )
            }
            return result

        ranked = ctx.ranked
        if not ranked:
            result["status"] = "NOT_FOUND"
            result["safety_score"] = 0
            return result

        if ctx.relevance_rejected:
            result["status"] = "NOT_FOUND"
            result["safety_score"] = 0
            result["cve_candidates_total"] = len(ranked)
            result["relevance_rejected"] = True
            result["top_relevance_score"] = round(ctx.top_score, 2)
            return result

        customer_ver = parse_version(version)
        bounds_map = ctx.bounds_map

        cap = _max_cves_cap()
        # Sınır çözümleri burada bir kez hesaplanır ve kapılarda yeniden
        # kullanılır; iki kez hesaplamak taramanın en pahalı adımıydı.
        resolutions: Dict[str, Any] = {}
        ordered = _prioritize_by_version(ranked, bounds_map, version, resolutions)
        to_scan = ordered if cap <= 0 else ordered[:cap]
        result["scanned_cve_ids"] = [r.cve_id for r in to_scan]
        result["cve_candidates_total"] = len(ranked)
        result["cve_not_scanned"] = max(0, len(ranked) - len(to_scan))

        histogram: Dict[str, int] = {}

        # Tüm adayların ürün/sürüm çıkarımı TEK model çağrısında yapılır; CVE
        # başına ayrı çağırmak CRF çözümlemesini aday sayısı kadar tekrarlardı.
        #
        # Çıkarım sürümden bağımsız (yalnızca CVE metnine bakar), bu yüzden
        # sonuç ürün bağlamında saklanır: aynı ürünün sonraki sürümleri modeli
        # hiç çağırmadan aynı çıkarımı kullanır. `_prioritize_by_version` sıralamayı
        # sürüme göre değiştirdiğinden üst sınırın (cap) kestiği aday kümesi
        # sürümden sürüme farklı olabilir; o yüzden yalnızca EKSİK olanlar çıkarılır.
        missing = [c for c in to_scan if c.cve_id not in ctx.extracted]
        if missing:
            self._extract_into(ctx, missing)
        extracted = [ctx.extracted[c.cve_id] for c in to_scan]

        for candidate, cve_info in zip(to_scan, extracted):
            cve_id = candidate.cve_id
            description = candidate.description
            result["scanned_cves"] += 1
            outcome, data = self.check_single_cve(
                cve_id,
                description,
                product_normalized,
                customer_ver,
                version,
                jsonl_version=candidate.version_hint,
                catalog_product=candidate.qualified_product,
                customer_product=product,
                cve_info=cve_info,
                sole_family=ctx.sole_family,
                clean_product=ctx.clean_product,
                exact_catalog=ctx.exact_catalog,
            )
            outcome, data = self._apply_gates(
                outcome,
                data,
                cve_id=cve_id,
                description=description,
                bounds=bounds_map.get(cve_id),
                resolved=resolutions.get(cve_id, _MISSING),
                product=product,
                version=version,
                platform=platform,
                customer_vendor=customer_vendor,
                catalog_product=candidate.product,
                catalog_vendor=candidate.vendor,
                # `check_single_cve` eşleşen adı buraya yazar: katalog yolunda
                # katalog adı, çıkarım yolunda modelin bulduğu ad.
                match_name=(cve_info.get("app_name") or "").strip(),
            )

            histogram[outcome] = histogram.get(outcome, 0) + 1
            if outcome == "threat" and data:
                result["threats"].append(data)
            elif outcome == "safe" and data:
                result["safe_reasons"].append(data)
                result["n_safe"] += 1
            elif outcome == "uncertain" and data:
                result["uncertain_items"].append(data)
                result["n_uncertain"] += 1
            elif outcome == "ignored":
                result["n_ignored"] += 1

        result["outcome_histogram"] = histogram
        self._finalize_status(result)

        # Önceliklendirme düzeltmeden ÖNCE: tehdit listesini risk sırasına
        # sokuyor ve sonraki iki adım (düzeltme ayrıntısı, metin kırpma) "ilk N"
        # derken artık en acil N'i kastediyor.
        priority_counts = prioritization.attach(result["threats"])
        risk_summary = prioritization.summarize(result["threats"], priority_counts)
        if risk_summary:
            result["risk_summary"] = risk_summary

        # Reference implementation: the post-verdict enrichment steps of the
        # production engine (remediation proposal from OSV/vendor references and
        # end-of-life support status) are not part of the decision procedure and
        # are not included; see MAPPING.md ("post-verdict reporting"). The verdict,
        # the findings and their ordering are unaffected.

        _trim_payload(result)
        result["decision_summary"] = build_product_decision_summary(result)
        return result

    # ------------------------------------------------------------------ kapılar

    def _apply_gates(
        self,
        outcome: str,
        data: Optional[Dict[str, Any]],
        *,
        cve_id: str,
        description: str,
        bounds: Optional[Sequence[Dict[str, str]]],
        product: str,
        version: str,
        platform: Optional[str],
        customer_vendor: Optional[str],
        catalog_product: str = "",
        catalog_vendor: str = "",
        match_name: str = "",
        resolved: Any = _MISSING,
    ) -> ScanOutcome:
        """Uygulanabilirlik ve yapısal-sınır düzeltmelerini uygular.

        `safe` sonuçlar da değerlendirilir: metinden çıkarılan kısıt SAFE derken
        CVE'nin YAPISAL aralığı sürümü kapsıyor olabilir. Yapısal veri metin
        çıkarımından güvenilir olduğu için bu durumda karar yükseltilir —
        aksi halde kapı yalnızca THREAT'i düşürüp hiç yükseltmediğinden
        sistematik olarak tehdit kaçırırdı.
        Yükseltme yine ürün kimliği ve platform kapılarından geçmek zorundadır.
        """
        if outcome not in ("uncertain", "threat", "safe"):
            return outcome, data

        # Ürün/satıcı bilgisi önce sınır kaydından, yoksa adayın kendisinden gelir:
        # CVE'lerin çoğunda yapısal sürüm sınırı yoktur ve yalnızca sınıra bakmak
        # kapıları bu kayıtlarda tamamen devre dışı bırakırdı.
        # Son çare EŞLEŞEN ad: CVE'lerin bir kısmında ne yapısal sınır ne de
        # katalog ürün alanı var; eşleşme modelin metinden çıkardığı addan
        # geliyor. O ad kapılara verilmediğinde `cve_prod` boş kalıyor ve
        # kimlik kurallarının HİÇBİRİ çalışamaz — "Glasswing Reader" sorgusu
        # "Glasswing Publisher"ın CVE'sini, kural doğru olduğu hâlde, tehdit gösterir.
        primary = bounds[0] if bounds else {}
        cve_prod = primary.get("product") or catalog_product or match_name or ""
        cve_vendor = primary.get("vendor") or catalog_vendor or ""
        cve_text = primary.get("text") or description or ""

        # Ürün alanı TEK BAŞINA kimlik taşımıyorsa satıcı öne eklenir. Bazı
        # kayıtlarda bu alan yalnızca "server" yazar (satıcı ayrı sütunda,
        # ör. "ravenmail"); kapılara "server" gidince hiçbir kimlik kuralı
        # çalışamaz ve sunucu CVE'leri masaüstü istemcisine yazılır.
        if cve_prod and cve_vendor and not disambig.identity_tokens(cve_prod):
            cve_prod = f"{cve_vendor} {cve_prod}"

        endpoint_os = app_gates.os_family(f"{platform or ''} {product}")
        cve_os = app_gates.os_family(f"{cve_prod} {cve_text}")
        os_conflict = bool(endpoint_os and cve_os and endpoint_os != cve_os)
        # Metin uç noktanın platformunu açıkça "etkilenmiyor" ilan ediyorsa
        # aile kıyaslamasına gerek yok — zaten o kıyas çok platformlu
        # bültenlerde karar veremiyor.
        os_conflict = os_conflict or app_gates.platform_declared_unaffected(
            cve_text, platform or product
        )
        web_plugin = app_gates.is_web_cms_plugin(cve_prod, cve_text, cve_vendor, product)
        vendor_na = app_gates.vendor_not_applicable(cve_vendor, customer_vendor, cve_prod)
        binding_na = app_gates.is_language_binding_mismatch(cve_prod, cve_text, product)
        # Word ↔ Excel gibi kardeş paket bileşenleri: adların çoğu ortak olduğu
        # için bulanık eşleme bunları aynı ürün sanar.
        component_na = disambig.component_conflict(cve_prod, product)
        # Ürün kimliği kapıları: CVE'nin ADLANDIRDIĞI şey ile envanterdeki kalem
        # farklı ürünler mi? Bu denetim sürüm yolundan BAĞIMSIZ — yalnızca
        # yapısal yükseltmeye bağlanırsa metin yolu THREAT dediğinde atlanır ve
        # "Brightfield Weather Monitor"a başka bir satıcının "Weather Monitor"
        # CVE'si yazılmaya devam eder.
        identity_na = product_identity.structured_identity_ok(cve_prod, product)
        distinct_na = product_identity.distinct_product_pair(cve_prod, product)

        gate_fired = (
            os_conflict
            or web_plugin
            or vendor_na
            or binding_na
            or component_na
            or identity_na
            or distinct_na
        )
        # Zaten SAFE olan bir kararda kapıların işi bitmiştir; ama kapı yanmışsa
        # aşağıdaki yapısal-sınır YÜKSELTMESİ de yapılmamalı — aksi halde
        # uygulanamaz bir CVE (ör. bir WordPress eklentisi) SAFE'ten THREAT'e
        # yükselir ve kapı baypas edilmiş olur.
        if outcome == "safe":
            if gate_fired:
                return outcome, data
        elif gate_fired:
            if component_na:
                kind = "component"
                reason = component_na
            elif identity_na:
                kind = "identity"
                reason = identity_na
            elif distinct_na:
                kind = "identity"
                reason = distinct_na
            elif binding_na:
                kind = "binding"
                reason = (
                    f"CVE targets a language binding/wrapper ('{cve_prod}') → not "
                    f"applicable to the core library '{product}' on this endpoint"
                )
            elif vendor_na:
                kind = "vendor"
                reason = (
                    f"CVE vendor '{cve_vendor or 'Unknown'}' ≠ product vendor "
                    f"'{customer_vendor}' → different product; not applicable for this endpoint"
                )
            elif web_plugin:
                kind = "web_plugin"
                reason = (
                    f"CVE targets a web/CMS plugin/theme ('{cve_prod}') → not "
                    f"applicable to the endpoint application '{product}'"
                )
            else:
                kind = "os"
                reason = (
                    f"CVE is specific to the {cve_os} platform; endpoint is "
                    f"{endpoint_os} → not applicable for this endpoint"
                )
            base = dict(data) if isinstance(data, dict) else {}
            base.update(
                {
                    "cve_id": cve_id,
                    "description": base.get("description") or description,
                    "affected_product": base.get("affected_product") or product,
                    "your_version": version,
                    "reason": reason,
                    "decision_source": f"applicability_{kind}",
                    "not_applicable": True,
                }
            )
            base.pop("uncertain_reason", None)
            return "safe", explain_cve_row(base, "SAFE")

        if not bounds:
            return outcome, data

        # Çözüm `_prioritize_by_version` sırasında zaten hesaplandı; yeniden
        # hesaplamak taramanın en pahalı adımıydı.
        if resolved is _MISSING:
            resolved = _resolve_with_structured_bounds(version, bounds)
        if not resolved:
            return outcome, data

        verdict, reason, constraint_type, constraint_version = resolved
        new_outcome: Optional[str] = None
        if verdict == "SAFE":
            # "Sürüm etkilenen listede yok" bir ARALIK kadar güçlü değil: CNA
            # listeyi eksik bırakmış olabilir. Metinden çıkarılmış bir THREAT'i
            # düşürmesine izin verilmez, yalnızca UNCERTAIN'i kapatır.
            if constraint_type == "neq" and outcome == "threat":
                return outcome, data
            new_outcome = "safe" if outcome != "safe" else None
        elif verdict == "THREAT" and outcome in ("uncertain", "safe"):
            # Yapısal sınır müşteri sürümünü etkilenen aralıkta gösteriyor. Yalnızca
            # ürün kimliği + platform kapılarını geçerse yükselt; gevşek/generic
            # eşleşmeleri ('Agent', 'Manager', 'for Android') yükseltme.
            id_ok = app_gates.product_identity_ok(cve_prod, product)
            plat_bad = app_gates.platform_mismatch(cve_prod, cve_text, product, platform)
            if id_ok and not plat_bad:
                new_outcome = "threat"

        if not new_outcome:
            return outcome, data

        base = dict(data) if isinstance(data, dict) else {}
        base.update(
            {
                "cve_id": cve_id,
                "description": base.get("description") or description,
                "affected_product": base.get("affected_product") or product,
                "your_version": version,
                "constraint_type": constraint_type,
                "constraint_version": constraint_version,
                "reason": reason,
                "decision_source": "structured_bounds",
                "structured_bounds_applied": True,
            }
        )
        base.pop("uncertain_reason", None)
        return new_outcome, explain_cve_row(base, verdict)

    @staticmethod
    def _finalize_status(result: Dict[str, Any]) -> None:
        """threats/safe/uncertain sayımlarından nihai durumu ve güven skorunu üretir."""
        applicable_safe = [r for r in result["safe_reasons"] if not r.get("not_applicable")]

        # Farklı bir ÜRÜN olduğu için elenen CVE'ler (vendor / web-plugin / dil
        # binding) ürünün bulunduğuna kanıt değildir. Her "safe" böyleyse ve başka
        # hiçbir şey çözülmediyse ürünün uygulanabilir CVE'si yok demektir →
        # alakasız bir CVE'yi sergileyen yanıltıcı SAFE yerine NOT_FOUND döndür.
        # (OS/platform uyuşmazlıkları hariç: onlar hâlâ aynı ürünü ilgilendirir.)
        diff_product_only = (
            bool(result["safe_reasons"])
            and not applicable_safe
            and all(
                str(r.get("decision_source", "")).startswith("applicability_")
                and not str(r.get("decision_source", "")).endswith("_os")
                for r in result["safe_reasons"]
            )
        )

        # Taranan HER aday ürün kimliği tutmadığı için elendiyse, envanterdeki
        # ürün veritabanında yok demektir. Bu durumda "SAFE" demek yanıltıcıdır:
        # ürünü tanıyamadık, güvenli olduğunu bilmiyoruz.
        if (
            result["scanned_cves"] > 0
            and result["n_ignored"] == result["scanned_cves"]
        ):
            result["status"] = "NOT_FOUND"
            result["safety_score"] = 0
            result["all_candidates_rejected"] = True
            return

        # Kıyaslanamayan (şema uyuşmazlığı) kayıtlar tek başına belirsizlik
        # sayılmaz: CVE'nin sürüm sistemi müşterininkiyle aynı değil, yani o
        # CVE'den bir risk çıkarılamaz. Aday üst sınırı kalktıktan sonra bu
        # kayıtlar binlerce olabiliyor ve tek başlarına kaldıklarında çözülmüş
        # SAFE kararlarını gölgeleyip her sonucu UNCERTAIN yapıyorlardı.
        decidable_uncertain = [
            u for u in result["uncertain_items"] if not u.get("non_comparable")
        ]
        n_uncertain = len(decidable_uncertain)

        if result["threats"]:
            result["status"] = "THREAT"
            result["safety_score"] = 0
        elif n_uncertain > 0 and not result["safe_reasons"]:
            result["status"] = "UNCERTAIN"
            result["safety_score"] = max(30, 100 - n_uncertain * 5)
        elif n_uncertain > 0:
            result["status"] = "UNCERTAIN"
            result["safety_score"] = max(50, 100 - n_uncertain * 3)
        elif diff_product_only:
            result["status"] = "NOT_FOUND"
            result["safety_score"] = 100
        else:
            result["status"] = "SAFE"
            result["safety_score"] = 100


_scanner: Optional[ThreatScanner] = None
_scanner_lock = threading.Lock()


def get_scanner() -> ThreatScanner:
    """Süreç genelinde tek ThreatScanner örneği (model yalnızca bir kez yüklenir)."""
    global _scanner
    if _scanner is None:
        with _scanner_lock:
            if _scanner is None:
                _scanner = ThreatScanner()
    return _scanner
