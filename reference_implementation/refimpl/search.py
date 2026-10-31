"""
Aday CVE arama ve ilgililik sıralaması.

Veri bir korpus deposundan okunur (production: PostgreSQL; reference
implementation: `refimpl.store` → in-memory `refimpl.corpus`); bu modül sorgu
sonuçlarını tarayıcının beklediği biçime çevirir ve ürün adına göre ilgililik puanlar.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, NamedTuple, Sequence

from refimpl.fuzzy.matcher import normalize_product_name
from refimpl import store as cve_repo

logger = logging.getLogger(__name__)


class Candidate(NamedTuple):
    """Taranmaya aday bir CVE kaydı.

    `product`/`vendor` CVE'nin yapısal `affected` alanlarından gelir ve ürün
    kimliği için serbest metin çıkarımından daha güvenilirdir. CVE kayıtları
    ikisini ayrı tutar (ör. vendor="Google", product="Chrome"), oysa envanter
    adı genelde birleşiktir ("Google Chrome") — eşleme ikisini de denemelidir.
    """

    cve_id: str
    description: str
    version_hint: str
    product: str
    vendor: str

    @property
    def qualified_product(self) -> str:
        """Satıcı adıyla nitelenmiş ürün adı ("Google Chrome")."""
        vendor = (self.vendor or "").strip()
        product = (self.product or "").strip()
        if vendor and product and vendor.lower() not in product.lower():
            return f"{vendor} {product}"
        return product


# Geriye dönük ad
CVERow = Candidate

# Bir ürünü diğerinden ayırmayan jenerik satıcı/dolgu kelimeleri.
_GENERIC_PRODUCT_TOKENS = {
    "apache", "microsoft", "oracle", "google", "ibm", "cisco", "adobe", "red",
    "hat", "redhat", "the", "inc", "ltd", "corp", "corporation", "co", "gmbh",
    "foundation", "software", "project", "org", "team", "and", "for",
}


def cve_year(cve_id: str) -> int:
    m = re.match(r"CVE-(\d{4})-", cve_id or "")
    return int(m.group(1)) if m else 0


def _stem_token(t: str) -> str:
    """'log4j2' ve 'log4j' aynı köke insin diye sondaki sürüm rakamını atar."""
    return re.sub(r"\d+$", "", t)


def _discriminative(name: str) -> List[str]:
    return [
        t
        for t in (_stem_token(x) for x in (name or "").lower().split())
        if len(t) >= 3 and t not in _GENERIC_PRODUCT_TOKENS
    ]


def product_token_overlap(query_norm: str, product: str) -> bool:
    """Kayıt ürünü sorguyla ayırt edici bir token paylaşıyor mu?

    Açıklama-anahtar kelime yolunu sınırlar: 'Apache ActiveMQ Artemis' CVE'si,
    açıklamasında log4j2 geçiyor diye 'Apache Log4j2' sorgusuna dönmesin.
    """
    q_tokens = _discriminative(query_norm)
    if not q_tokens:
        return True  # sorguda ayırt edici bir şey yok; fazla eleme yapma
    p_tokens = _discriminative(normalize_product_name(product or ""))
    if not p_tokens:
        return True  # ürün alanı yalnızca jenerik satıcı adı

    def matches(qt: str, pt: str) -> bool:
        if qt == pt:
            return True
        # Yalnızca kısa sürüm/çoğul eki farkına izin ver ('postgres'/'postgresql').
        # Rastgele alt dizeleri reddet, böylece 'siri' → 'osirix' eşleşmez.
        short, long = (qt, pt) if len(qt) <= len(pt) else (pt, qt)
        return len(short) >= 4 and len(long) - len(short) <= 2 and long.startswith(short)

    if any(matches(q, p) for q in q_tokens for p in p_tokens):
        return True

    # Bitişik yazılmış ürün aileleri buraya kadar gelir: "BrightwaveLinux"
    # tek token olduğu için yukarıdaki uzunluk farkı kuralına (≤2 karakter)
    # takılır ve "Brightwave Agent" sorgusuyla eşleşmez — ürünün TÜM
    # CVE'leri aday listesine hiç giremez. Kural burada ham ad üzerinden
    # işletilir; normalize edilmiş adda CamelCase bilgisi kalmıyor.
    from refimpl.disambiguation import same_compound_family

    return same_compound_family(product or "", query_norm)


def _looks_like_version(s: str) -> bool:
    if not s or len(s) > 80:
        return False
    if re.search(r"\d+\.\d+", s):
        return True
    return bool(re.match(r"^[\d.<>=\s\-xXvV]+$", s.strip()))


def _to_row(record: Dict[str, Any]) -> Candidate:
    version = (record.get("version") or "").strip()
    if not _looks_like_version(version):
        version = ""
    return Candidate(
        cve_id=record["cve_id"],
        description=(record.get("description") or "").strip(),
        version_hint=version,
        product=(record.get("product") or "").strip(),
        vendor=(record.get("vendor") or "").strip(),
    )


def search_cves(product_normalized: str, vendor: str = "") -> List[Candidate]:
    """Ürün adına göre aday CVE'leri döndürür.

    İKİ kaynak her zaman birleştirilir:

      1. `cve_affected` — CVE'nin yapısal ürün/satıcı alanları
      2. `cves.description` — tam-metin araması

    İkincisi isteğe bağlı değildir: CVE kayıtlarının %41'inde yapısal `affected`
    girdisi yoktur (eski NVD kayıtlarında `product: "n/a"`), bu yüzden yalnızca
    açıklamadan bulunabilirler. Bir ürünün CVE'lerinin çoğu yapısal ürün satırı
    taşımayabilir — açıklama araması yedek olarak bırakılsaydı onlar hiç
    görünmezdi.
    """
    if not product_normalized:
        return []

    rows: Dict[str, Candidate] = {}

    for rec in cve_repo.search(product_normalized, vendor=vendor):
        if not _accepts(product_normalized, vendor, rec):
            continue
        rows[rec["cve_id"]] = _to_row(rec)

    for rec in cve_repo.search_by_description(product_normalized):
        if rec["cve_id"] in rows:
            continue
        if not _accepts(product_normalized, vendor, rec):
            continue
        rows[rec["cve_id"]] = _to_row(rec)

    return list(rows.values())


def _accepts(product_normalized: str, vendor: str, record: Dict[str, Any]) -> bool:
    """Kayıt sorguyla ayırt edici bir sinyal paylaşıyor mu?"""
    product = record.get("product") or ""
    if product_token_overlap(product_normalized, product):
        return True
    # Ürün adı tutmasa da satıcı eşleşiyorsa aday olarak kalsın; kimlik kararı
    # sonraki katmanlarda (fuzzy + politika kapıları) veriliyor.
    #
    # Karşılaştırma birebir eşitlik DEĞİL: envanter satıcıyı kurumsal ekleriyle
    # yazıyor ("Tailspin Technologies Inc"), CVE kaydı sade ("Tailspin"). Eşitlik
    # arandığında bu kol hiç çalışmıyordu.
    rec_vendor = (record.get("vendor") or "").strip()
    if not vendor or not rec_vendor:
        return False

    from refimpl.disambiguation import vendors_conflict

    return not vendors_conflict(rec_vendor, vendor)


def load_cve_bounds(
    cve_ids: Sequence[str],
    product_normalized: str = "",
) -> Dict[str, Dict[str, str]]:
    """Verilen CVE'ler için yapısal sürüm sınırlarını döndürür.

    İki kaynak birleştirilir: CNA'nın kendi bildirimi (cvelistV5) ve NVD'nin CPE
    analizi. NVD satırları SONA eklenir — karar `_resolve_with_structured_bounds`
    içinde "herhangi bir aralık kapsıyorsa THREAT" kuralıyla verildiği için sıra
    tehdidi etkilemez, ama CNA'nın SAFE gerekçesi öne çıkar.
    """
    merged = cve_repo.bounds_for(cve_ids, product_normalized)
    try:
        for cve_id, ranges in cve_repo.cpe_bounds_for(cve_ids, product_normalized).items():
            merged.setdefault(cve_id, []).extend(ranges)
    except Exception:
        # CPE tablosu yoksa/okunamıyorsa tarama CNA verisiyle sürer; bu kaynak
        # bir zenginleştirme, zorunluluk değil.
        logger.warning("NVD CPE sınırları okunamadı", exc_info=True)
    return merged


def score_cve_relevance(row: Candidate, product_normalized: str) -> float:
    """Yüksek skor = daha ilgili. Ürün eşleşmesi ağırlıklı, yenilik ikincil."""
    score = 0.0

    # Yapısal ürün alanı sorguyla birebir tutuyorsa bu en güçlü sinyaldir.
    # Birebir değilse de CVE adı ürünü kimlik düzeyinde kapsıyor olabilir
    # ("MySQL Server" ↔ "MySQL"); bu adaylar sıralamada öne çıkmazsa tarama
    # kapağı eşleşmeyecek adaylarla dolar.
    from refimpl.disambiguation import covers_product

    for name in (row.qualified_product, row.product):
        if not name:
            continue
        if normalize_product_name(name) == product_normalized:
            score += 40.0
            break
        if covers_product(name, product_normalized):
            score += 30.0
            break

    # Yenilik: yalnızca eşit ilgililikteki adaylar arasında ayrım için (max 25).
    score += min(25.0, max(0, cve_year(row.cve_id) - 1999) * 0.5)

    tokens = _discriminative(product_normalized)
    if tokens:
        hits = sum(1 for t in tokens if t in row.description.lower())
        score += 50.0 * (hits / len(tokens))

    # Sürüm ipucu taşıyan kayıtlar sürüm kıyası için daha kullanışlı.
    if row.version_hint and _looks_like_version(row.version_hint):
        score += 5.0

    return score


def rank_cves_by_relevance(cves: List[Candidate], product_normalized: str) -> List[Candidate]:
    if not cves:
        return []
    scored = [(score_cve_relevance(r, product_normalized), r.cve_id, r) for r in cves]
    scored.sort(key=lambda x: (-x[0], x[1]))
    return [r for _, _, r in scored]
