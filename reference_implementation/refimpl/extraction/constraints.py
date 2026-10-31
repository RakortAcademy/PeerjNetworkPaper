"""
CVE metninden ve JSONL version alanından versiyon kısıtları (lt/le/ge/aralık).
BiLSTM çıkaramadığında rules katmanı.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


def _norm_ver(v: Optional[str]) -> Optional[str]:
    if not v:
        return None
    s = str(v).strip()
    s = re.sub(r"^[vV]", "", s)
    s = re.sub(r"\.+$", "", s)
    return s[:40] if s else None


# CVE kayıtlarının bir bölümünde sürüm aralığı yapısal alanlara (lessThan vb.)
# değil, `version` metninin İÇİNE yazılır: ">= 0.2.0, < 0.39.0", "< 2.1.4",
# "All versions < V4.1.4". Depoda 1,09M satırın ~36 binini (%3,3) bu biçim
# oluşturuyor; ayrıştırılmazsa aralığın tamamı "tam sürüm" sanılır ve
# etkilenen sürüm SAFE görünür.
_OPERATOR_RE = re.compile(r"(>=|<=|>|<|=)\s*[vV]?([\d][\w.\-]*)")

_OPERATOR_KEYS = {
    "<": "less_than",
    "<=": "less_than_or_equal",
    ">=": "greater_equal",
    # ">" için ayrı bir alan yok; alt sınır olarak saklamak müşteriyi aralığın
    # içinde göstermek demek olurdu (yanlış tehdit), o yüzden yok sayılır.
}


def parse_version_expression(raw: Optional[str]) -> Dict[str, str]:
    """Operatör içeren sürüm metnini yapısal sınırlara çevirir.

    ">= 0.2.0, < 0.39.0"  → {greater_equal: 0.2.0, less_than: 0.39.0}
    "All versions < V4.1.4" → {less_than: 4.1.4}

    Operatör yoksa boş sözlük döner — çağıran metni tam sürüm olarak
    değerlendirmeye devam edebilir.
    """
    if not raw:
        return {}
    out: Dict[str, str] = {}
    for op, value in _OPERATOR_RE.findall(str(raw)):
        key = _OPERATOR_KEYS.get(op)
        if not key:
            continue
        norm = _norm_ver(value)
        # Aynı operatör birden çok kez geçerse ilki tutulur; CVE metinlerinde
        # ikinci geçiş genelde açıklama cümlesinin parçasıdır.
        if norm and key not in out:
            out[key] = norm
    return out


# --------------------------------------------------------------------------
# `version` metninin çok parçalı hâli
#
# Operatörsüz CNA'lar etkilenen sürümleri düz metin olarak yazar ve bu metin
# çoğu zaman TEK bir kısıt değildir:
#
#   "5.6.9 and below"                       → <= 5.6.9
#   "BrightwaveOS versions 4.6.2 and below"      → <= 4.6.2
#   "BrightwaveOS 4.8.3, 4.6.7"                  → = 4.8.3  ve  = 4.6.7
#   "2098.014.20051 and earlier, 2097.012.30090 and earlier"  → iki ayrı üst sınır
#
# Depoda 1,09M satırın 535 bini (%49) hiç yapısal sınır taşımıyor; bu biçimler
# ayrıştırılmazsa o satırlar karar motoruna hiç ulaşmaz ve etkilenen sürümleri
# metnin içinde kayıtlı olan bir ürün UNCERTAIN kalır.
# --------------------------------------------------------------------------

# Virgül her zaman ayraç; "and" yalnızca ardından sürüm/ürün geliyorsa ayraçtır
# ("4.8.3 and earlier" bölünmemeli, "…, and 2095.007.30311 and earlier" bölünmeli).
_ENUM_SPLIT_RE = re.compile(r"\s*[,;]\s*")
_LEADING_CONJ_RE = re.compile(r"^(?:and|or)\s+", re.IGNORECASE)

# "X and below/earlier/prior/lower" — sürüm tokenı sözcük sınırıyla başlamalı,
# yoksa "S7x and prior" içindeki "7x" sürüm sanılır.
_AND_BELOW_RE = re.compile(
    r"\b([\d][\w.\-]*)\s+(?:and|or)\s+(?:below|earlier|prior|lower|older)",
    re.IGNORECASE,
)
_PRIOR_TO_RE = re.compile(r"(?:prior\s+to|before)\s+[vV]?([\d][\w.\-]*)", re.IGNORECASE)
_UP_TO_RE = re.compile(
    r"(?:up\s+to\s+and\s+including|up\s+to|through)\s+[vV]?([\d][\w.\-]*)",
    re.IGNORECASE,
)
# Tam sürüm: önünde ürün adı olabilir ("Android 12.0", "BrightwaveOS 6.4.3").
# En az bir nokta şart — "12" gibi tek sayılar bakım DALI anlamına gelebiliyor
# ve eşitlik kıyası orada yanlış tehdit üretirdi.
_EXACT_RE = re.compile(
    r"^(?:[A-Za-z][\w./\-]*\s+)*[vV]?(\d+(?:\.\d+)+[\w.\-]*)$"
)

# Tek bir `version` alanından üretilecek satır sayısı. Adobe/Android kayıtlarında
# onlarca sürüm sayılıyor; sınırsız bırakmak tek CVE'yi yüzlerce satıra şişirir.
_MAX_PARTS = 48


def _parse_version_segment(segment: str) -> Optional[Dict[str, str]]:
    """Tek bir parçayı sınıra ya da tam sürüme çevirir; anlaşılmazsa None."""
    text = _LEADING_CONJ_RE.sub("", segment.strip())
    if not text or len(text) > 120:
        return None

    expr = parse_version_expression(text)
    if expr:
        return dict(expr)

    m = _AND_BELOW_RE.search(text)
    if m:
        norm = _norm_ver(m.group(1))
        return {"less_than_or_equal": norm} if norm else None

    m = _PRIOR_TO_RE.search(text)
    if m:
        norm = _norm_ver(m.group(1))
        return {"less_than": norm} if norm else None

    m = _UP_TO_RE.search(text)
    if m:
        norm = _norm_ver(m.group(1))
        return {"less_than_or_equal": norm} if norm else None

    m = _EXACT_RE.match(text)
    if m:
        norm = _norm_ver(m.group(1))
        return {"version": norm} if norm else None

    return None


def parse_version_field(raw: Optional[str]) -> List[Dict[str, str]]:
    """`version` metnini SIFIR YA DA DAHA ÇOK yapısal satıra çevirir.

    Tek sözlük yerine liste döner: bir CNA aynı alanda birden çok bakım dalını
    sayabiliyor ("2098.014.x and earlier, 2097.012.x and earlier") ve bunları tek
    kısıta indirgemek dalların birini düşürüp yanlış SAFE üretirdi.

    Hiçbir parça anlaşılmazsa boş liste döner; çağıran metni ham hâliyle
    saklamaya devam eder.
    """
    if not raw:
        return []
    text = str(raw).strip()
    if not text or text.lower() in ("n/a", "unknown", "unspecified", "*", "-"):
        return []

    # Operatörlü ifade TEK bir kısıttır: ">= 0.2.0, < 0.39.0" virgülden bölünürse
    # alt ve üst sınır iki BAĞIMSIZ satıra ayrılır ve "< 0.39.0" tek başına
    # 0.1.0'ı da etkilenmiş gösterirdi.
    whole = parse_version_expression(text)
    if whole:
        return [whole]

    out: List[Dict[str, str]] = []
    seen = set()
    for segment in _ENUM_SPLIT_RE.split(text):
        parsed = _parse_version_segment(segment)
        if not parsed:
            continue
        key = tuple(sorted(parsed.items()))
        if key in seen:
            continue
        seen.add(key)
        out.append(parsed)
        if len(out) >= _MAX_PARTS:
            break
    return out


def parse_jsonl_version_field(version_str: Optional[str]) -> Dict[str, Any]:
    """JSONL `version` sütunu: '1.0.4 and earlier', '9.0.40', vb."""
    if not version_str:
        return {}
    raw = str(version_str).strip()
    if not raw or raw.lower() in ("n/a", "unknown"):
        return {}

    # Operatörlü aralık ifadeleri önce: "1.0 and earlier" gibi kalıplar bu
    # metinlerde de geçebiliyor ve yalnızca üst sınırı yakalayıp alt sınırı
    # düşürürdü.
    expr = parse_version_expression(raw)
    if expr:
        return dict(expr)

    m = re.search(r"([\d][\w.]*)\s+and\s+earlier", raw, re.IGNORECASE)
    if m:
        return {"less_than_or_equal": _norm_ver(m.group(1))}

    m = re.search(r"before\s+([\d][\w.]*)", raw, re.IGNORECASE)
    if m:
        return {"less_than": _norm_ver(m.group(1))}

    m = re.search(r"through\s+([\d][\w.]*)", raw, re.IGNORECASE)
    if m:
        return {"less_than_or_equal": _norm_ver(m.group(1))}

    if re.fullmatch(r"[\d][\w.]*", raw):
        return {"jsonl_hint_version": _norm_ver(raw)}

    return {}


def parse_description_constraints(
    description: str,
    customer_major: Optional[int] = None,
) -> Dict[str, Any]:
    """CVE açıklamasından lt/le/ge ve aralık çıkar."""
    if not description:
        return {}
    text = description.replace("\n", " ")

    out: Dict[str, Any] = {}

    # "9.x before 9.0.0.M12" — müşteri major ile eşleşen dal
    if customer_major is not None:
        m = re.search(
            rf"\b{customer_major}\.x\s+before\s+([\d][\w.]*)",
            text,
            re.IGNORECASE,
        )
        if m:
            out["less_than"] = _norm_ver(m.group(1))
            return out
        m = re.search(
            rf"\b{customer_major}(?:\.\d+)?\s+before\s+([\d][\w.]*)",
            text,
            re.IGNORECASE,
        )
        if m:
            out["less_than"] = _norm_ver(m.group(1))
            return out

    # Aralık: "9.0.0.M1 to 9.0.0.M9", "1.7.0_04 to 1.7.0_10"
    m = re.search(
        r"([\d][\w.]*)\s+to\s+([\d][\w.]*)",
        text,
        re.IGNORECASE,
    )
    if m:
        out["greater_equal"] = _norm_ver(m.group(1))
        out["less_than_or_equal"] = _norm_ver(m.group(2))
        return out

    # OpenSSL biçimi: "(Affected 1.1.1-1.1.1k)" — tire ile açık aralık.
    # Ölçümde kısıt çıkarılamayan açıklamaların %20'si bu kalıptaydı.
    m = re.search(
        r"affected\s+v?([\d][\w.]*?)\s*[-–]\s*v?([\d][\w.]*)",
        text,
        re.IGNORECASE,
    )
    if m:
        out["greater_equal"] = _norm_ver(m.group(1))
        out["less_than_or_equal"] = _norm_ver(m.group(2))
        return out

    # "Fixed in OpenSSL 1.1.1l" — düzeltme cümlesinde ürün adı araya giriyor,
    # bu yüzden sürümü doğrudan izleyen kalıplar yakalayamıyordu (%26).
    m = re.search(
        r"fixed\s+in\s+[A-Za-z][\w.\-]*(?:\s+[A-Za-z][\w.\-]*){0,3}?\s+v?([\d]+\.[\d][\w.]*)",
        text,
        re.IGNORECASE,
    )
    if m:
        out["less_than"] = _norm_ver(m.group(1))
        return out

    patterns = [
        (r"versions?\s+prior\s+to\s+([\d][\w.]*)", "less_than"),
        (r"versions?\s+before\s+([\d][\w.]*)", "less_than"),
        (r"prior\s+to\s+([\d][\w.]*)", "less_than"),
        (r"before\s+([\d][\w.]*)", "less_than"),
        (r"up\s+to\s+([\d][\w.]*)", "less_than_or_equal"),
        (r"through\s+([\d][\w.]*)", "less_than_or_equal"),
        (r"([\d][\w.]*)\s+and\s+earlier", "less_than_or_equal"),
        (r"([\d][\w.]*)\s+and\s+prior", "less_than_or_equal"),
        (r"<=\s*([\d][\w.]*)", "less_than_or_equal"),
        (r"<\s*([\d][\w.]*)", "less_than"),
        (r">=\s*([\d][\w.]*)", "greater_equal"),
        (r"([\d][\w.]*)\s+and\s+later", "greater_equal"),
        # --- düzeltme dili ---------------------------------------------------
        # "fixed in 4.2.1" / "patched in 4.2.1" / "upgrade to version 4.2.1":
        # düzeltmenin GELDİĞİ sürüm, öncesi etkilenir. Ölçümde açıklamasında
        # sürüm geçtiği hâlde kısıt çıkarılamayan kayıtların önemli bir kısmı
        # yalnızca bu dili kullanıyordu.
        (r"(?:has\s+been\s+)?fixed\s+in\s+(?:version\s+)?([\d][\w.]*)", "less_than"),
        (r"(?:is\s+)?patched\s+in\s+(?:version\s+)?([\d][\w.]*)", "less_than"),
        (r"(?:is\s+)?(?:resolved|addressed|corrected)\s+in\s+(?:version\s+)?([\d][\w.]*)",
         "less_than"),
        (r"(?:upgrade|update|upgrading|updating)\s+to\s+(?:version\s+)?([\d][\w.]*)",
         "less_than"),
        # --- eşdeğer üst sınır ifadeleri -------------------------------------
        (r"([\d][\w.]*)\s+or\s+earlier", "less_than_or_equal"),
        (r"([\d][\w.]*)\s+or\s+(?:below|older|lower)", "less_than_or_equal"),
        (r"earlier\s+than\s+([\d][\w.]*)", "less_than"),
        (r"older\s+than\s+([\d][\w.]*)", "less_than"),
        (r"([\d][\w.]*)\s+or\s+(?:above|newer|higher|later)", "greater_equal"),
    ]
    for pat, key in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            out[key] = _norm_ver(m.group(1))
            return out

    # "affects X.Y.Z and earlier" / "2.4.54 and earlier"
    m = re.search(
        r"affects\s+[^.]{0,80}?\s+([\d][\w.]*)\s+and\s+earlier",
        text,
        re.IGNORECASE,
    )
    if m:
        out["less_than_or_equal"] = _norm_ver(m.group(1))
        return out

    m = re.search(
        r"([\d]+\.[\d]+(?:\.[\d]+)*)\s+and\s+earlier",
        text,
        re.IGNORECASE,
    )
    if m:
        out["less_than_or_equal"] = _norm_ver(m.group(1))

    return out


def merge_constraints_into_cve_info(
    cve_info: Dict[str, Any],
    description: str,
    jsonl_version: Optional[str] = None,
    customer_major: Optional[int] = None,
) -> Dict[str, Any]:
    """Mevcut cve_info üzerine eksik kısıtları doldur (öncelik: mevcut > description > jsonl)."""
    out = dict(cve_info or {})
    sources = []

    def _has_bounds(d: Dict[str, Any]) -> bool:
        return bool(
            d.get("less_than")
            or d.get("less_than_or_equal")
            or d.get("greater_equal")
            or d.get("app_version")
        )

    if not _has_bounds(out):
        from_desc = parse_description_constraints(description, customer_major=customer_major)
        for k, v in from_desc.items():
            if k.startswith("jsonl_"):
                continue
            if v and not out.get(k):
                out[k] = v
        if from_desc:
            sources.append("description_regex")

    if not _has_bounds(out):
        from_jsonl = parse_jsonl_version_field(jsonl_version)
        hint = from_jsonl.pop("jsonl_hint_version", None)
        for k, v in from_jsonl.items():
            if v and not out.get(k):
                out[k] = v
        if hint and not out.get("less_than_or_equal") and not out.get("less_than"):
            # Tek sürüm ipucu: "X and earlier" yoksa üst sınır olarak dene (muhafazakar)
            if re.search(r"earlier|prior|before|through", description or "", re.I):
                out["less_than_or_equal"] = hint
                sources.append("jsonl_hint")
        elif from_jsonl:
            sources.append("jsonl_field")

    if sources:
        out["constraint_source"] = "+".join(sources)
    return out
