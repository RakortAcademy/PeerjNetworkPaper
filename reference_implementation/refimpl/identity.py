"""
Ürün kimliği — envanter yazılımı ile CVE'nin gerçekten aynı ürün olup olmadığını doğrular.

THREAT öncesi yapısal kapı: keyword/sürüm çakışması false positive'lerini keser.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple


_GENERIC_TOKENS: frozenset[str] = frozenset(
    {
        "brindle",
        "corvane",
        "tessary",
        "mirrowick",
        "halden",
        "manager",
        "client",
        "runtime",
        "application",
        "installer",
        "update",
        "windows",
        "x64",
        "x86",
    }
)

# (envanter ipucu, CVE metninde olmaması gereken yabancı ürün, açıklama)
#
# Bu tablolar yöntemin BİLGİ TABANIDIR, yöntemin kendisi değil: dağıtımda
# doğrulanmış çiftlerle doldurulur. Araştırma paketinde içerikleri tamamen
# KURGUSALDIR (gerçek ürün, müşteri envanteri ya da olay kaydı içermez); mekanizma
# ve tablo biçimi aynıdır.
_KNOWN_CROSS_PRODUCT: Tuple[Tuple[str, ...], Tuple[str, ...], str] = (
    (("brindle",), ("brindle cloud console", "brindlecloud"), "Brindle masaüstü ≠ Brindle Cloud Console"),
    (("quillon",), ("quillon-py", "pypi package"), "Quillon editörü ≠ quillon-py Python paketi"),
    (("corvane",), ("corvane relay",), "Corvane görüntüleyici ≠ Corvane Relay sunucusu"),
    (("tessary", "tessary-cli"), ("tessary hosted",), "Tessary CLI ≠ Tessary Hosted hizmeti"),
    (("mirrowick",), ("mirrowick connector", "helpdesk add-on"), "Mirrowick ≠ Mirrowick Connector eklentisi"),
)

_DISTINCT_SUBPRODUCTS: Tuple[Tuple[str, str], ...] = (
    ("brindle", "brindlecloud"),
    ("corvane", "corvane relay"),
    ("quillon", "quillon-py"),
)


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower().strip())


def _tokens(text: str) -> Set[str]:
    return {t for t in re.split(r"[\s_./\-():]+", _norm(text)) if len(t) > 2}


def _inventory_core(inventory_product: str) -> str:
    p = _norm(inventory_product)
    p = re.sub(r"\s*\([^)]*\)\s*", " ", p)
    p = re.sub(r"\s+\d+(\.\d+){1,3}.*$", "", p)
    return p.strip()


def _known_cross_product_mismatch(
    inventory_product: str,
    description: str,
) -> Optional[str]:
    inv = _inventory_core(inventory_product)
    desc = _norm(description)
    for inv_keys, foreign_keys, reason in _KNOWN_CROSS_PRODUCT:
        if not any(k in inv for k in inv_keys):
            continue
        if any(k in desc for k in foreign_keys):
            return reason
    for a, b in _DISTINCT_SUBPRODUCTS:
        if a in inv and b in desc and b not in inv:
            return f"Inventory '{a}' and CVE '{b}' are different product families"
    return None


def _foreign_version_binding(
    inventory_product: str,
    your_version: str,
    constraint_version: str,
    description: str,
) -> Optional[str]:
    """CVE'deki sürüm sınırı başka ürün satırına ait (Quillon 4.x vs quillon-py 0.9)."""
    desc = _norm(description)
    inv = _inventory_core(inventory_product)
    cv = (constraint_version or "").strip()
    yv = (your_version or "").strip()

    bound = cv
    for prefix in ("<= ", "< ", ">= ", "> ", "== "):
        if bound.startswith(prefix):
            bound = bound[len(prefix) :].strip()
            break
    if " .. " in bound:
        parts = bound.split(" .. ", 1)
        bound = parts[1].strip() if len(parts) > 1 else bound

    if not bound or not yv:
        return None

    foreign_markers = (
        "brindlecloud",
        "brindle cloud console",
        "quillon-py",
        "corvane relay",
        "tessary hosted",
        "mirrowick connector",
    )
    inv_flat = inv.replace(" ", "")
    for marker in foreign_markers:
        if marker not in desc:
            continue
        if marker.replace(" ", "") in inv_flat:
            continue
        if bound in desc and marker in desc:
            idx_m = desc.find(marker)
            idx_b = desc.find(bound)
            if idx_m >= 0 and idx_b >= 0 and abs(idx_m - idx_b) < 120:
                return (
                    f"CVE version bound ({bound}) belongs to product '{marker}'; "
                    f"inventory '{inventory_product}' is a different product"
                )
    return None


def _version_scheme_mismatch(
    your_version: str,
    constraint_version: str,
    description: str,
) -> Optional[str]:
    """Aynı ürün ailesinde farklı sürüm şeması (envanter 3.6 vs CVE 'up to 21.5')."""
    yv = _norm(your_version)
    desc = _norm(description)
    cv = (constraint_version or "").strip()
    bound = cv
    for prefix in ("<= ", "< ", ">= ", "> "):
        if bound.startswith(prefix):
            bound = bound[len(prefix) :].strip()
            break
    if not bound or not re.search(r"\d", yv):
        return None

    y_major = re.match(r"(\d+)", yv)
    b_major = re.match(r"(\d+)", bound)
    if not y_major or not b_major:
        return None
    ym, bm = int(y_major.group(1)), int(b_major.group(1))
    if abs(ym - bm) < 8:
        return None

    bound_esc = re.escape(bound)
    if re.search(rf"(up to|before|through|prior to|versions?\s+)[^.;]{{0,40}}{bound_esc}", desc):
        if ym < 10 <= bm:
            return (
                f"CVE version line ({bound}) is not in the same numbering scheme "
                f"as the inventory version ({your_version})"
            )
    return None


# Tek başına ürün kimliği belirlemeyen yaygın kelimeler. Bir CVE açıklamasında
# geçmeleri, o CVE'nin envanterdeki ürünle ilgili olduğunu göstermez.
_COMMON_WORDS: frozenset = frozenset({
    "unity", "studio", "server", "client", "player", "viewer", "editor",
    "reader", "writer", "manager", "monitor", "center", "central", "console",
    "portal", "gateway", "bridge", "connect", "connector", "access", "secure",
    "security", "defender", "guard", "shield", "protect", "backup", "restore",
    "sync", "cloud", "drive", "share", "point", "team", "teams", "meeting",
    "office", "suite", "tools", "utility", "helper", "assistant", "agent",
    "service", "system", "platform", "engine", "framework", "library",
    "package", "module", "plugin", "driver", "update", "updater", "installer",
    "setup", "launcher", "runtime", "desktop", "mobile", "online", "express",
    "professional", "enterprise", "standard", "premium", "basic", "core",
    "print", "printer", "scanner", "camera", "audio", "video", "media",
    "music", "photo", "image", "graphic", "design", "paint", "draw",
    "mail", "message", "chat", "phone", "voice", "call", "contact",
    "calendar", "note", "notes", "task", "project", "board", "report",
    "data", "base", "table", "query", "search", "index", "cache", "store",
    "shop", "market", "pay", "wallet", "money", "bank", "finance",
    "health", "fitness", "sport", "game", "play", "learn", "study", "book",
    "news", "weather", "clock", "timer", "alarm", "world", "home", "work",
})


def _strong_token_overlap(inventory_product: str, description: str) -> bool:
    inv = _inventory_core(inventory_product)
    inv_t = _tokens(inv) - _GENERIC_TOKENS
    desc = _norm(description)
    if not inv_t:
        return False

    hits = [
        t
        for t in inv_t
        if len(t) >= 4 and re.search(rf"\b{re.escape(t)}\b", desc)
    ]
    if len(hits) >= 2:
        return True

    # Tek token eşleşmesi: ad yeterince ayırt ediciyse kabul edilir. Sabit bir
    # ürün listesi tutmak sürdürülemez (her yeni ürün elle eklenmek zorunda
    # kalır ve tek kelimelik adların tüm CVE'leri UNCERTAIN'e düşer). Ölçüt: token, yaygın bir İngilizce/jenerik
    # yazılım kelimesi olmayan ≥4 karakterlik bir ad olmalı.
    return any(len(t) >= 4 and t not in _COMMON_WORDS for t in hits)


# ---------------------------------------------------------------------------
# Yapısal sınır yolundaki kimlik kapıları
#
# Yukarıdaki politika katmanı yalnızca METİNDEN çıkarılmış kısıtlara uygulanır.
# Yapısal sınır (CNA/NVD) yolu onu atlar; aşağıdaki kapılar o yoldan gelen
# kimlik hatalarını kapatır.
# ---------------------------------------------------------------------------

#: İşletim sistemi adları. Bir CVE'nin ürünü işletim sisteminin KENDİSİyse, o
#: sistem üzerinde çalışan bir UYGULAMAYA uygulanamaz.
_OS_PRODUCT_NAMES: frozenset = frozenset({
    "android", "windows", "macos", "mac", "osx", "ios", "ipados", "tvos",
    "watchos", "linux", "chromeos", "unix", "solaris", "aix", "freebsd",
})

_VERSIONISH_RE = re.compile(r"^v?\d+(\.\d+)*$")


def _is_versionish(token: str) -> bool:
    """"11", "7.0" gibi sürüm parçaları ürün kimliğini değiştirmez."""
    return bool(_VERSIONISH_RE.match(token))


def is_operating_system_product(cve_product: str) -> bool:
    """CVE'nin ürün alanı bir işletim sisteminin KENDİSİ mi?

    Satıcı ve tür kelimeleri atıldıktan sonra geriye yalnızca işletim sistemi
    adı (ve sürüm parçaları) kalıyorsa evet: "Google Android",
    "Microsoft, Inc Windows 11", "Apple macOS".
    """
    from refimpl.disambiguation import identity_tokens

    ids = identity_tokens(cve_product)
    if not ids:
        return False
    saw_os = False
    for token in ids:
        if token in _OS_PRODUCT_NAMES:
            saw_os = True
        elif not _is_versionish(token):
            return False
    return saw_os


def is_same_operating_system(inventory_product: str) -> bool:
    """Envanterdeki kalem o işletim sisteminin KENDİSİ mi?

    Ölçüt adın TAMAMI, kimlik tokenları değil: "Windows Snip Studio" gibi bir
    uygulama adı {windows} tokenını taşır ama bir işletim sistemi değildir;
    Windows CVE'leri ona tehdit olarak yazılmamalı.
    """
    fields = (inventory_product or "").lower().split()
    if not fields:
        return False
    return all(
        f in _OS_PRODUCT_NAMES or _is_versionish(f) or f == "os" for f in fields
    )


def only_common_word_identity(cve_product: str) -> bool:
    """CVE ürününün kimliği YALNIZCA yaygın kelimelerden mi oluşuyor?

    "IBM Secure Gateway" satıcı atılınca {secure, gateway}'e iner ve
    `covers_product` onu "Kestrel Secure Gateway"in alt kümesi sayar; o ürünün
    CVE'leri ilgisiz bir ürüne tehdit olarak yazılır. Yaygın bir kelime tek başına ürün
    kimliği kanıtı değildir.
    """
    from refimpl.disambiguation import identity_tokens

    ids = identity_tokens(cve_product)
    if not ids:
        return False
    return all(t in _COMMON_WORDS for t in ids)


def structured_identity_ok(cve_product: str, inventory_product: str) -> Optional[str]:
    """Yapısal sınırdan gelen bir THREAT'in ürün kimliğini denetler.

    None = geçti; dize dönerse ret gerekçesidir.
    """
    if not cve_product:
        return None

    if is_operating_system_product(cve_product) and not is_same_operating_system(
        inventory_product
    ):
        return (
            f"CVE işletim sisteminin kendisine ait ('{cve_product}'); envanterdeki "
            f"'{inventory_product}' onun üzerinde çalışan bir uygulama"
        )

    # Adlar normalize edilmiş hâlde AYNIYSA kural işlemez: "Weather" ile "Weather"
    # gerçekten aynı üründür, yaygın kelime olması durumu değiştirmez.
    from refimpl.fuzzy.matcher import normalize_product_name

    if normalize_product_name(cve_product) != normalize_product_name(
        inventory_product
    ) and only_common_word_identity(cve_product):
        return (
            f"CVE ürün kimliği yalnızca yaygın kelimelerden oluşuyor "
            f"('{cve_product}'); ad çakışması"
        )
    return None


#: Doğrulanmış AYRI ürün çiftleri — envanter adı ile CVE'nin ÜRÜN ALANI arasında.
#:
#: `_KNOWN_CROSS_PRODUCT` CVE METNİNE bakar; bu tablo ürün alanına bakar. İkisi
#: ayrı: aşağıdaki çiftlerde açıklama bir çelişki işareti taşımıyor, ürün adları
#: farklı olduğu hâlde kimlik-token kapsaması eşleşiyor.
#:
#: Dağıtımda her satır doğrulanmış bir çifttir; araştırma paketindeki satırlar
#: KURGUSALDIR (bkz. `_KNOWN_CROSS_PRODUCT` üstündeki not).
_DISTINCT_PRODUCT_PAIRS: Tuple[Tuple[str, str, str], ...] = (
    ("ravenmail", "ravenmail server", "Ravenmail istemcisi ≠ Ravenmail Server"),
    ("ravenmail", "ravenmail sdk", "Ravenmail istemcisi ≠ Ravenmail SDK kitaplığı"),
    ("pinecrest studio", "pinecrest", "Pinecrest Studio ≠ Pinecrest (eski bağımsız ürün)"),
    ("orchardsync", "orchardsync enterprise", "OrchardSync ≠ OrchardSync Enterprise sunucusu"),
    ("glasswing reader", "glasswing publisher", "Glasswing Reader ≠ Glasswing Publisher"),
)


def distinct_product_pair(cve_product: str, inventory_product: str) -> Optional[str]:
    """Envanter kalemi ile CVE ürünü bilinen AYRI ürünler mi?"""
    inv = _inventory_core(inventory_product)
    cve = _norm(cve_product)
    for inv_key, cve_key, reason in _DISTINCT_PRODUCT_PAIRS:
        if inv_key not in inv or cve_key not in cve:
            continue
        # Envanterin KENDİSİ o ürünse çelişki yok ("OrchardSync Enterprise"
        # taranıyorsa o sunucunun CVE'si doğrudan onu ilgilendirir).
        #
        # Ölçüt TAM AD, `in` DEĞİL: alt dize kullanmak "Pinecrest Studio"
        # envanterini "Pinecrest"ın kendisi sayar ve kuralı iptal eder.
        if inv == cve_key:
            continue
        return reason
    return None


def assess_threat_product_identity(data: Dict[str, Any]) -> Tuple[bool, Optional[str], str]:
    """
    THREAT için ürün kimliği doğrulaması.

    Returns: (confirmed, block_reason, method)
      method: structural  — token örtüşmesi kimliği doğruladı
              rejected    — bilinen çapraz-ürün / sürüm şeması çatışması
              unverified  — yapısal kanıt yok (THREAT'e yükseltilmez)
    """
    # ÖNEMLI: affected_product'a fallback YOK. affected_product CVE'nin kendi
    # ürünüdür; onu envanter kimliği sanmak CVE'yi kendi açıklamasıyla
    # karşılaştırır (döngüsel onay) → "Home"/"Preview" gibi normalize edilemeyen
    # jenerik isimler "Secure Access" CVE'sine THREAT olur. Bu yüzden sadece
    # gerçek envanter kimliğini kullan.
    inventory = (
        data.get("product_normalized")
        or data.get("your_product")
        or ""
    ).strip()
    description = data.get("description") or ""
    your_version = data.get("your_version") or ""
    constraint = data.get("constraint_version") or ""

    # Envanter ürün adı normalize edilemediyse (çok jenerik: "Home", "Preview",
    # "Apps"...) ürün kimliği yapısal olarak doğrulanamaz → THREAT güvenilmez.
    if not inventory:
        return (
            False,
            "Inventory product name could not be normalized (too generic); "
            "product identity cannot be verified",
            "rejected",
        )

    cross = _known_cross_product_mismatch(inventory, description)
    if cross:
        return False, f"Product identity mismatch: {cross}", "rejected"

    foreign = _foreign_version_binding(inventory, your_version, constraint, description)
    if foreign:
        return False, foreign, "rejected"

    scheme = _version_scheme_mismatch(your_version, constraint, description)
    if scheme:
        return False, scheme, "rejected"

    # CVE'nin YAPISAL ürün alanıyla eşleştiysek kimlik zaten doğrulanmıştır:
    # bu alan CNA tarafından bildirilen kanonik addır, serbest metinden
    # çıkarımdan güvenilirdir. Aşağıdaki token-örtüşmesi yolu yalnızca yapısal
    # ürün alanı olmayan (CVE'lerin ~%40'ı) kayıtlar için kalır.
    if data.get("product_match_source") == "catalog":
        return True, None, "catalog"

    if _strong_token_overlap(inventory, description):
        inv_core = _inventory_core(inventory)
        inv_t = _tokens(inv_core) - _GENERIC_TOKENS
        if len(inv_t) == 1 and next(iter(inv_t)) in _GENERIC_TOKENS:
            pass
        elif any(g in inv_core for g in ("brindle", "corvane", "tessary", "mirrowick")):
            pass
        else:
            return True, None, "structural"

    return False, None, "unverified"
