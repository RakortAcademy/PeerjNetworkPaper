"""
Belirsiz ürün adlarının çözümlenmesi.

Envanterden gelen adlar üç şekilde yanıltıcı olabilir:

  Jenerik ad     "Calendar", "Notes", "Photos", "Terminal" onlarca satıcıda
                 aynı isimle bulunur. Satıcı ya da işletim sistemi bilgisi
                 olmadan hangi ürün olduğu belirlenemez.

  Kardeş bileşen "Microsoft Word" ile "Microsoft Excel" aynı pakete aittir ve
                 adlarının çoğu tokenı ortaktır; birinin CVE'si diğerine
                 uygulanamaz. Paketin kendisi ("Microsoft Office") ise her
                 bileşeni kapsar.

  Sürüm/sürüm-adı "Office Word 2016", "Acrobat Reader DC", "Chrome x64" gibi
                 adlarda yıl/edisyon/mimari tokenları ürün kimliğinin parçası
                 değildir ve eşleşmeyi bozar.
"""
from __future__ import annotations

import re
from typing import List, Optional, Set, Tuple

# Tek başına hiçbir ürünü tanımlamayan, birçok satıcıda aynı adla bulunan
# uygulama adları. Bunlar için satıcı ya da işletim sistemi bilgisi şarttır.
GENERIC_APP_NAMES: Set[str] = {
    "calendar", "notes", "photos", "mail", "messages", "maps", "music",
    "news", "podcasts", "reminders", "contacts", "clock", "weather",
    "calculator", "camera", "files", "gallery", "home", "health", "wallet",
    "books", "shortcuts", "stocks", "tips", "voice memos", "freeform",
    "terminal", "console", "settings", "preferences", "finder", "explorer",
    "store", "help", "search", "chat", "phone", "video", "player", "viewer",
    "editor", "browser", "monitor", "dashboard", "portal", "client", "agent",
    # "Apps" / "App Store": macOS envanterinde Apple'ın yer tutucu kayıtları.
    # Tek başına hangi uygulama olduğunu söylemiyorlar ve satıcı olmadan
    # "Microsoft 365 Apps for Enterprise" ile eşleşiyorlardı — tek kayıt 106
    # tehdit üretiyordu. "app store" ayrıca listelenmiyor: iki tokenı da
    # jenerik olduğu için aşağıdaki kural onu kendiliğinden yakalıyor.
    "app", "apps",
    "server", "manager", "updater", "installer", "launcher", "sync", "backup",
    "print", "scan", "paint", "screen", "keyboard", "mouse", "display",
}

# Yıl / edisyon / mimari tokenları — ürün KİMLİĞİNİ belirlemez.
_EDITION_TOKENS: Set[str] = {
    "professional", "pro", "plus", "standard", "home", "enterprise", "business",
    "premium", "basic", "starter", "ultimate", "essentials", "express",
    "ltsc", "ltsb", "dc", "classic", "legacy", "preview", "beta", "rc",
    "x64", "x86", "amd64", "arm64", "win32", "win64", "32bit", "64bit",
    "bit", "edition", "version", "setup", "installer", "runtime", "redistributable",
    "tr-tr", "en-us", "language", "pack", "update", "kb",
}

_YEAR_RE = re.compile(r"^(19|20)\d{2}$")
_VERSIONISH_RE = re.compile(r"^v?\d+(\.\d+)*$")

# Ofis paketi ve kardeş bileşenleri. Paket adı tüm bileşenleri kapsar; bileşenler
# birbirini kapsamaz.
_SUITES: Tuple[Tuple[str, Set[str]], ...] = (
    (
        "microsoft office",
        {
            "word", "excel", "powerpoint", "outlook", "access", "publisher",
            "onenote", "visio", "project", "skype", "teams", "sharepoint",
            "infopath", "lync", "groove",
        },
    ),
    (
        "adobe creative cloud",
        {
            "photoshop", "illustrator", "indesign", "premiere", "after effects",
            "acrobat", "lightroom", "animate", "audition", "dreamweaver",
        },
    ),
    (
        "libreoffice",
        {"writer", "calc", "impress", "draw", "base", "math"},
    ),
)

# İşletim sistemi → o sistemin birinci parti uygulamalarını üreten satıcı.
OS_VENDOR: dict = {
    "macos": "apple",
    "mac": "apple",
    "osx": "apple",
    "ios": "apple",
    "ipados": "apple",
    "windows": "microsoft",
    "win": "microsoft",
    "android": "google",
    "chromeos": "google",
}


# Gerçek envanterlerden gelen adlar dosya adı, kurulum paketi ya da paket
# yöneticisi koordinatı olabilir. Bunlar temizlenmezse hiçbir CVE ürünüyle
# eşleşmez.
_TRADEMARK_RE = re.compile(r"\((?:tm|r|c)\)|[™®©]", re.IGNORECASE)
_FILE_EXT_RE = re.compile(r"\.(exe|msi|dmg|pkg|deb|rpm|appx|msix|jar|zip)\b", re.IGNORECASE)
_MAVEN_COORD_RE = re.compile(r"^([a-z0-9_.-]+):([a-z0-9_.-]+)(?::.*)?$", re.IGNORECASE)
_PARENTHETICAL_RE = re.compile(r"\([^)]*\)")


def clean_inventory_name(name: str) -> str:
    """Envanterden gelen ham adı eşleştirilebilir bir ürün adına indirger.

    "TOMCAT9.EXE x64 setup"             → "TOMCAT9"
    "org.apache.tomcat:tomcat-catalina" → "tomcat catalina"
    "Java(TM) SE Development Kit"       → "Java SE Development Kit"
    """
    raw = (name or "").strip()
    if not raw:
        return ""

    # Paket yöneticisi koordinatı: grup:artifact → artifact adı ürünü belirler.
    coord = _MAVEN_COORD_RE.match(raw)
    if coord:
        raw = coord.group(2).replace("-", " ").replace(".", " ")

    raw = _TRADEMARK_RE.sub(" ", raw)
    raw = _FILE_EXT_RE.sub(" ", raw)
    # "(x64 edition)", "(tr-TR)" gibi parantezli ekler ürünü tanımlamaz.
    raw = _PARENTHETICAL_RE.sub(" ", raw)

    tokens = [t for t in re.split(r"[\s_/\\]+", raw) if t]
    kept = [t for t in tokens if t.lower() not in _INSTALLER_TOKENS]
    return " ".join(kept).strip() or raw.strip()


# Kurulum paketi adlarında geçen, ürünün parçası olmayan kelimeler.
_INSTALLER_TOKENS = {
    "setup", "installer", "install", "uninstall", "x64", "x86", "amd64",
    "arm64", "win32", "win64", "32bit", "64bit", "bit", "msi", "exe",
    "package", "bundle", "redist", "redistributable", "offline", "online",
}


def strip_edition_tokens(name: str) -> str:
    """Yıl, edisyon ve mimari tokenlarını atarak kimlik çekirdeğini bırakır.

    "Microsoft Office Word 2016 x64" → "microsoft office word"
    """
    tokens = re.split(r"[^a-z0-9.+#-]+", (name or "").lower())
    kept = [
        t for t in tokens
        if t
        and t not in _EDITION_TOKENS
        and not _YEAR_RE.match(t)
        and not _VERSIONISH_RE.match(t)
    ]
    return " ".join(kept)


# Windows envanterleri kurulu YAMALARI da uygulama gibi listeliyor:
#   "Update for x64-based Windows Systems (KB5099901)"   sürüm 3.12.0.0
#   "Security Update for Microsoft Office (KB5099902)"
#
# Bunlar ürün değil, uygulanmış güncellemedir — kendi CVE'leri yoktur. Ürün
# sanılırsa adı "Windows" ile eşleşir ve güncelleyicinin sürümü Windows
# derleme numaralarıyla kıyaslanır: yamanın KENDİSİ çok sayıda açık olarak
# raporlanır.
_UPDATE_PACKAGE_RE = re.compile(
    r"""(
          \(\s*KB\d{5,}\s*\)          # KB makale numarası — kesin işaret
        | ^\s*(security\s+)?update\s+for\b
        | ^\s*hotfix\b
        | ^\s*cumulative\s+update\b
        | ^\s*servicing\s+stack\s+update\b
        | ^\s*güvenlik\s+güncelleştirmesi\b
        | ^\s*güncelleştirme\b
    )""",
    re.IGNORECASE | re.VERBOSE,
)


def is_update_package(name: str) -> bool:
    """Envanter kalemi bir ürün değil, uygulanmış bir GÜNCELLEME mi?"""
    return bool(_UPDATE_PACKAGE_RE.search(name or ""))


def is_generic_product_name(name: str) -> bool:
    """Ad tek başına hangi ürün olduğunu belirlemiyorsa True.

    Yalnızca jenerik kelimelerden oluşan kısa adlar için geçerlidir; satıcı adı
    ya da ayırt edici bir token içeren adlar ("Apple Calendar", "Zimbra
    Calendar") jenerik sayılmaz.
    """
    core = strip_edition_tokens(name)
    if not core:
        return True
    if core in GENERIC_APP_NAMES:
        return True
    tokens = [t for t in core.split() if t]
    # 1-2 kelimelik ve tüm kelimeleri jenerik olan adlar ayırt edici değildir.
    return len(tokens) <= 2 and all(t in GENERIC_APP_NAMES for t in tokens)


def infer_vendor_from_os(operating_system: Optional[str]) -> Optional[str]:
    """İşletim sisteminden birinci parti satıcıyı çıkarır (macOS → Apple)."""
    if not operating_system:
        return None
    key = re.sub(r"[^a-z]", "", operating_system.lower())
    for prefix, vendor in OS_VENDOR.items():
        if key.startswith(re.sub(r"[^a-z]", "", prefix)):
            return vendor
    return None


def _suite_for(name_core: str) -> Optional[Tuple[str, Set[str]]]:
    for suite, components in _SUITES:
        if suite in name_core or any(c in name_core.split() for c in components):
            return suite, components
    return None


def suite_component(name: str) -> Optional[Tuple[str, Optional[str]]]:
    """Ad bir paket bileşeniyse (paket_adı, bileşen) döndürür.

    "Microsoft Office Word 2016" → ("microsoft office", "word")
    "Microsoft Office 2016"      → ("microsoft office", None)   # paketin kendisi
    """
    core = strip_edition_tokens(name)
    found = _suite_for(core)
    if not found:
        return None
    suite, components = found
    tokens = set(core.split())
    present = tokens & components
    return suite, (sorted(present)[0] if present else None)


# Ürün TÜRÜNÜ belirten, kimliği değiştirmeyen kelimeler ve satıcı adları.
# "MySQL Server" ile "MySQL" aynı üründür; "MySQL Cluster" değildir, bu yüzden
# 'cluster' bilinçli olarak bu listede yoktur.
_TYPE_WORDS: Set[str] = {
    "server", "client", "service", "services", "software", "suite", "platform",
    "edition", "runtime", "framework", "sdk", "desktop", "application", "app",
    "system", "core", "base", "standard", "professional", "pro", "community",
    "enterprise", "open", "source", "product", "tool", "tools", "package",
    # satıcılar
    "apache", "oracle", "microsoft", "google", "adobe", "ibm", "cisco", "eclipse",
    "mozilla", "redhat", "vmware", "atlassian", "sun", "novell", "hp", "hpe",
    "dell", "sap", "corporation", "corp", "inc", "ltd", "gmbh", "foundation",
    "project", "the", "of", "for", "and",
}


def identity_tokens(name: str) -> Set[str]:
    """Adın kimliğini belirleyen tokenlar — tür ve satıcı kelimeleri düşülür."""
    core = strip_edition_tokens(name)
    return {t for t in re.split(r"[^a-z0-9+#]+", core) if len(t) >= 2 and t not in _TYPE_WORDS}


def _identity_sequence(name: str) -> list:
    """Kimlik tokenları — SIRALI (kapsama değil, önek kıyaslaması için)."""
    core = strip_edition_tokens(name)
    return [
        t for t in re.split(r"[^a-z0-9+#]+", core)
        if len(t) >= 2 and t not in _TYPE_WORDS
    ]


def same_product_head(cve_product: str, inventory_product: str) -> bool:
    """Envanterdeki ad, CVE ürün adının BAŞINI mı oluşturuyor?

    "Formcrafter"      ↔ "Formcrafter Pro"          → evet
    "Acme"           ↔ "Acme NAC"               → evet
    "Countdown Timer"  ↔ "WordPress Countdown Timer" → HAYIR (baş değil, kuyruk)
    "VLC"              ↔ "Countdown Timer"           → hayır

    Alt küme yerine ÖNEK aranmasının nedeni: adın kuyruğunda geçmesi aynı ürün
    olduğunu göstermez. "WordPress Countdown Timer" bir WordPress eklentisidir;
    aynı adı taşıyan bir masaüstü uygulamasıyla karıştırılmamalıdır.
    """
    cve_seq = _identity_sequence(cve_product)
    inv_seq = _identity_sequence(inventory_product)
    if not cve_seq or not inv_seq or len(inv_seq) > len(cve_seq):
        return False
    return cve_seq[: len(inv_seq)] == inv_seq


def covers_product(cve_product: str, inventory_product: str) -> bool:
    """CVE ürünü, envanterdeki ürünü KAPSIYOR mu?

    Ölçüt yönlüdür: CVE'nin kimlik tokenları envanterinkilerin ALT KÜMESİ
    olmalı. Yani CVE daha genel (ya da eşit) adlandırma kullanabilir:

        "MySQL Server"            ⊆ "MySQL"            → evet (tür kelimesi)
        "Oracle GlassFish Server" ⊆ "GlassFish"        → evet
        "Apache Tomcat"           ⊆ "tomcat catalina"  → evet (bileşen envanteri)
        "MySQL Cluster"           ⊄ "MySQL"            → hayır (farklı ürün)

    Ters yön (CVE daha spesifik) kabul edilmez: bir bileşenin açığını tüm
    ürüne yaymak yanlış pozitif üretir.

    Dizi benzerliği bu ayrımı yapamaz — "MySQL Server" ↔ "MySQL" skoru 0.59'da
    kalır ve eşiği geçemez.
    """
    cve_tokens = identity_tokens(cve_product)
    inv_tokens = identity_tokens(inventory_product)
    if not cve_tokens or not inv_tokens:
        return False
    return cve_tokens <= inv_tokens


#: Bitişik yazılmış bileşik adın parça sınırları: "BrightwaveLinux" →
#: ["Brightwave", "Linux"]; "SkyDeskMac" → ["Sky", "Desk", "Mac"].
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

#: Ortak kökten SONRA gelebilecek, ürünü değiştirmeyen ekler. Yalnızca bunlar
#: kabul edilir; keyfi bir ek ürünü değiştirir ("ChromeOS" bir tarayıcı değil,
#: işletim sistemidir ve "Chrome" ile aynı sayılmamalı).
_PLATFORM_SUFFIXES: Set[str] = {
    "windows", "win", "mac", "macos", "osx", "linux", "unix", "android",
    "ios", "ipados", "server", "desktop", "mobile", "web", "cloud",
    # Sürüm/edisyon ekleri: aynı kod tabanının yapıları.
    "vpn", "client", "agent", "standalone", "portable",
}


def _compound_segments(name: str) -> List[str]:
    """Adı hem CamelCase hem ayraç sınırlarında parçalara böler.

    "SkyDeskMac"       → ["sky", "desk", "mac"]
    "SkyDesk Agent"    → ["skydesk", "agent"]      (boşluk CamelCase'i bozmaz)
    """
    spaced = _CAMEL_RE.sub(" ", name or "")
    return [
        t for t in (re.sub(r"[^a-z0-9]", "", p.lower()) for p in re.split(r"[\s_/\\-]+", spaced))
        if t
    ]


def _prefix_tails(segments: List[str]) -> dict:
    """Parça sınırında biten her ön ek → o ön ekten sonra kalan parçalar.

    ["sky","desk","mac"] →
        {"sky": ["desk","mac"], "skydesk": ["mac"],
         "skydeskmac": []}
    """
    out: dict = {}
    acc = ""
    for i, seg in enumerate(segments):
        acc += seg
        out[acc] = segments[i + 1:]
    return out


def _same_compound_family(first: str, second: str) -> bool:
    """İki ad aynı ürün ailesinin farklı yapıları mı?

    Satıcıların bir bölümü ürün ailesini bitişik yazar: BrightwaveLinux,
    BrightwaveMac, BrightwaveConsole. Envanterde ise "Brightwave Agent" durur.
    Token kıyaslaması ortak TEK bir token bulamaz ("brightwavelinux" tek
    parça kalır) ve ürünün CVE'leri hiç aday olamaz.

    Karşılaştırma parça DİZİSİ üzerinden değil, parça sınırında biten ÖN EKLER
    üzerinden yapılır: aynı ürün iki kaynakta farklı bölünmüş olabiliyor
    ("SkyDeskMac" üç parça, "SkyDesk Agent" iki parça) ve dizi
    kıyaslaması daha ilk adımda kopar.

    İki şart birlikte aranır:

    1. Ortak bir ön ek bulunmalı (en uzunu seçilir).
    2. Ön ekten SONRA kalan parçaların HEPSİ platform/edisyon eki olmalı.
       "ChromeOS" ile "Chrome" ortak "chrome" ön ekini paylaşır ama kalan "os"
       platform eki değil — biri tarayıcı, öteki işletim sistemi. Aynı şekilde
       BrightwaveOS ile BrightwaveRouter "brightwave"ı paylaşır, kalanlar
       "os"/"router"dır.
    """
    first_segments = _compound_segments(first)
    second_segments = _compound_segments(second)

    # Katalog adı satıcıyla birleşik gelebiliyor ("Woodgrove BrightwaveLinux")
    # ve satıcı ön eki ortak kökü bozuyor; baştaki bir parçayı atarak da denenir.
    # Gevşetme değil: aşağıdaki "kalan parçalar platform eki olmalı" şartı
    # yerinde duruyor, o yüzden "Woodgrove BrightwaveOS" ↔ "BrightwaveRouter" yine ayrık.
    pairs = [(first_segments, second_segments)]
    if len(first_segments) > 1:
        pairs.append((first_segments[1:], second_segments))
    if len(second_segments) > 1:
        pairs.append((first_segments, second_segments[1:]))

    for left, right in pairs:
        a, b = _prefix_tails(left), _prefix_tails(right)
        shared = set(a) & set(b)
        if not shared:
            continue
        root = max(shared, key=len)
        tail = a[root] + b[root]
        if tail and all(t in _PLATFORM_SUFFIXES for t in tail):
            return True
    return False


def same_compound_family(first: str, second: str) -> bool:
    """Dışarıya açık hâli — arama katmanı da aynı kuralı kullanır."""
    return _same_compound_family(first, second)


def names_conflict(first: str, second: str) -> bool:
    """İki ad farklı ürünleri mi anlatıyor?

    Ölçüt kimlik tokenlarının AYRIK olması. Sondaki sürüm rakamı atılır ki
    dosya adından gelen "TOMCAT9" ile "Tomcat" aynı kökte buluşsun; buna karşın
    "ChromeOS" ile "Chrome" ayrı kalır ve çakışma olarak işaretlenir.

    Dizi benzerliği bu ayrımı yapamaz: "ChromeOS" ile "Chrome" %86 benzerdir.
    """
    def stems(name: str) -> Set[str]:
        return {re.sub(r"\d+$", "", t) or t for t in identity_tokens(name)}

    first_tokens, second_tokens = stems(first), stems(second)
    if not first_tokens or not second_tokens:
        return False  # karar verecek bilgi yok; engelleme
    if first_tokens & second_tokens:
        return False
    # Ortak token yok ama adlardan biri bitişik yazılmış olabilir.
    return not _same_compound_family(first, second)


# Satıcı adlarındaki kurumsal ekler — kimliği değiştirmez.
# "PostgreSQL Global Development Group" ile "PostgreSQL" aynı satıcıdır.
_CORPORATE_SUFFIXES: Set[str] = {
    "inc", "inc.", "ltd", "ltd.", "llc", "corp", "corp.", "corporation",
    "gmbh", "sa", "sas", "ag", "bv", "nv", "plc", "co", "company",
    "foundation", "project", "projects", "group", "development", "global",
    "software", "technologies", "technology", "systems", "solutions", "labs",
    "team", "community", "org", "the", "and", "of",
}


def vendors_conflict(first: str, second: str) -> bool:
    """İki satıcı adı FARKLI satıcıları mı gösteriyor?

    `names_conflict` burada kullanılamaz: o, ÜRÜN adları için tasarlandığından
    satıcı kelimelerini (microsoft, oracle…) kimlik dışı sayıp atar ve satıcı
    karşılaştırmasında geriye hiçbir token kalmaz.

    Burada yalnızca kurumsal ekler ("Inc", "Foundation", "Global Development
    Group") atılır; geriye kalan adlar ayrıksa satıcılar farklıdır.
    """
    def core(name: str) -> Set[str]:
        tokens = re.split(r"[^a-z0-9]+", (name or "").lower())
        return {t for t in tokens if t and t not in _CORPORATE_SUFFIXES}

    first_tokens, second_tokens = core(first), core(second)
    if not first_tokens or not second_tokens:
        return False  # karar verecek bilgi yok
    return not (first_tokens & second_tokens)


def match_aliases(name: str) -> list:
    """Bir ürün adının eşleşmede denenecek eşdeğer biçimleri.

    Envanter adları paket ve bileşeni birlikte yazar ("Microsoft Office Word
    2016"), CVE kayıtları ise ya bileşeni ("Microsoft Word") ya da paketi
    ("Microsoft Office 2016") adlandırır. Her iki biçimi de üretmezsek bu
    CVE'lerin çoğu eşleşmeden elenir.

    "Microsoft Office Word 2016" →
        ["microsoft office word", "microsoft word", "microsoft office"]
    """
    core = strip_edition_tokens(name)
    aliases = [core] if core else []

    found = suite_component(name)
    if found:
        suite, component = found
        if component:
            # Paket adının satıcı öneki + bileşen ("microsoft" + "word").
            # Çıplak bileşen adı ("word") bilerek eklenmez: "WordPress" gibi
            # ilgisiz ürünlere eşleşecek kadar jeneriktir.
            vendor_prefix = suite.split()[0]
            aliases.append(f"{vendor_prefix} {component}")
        # Paketin kendisi de geçerli bir eşleşme hedefidir (paket CVE'leri
        # bileşeni kapsar).
        aliases.append(suite)

    seen, out = set(), []
    for alias in aliases:
        alias = (alias or "").strip()
        if alias and alias not in seen:
            seen.add(alias)
            out.append(alias)
    return out


def component_conflict(cve_product: str, customer_product: str) -> Optional[str]:
    """İki ad aynı paketin FARKLI bileşenleriyse çakışma açıklaması döndürür.

    Word ↔ Excel gibi kardeş bileşenler adlarının çoğunu paylaşır ve bulanık
    eşleme bunları aynı ürün sanabilir. Paketin kendisi (bileşensiz) her
    bileşeni kapsadığı için çakışma sayılmaz.
    """
    cve_side = suite_component(cve_product)
    customer_side = suite_component(customer_product)
    if not cve_side or not customer_side:
        return None
    cve_suite, cve_component = cve_side
    cust_suite, cust_component = customer_side
    if cve_suite != cust_suite:
        return None
    # Taraflardan biri paketin kendisiyse kapsama vardır, çakışma yoktur.
    if cve_component is None or cust_component is None:
        return None
    if cve_component == cust_component:
        return None
    return (
        f"CVE '{cve_product}' bileşenini hedefliyor; envanterdeki ürün "
        f"'{customer_product}' aynı paketin farklı bir bileşeni "
        f"({cust_component} ≠ {cve_component})"
    )
