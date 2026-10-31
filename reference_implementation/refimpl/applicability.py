"""
Uygulanabilirlik kapıları — bir CVE bu uç noktadaki bu ürüne gerçekten uygulanır mı?

Ürün adı eşleşse bile CVE başka bir şeyi hedefliyor olabilir: bir WordPress
eklentisi, bir dil binding'i, başka bir işletim sistemi ya da başka bir vendor.
Bu kapılar THREAT/UNCERTAIN kararlarını SAFE'e (not_applicable) indirir.
"""
from __future__ import annotations

import re
from typing import Optional

# Tek başına eşleştiğinde yanlış pozitif üreten, ürünü tanımlamayan generic tokenlar.
GENERIC_PRODUCT_TOKENS = {
    "agent", "manager", "server", "client", "service", "services", "app",
    "application", "software", "tool", "tools", "suite", "framework", "sdk",
    "driver", "plugin", "extension", "library", "system", "console", "studio",
    "player", "viewer", "editor", "browser", "edition", "home", "pro", "core",
    "enterprise", "platform", "engine", "module", "package", "the", "for",
    "and", "of", "based", "chromium",
    # Paketleme/bileşen kelimeleri: tek başına ürün KİMLİĞİ belirlemez. Tek ortak
    # kelime bunlardan biriyse yükseltme yapma (ör. JetBrains 'Runtime' ↦ MS Visual
    # C++ 'Runtime', 'Enterprise Health' ↦ 'Update Health Tools' yanlış pozitifleri).
    "runtime", "health", "update", "updates", "redistributable", "redist",
    "additional", "minimum", "installer", "components", "component", "hub",
    "host", "common", "shared", "support", "utility", "utilities", "manager.",
}

# Müşteri platformu farklıysa yükseltmeyi engelleyen, CVE'ye özgü platform ipuçları.
_OTHER_PLATFORM_TOKENS = {
    "android", "ios", "iphone", "ipad", "ipados", "macos", "mac os",
    "linux", "ubuntu", "debian", "android.", "for android", "for ios",
}

# OS ailesi saptama: ürün+metinden hedef işletim sistemini çıkarır. Yalnızca TEK
# bir aile saptanırsa o aile döner; birden fazla (çapraz-platform) ya da hiç ipucu
# yoksa None döner (None → çatışma yok, her uç noktaya uygulanır).
OS_FAMILY_PATTERNS = {
    "windows": r"\b(windows|win32|win64|winexec|windir|powershell|\.exe)\b",
    "macos": r"\b(macos|mac os|os x|osx|darwin|macintosh|\.dmg)\b",
    "linux": r"\b(linux|ubuntu|debian|red\s?hat|centos|fedora|glibc|\.deb|\.rpm)\b",
    "android": r"\b(android)\b",
    "ios": r"\b(ios|iphone|ipad|ipados)\b",
}

# Web/CMS eklenti CVE'leri: bir uç-nokta uygulama envanterine uygulanamaz.
# (ör. "Countdown & Clock (WordPress plugin)", "Jenkins Mask Passwords Plugin")
_WEB_CMS_RE = re.compile(
    r"\b(wordpress|woocommerce|wp|drupal|joomla|typo3|magento|prestashop|"
    r"elementor|jenkins|moodle|phpmyadmin|shopify|bigcommerce)\b"
)
# CVE ürün adının kendisi bir eklenti/tema ise (host-app değil) → uygulanamaz.
_PLUGIN_WORD_RE = re.compile(r"\b(plugin|add-?on|theme|widget)\b")

# Bir ürünün BAŞKA bir ürüne eklenti olduğunu gösteren ifadeler. "X for WordPress"
# kalıbı çekirdek uygulamayı değil, ona takılan bir bileşeni adlandırır.
_ADDON_PHRASE_RE = re.compile(
    r"\b(for|plugin|add-?on|theme|widget|extension|integration|connector|module)\b"
)

# Patchstack/WordPress CNA şablonu: "...This issue affects X: from n/a through
# <= y.z". Bu ifade neredeyse yalnızca WordPress eklenti/tema CVE'lerinde görülür.
_PATCHSTACK_RE = re.compile(r"from n/?a through")

# Yalnızca WordPress/CMS eklentisi üreten, bu nedenle masaüstü uygulamalarıyla
# isim çakışması yaratan bilinen vendor'lar.
_WEB_PLUGIN_VENDORS = {
    "miniorange", "expresstechsoftware", "uncanny owl", "wpdeveloper",
    "themeisle", "wpmudev", "cyberlord92", "tmsproducts", "wpchill",
}

# Dil-binding/wrapper CVE'leri: temel kütüphaneyle aynı uç noktada DEĞİLDİR.
# (ör. "Crypt::OpenSSL::PKCS12 ... for Perl" → envanter "OpenSSL" C kütüphanesine
#  uygulanamaz; adında 'OpenSSL' geçtiği için yanlış eşleşir.)
_BINDING_PHRASES = (
    "for perl", "perl module", "perl binding",
    "for python", "python package", "python module", "python binding", "pypi",
    "for ruby", "rubygem", "ruby gem",
    "for php", "php extension", "php module", "composer package",
    "for node", "node module", "npm package", "nodejs module",
    "for java", "java library", "maven package",
    "for rust", "rust crate", "cargo crate",
    "for go ", "golang package",
)

# Dil/ekosistem işaret tokenları — ürün KİMLİĞİ belirlemez.
_LANG_TOKENS = {
    "perl", "python", "ruby", "php", "node", "nodejs", "npm", "go", "golang",
    "rust", "java", "maven", "pypi", "rubygem", "gem", "crate", "composer",
    "cpan", "module", "package", "binding", "bindings", "extension", "wrapper",
}


def os_family(text: str) -> Optional[str]:
    """Metinden TEK bir OS ailesi saptanırsa onu döndürür, aksi halde None."""
    t = (text or "").lower()
    hits = [fam for fam, pat in OS_FAMILY_PATTERNS.items() if re.search(pat, t)]
    return hits[0] if len(hits) == 1 else None


def tokenize_product(name: str) -> set:
    return {t for t in re.split(r"[^a-z0-9]+", (name or "").lower()) if t}


def product_identity_ok(cve_product: str, customer_product: str) -> bool:
    """CVE ürünü, müşteri ürünüyle EN AZ bir spesifik (generic olmayan) token
    paylaşıyorsa kimlik eşleşmesi sayılır. Yalnızca generic token ('Agent',
    'Manager' gibi) içeren CVE ürünleri yükseltmeyi tetiklemez."""
    cve_toks = tokenize_product(cve_product)
    cust_toks = tokenize_product(customer_product)
    specific = cve_toks - GENERIC_PRODUCT_TOKENS
    if not specific:
        return False  # CVE ürünü yalnızca generic token → kimlik belirsiz
    return bool(specific & cust_toks)


def platform_mismatch(
    cve_product: str,
    cve_text: str,
    customer_product: str,
    customer_platform: Optional[str],
) -> bool:
    """CVE açıkça başka bir platforma özgüyse (ör. 'for Android') ve müşteri
    kaydında o platform ipucu yoksa True döner → yükseltme engellenir.

    **Metin müşterinin KENDİ platformunu da anıyorsa uyuşmazlık YOKTUR.**
    Bazı satıcı bültenleri bir açığın düzeltildiği tüm platformları tek cümlede
    sayar: "fixed in Orbital Browser 12.5, iOS 18.7 and macOS 15.5". Yalnızca
    "başka platform geçiyor mu" diye bakmak burada "ios" görüp macOS uç noktası
    için uyuşmazlık ilan eder ve yapısal sınırdan gelen YÜKSELTMEYİ engeller;
    gerçek tehditler böyle kaçar.
    """
    hay = f"{cve_product} {cve_text}".lower()
    cust = f"{customer_product} {customer_platform or ''}".lower()

    # Müşterinin platformu metinde geçiyorsa CVE onu da kapsıyor demektir.
    for tok in _OTHER_PLATFORM_TOKENS:
        if tok in cust and tok in hay:
            return False

    return any(tok in hay and tok not in cust for tok in _OTHER_PLATFORM_TOKENS)


def _is_host_core(cve_product: str, customer_product: str) -> bool:
    """CVE ürünü, envanterdeki host uygulamanın KENDİSİ mi?

    "WordPress", "Automattic WordPress", "Drupal core" çekirdektir.
    "GetResponse for WordPress", "Contact Form 7" ise ayrı bir eklentidir.

    Ölçüt: (1) eklenti bildiren bir ifade geçmemeli; (2) host adı CVE ürününde
    geçmeli; (3) geriye kalan ayırt edici tokenlar host adından ÖNCE gelmeli —
    yani yalnızca satıcı öneki olmalı ("Automattic WordPress"), sonrasında
    başka bir ürün adı gelmemeli.
    """
    if _ADDON_PHRASE_RE.search(cve_product):
        return False

    cve_tokens = [t for t in re.split(r"[^a-z0-9]+", cve_product) if t]
    host_tokens = [t for t in re.split(r"[^a-z0-9]+", customer_product) if t]
    if not host_tokens or not set(host_tokens).issubset(cve_tokens):
        return False

    # Host adı birden çok kez geçebilir ("WordPress.org WordPress"); kuyruk
    # hesabı SON geçtiği yerden başlamalı.
    last_host_index = max(
        i for i, token in enumerate(cve_tokens) if token in set(host_tokens)
    )
    trailing = set(cve_tokens[last_host_index + 1 :]) - GENERIC_PRODUCT_TOKENS
    return not trailing


#: "... are not affected" ifadesinden ÖNCE gelen kısım. Satıcı bültenleri
#: etkilenmeyen platformları böyle sayıyor ve bu cümle `os_family`'yi işlevsiz
#: bırakıyor: tek metinde altı işletim sistemi geçtiği için "birden çok aile →
#: karar verme" kuralı devreye giriyor ve kapı hiç yanmıyor.
_NOT_AFFECTED_RE = re.compile(r"([^.;]{0,240}?)\b(?:are|is)\s+not\s+affected", re.I)


def platform_declared_unaffected(cve_text: str, endpoint_platform: Optional[str]) -> bool:
    """CVE metni uç noktanın platformunu AÇIKÇA etkilenmiyor ilan ediyor mu?

    "A path traversal flaw in the Woodgrove Sync Agent **for Windows** ...
    Woodgrove Sync Agent for **macOS**, Linux, iOS and Android **is not
    affected**." — macOS uç noktasında bu bir tehdit değil, ama metinde birden
    çok platform geçtiği için OS ailesi kapısı karar veremez.

    Ölçüt dar tutuldu: yalnızca ifadeden ÖNCEKİ kısımda uç noktanın ailesi
    geçiyorsa yanar. "Versions before 3.2 are not affected" gibi cümlelerde
    platform tokenı olmadığı için kapı sessiz kalır.
    """
    if not cve_text or not endpoint_platform:
        return False
    family = os_family(endpoint_platform)
    if not family:
        return False
    pattern = OS_FAMILY_PATTERNS[family]
    return any(
        re.search(pattern, m.group(1).lower())
        for m in _NOT_AFFECTED_RE.finditer(cve_text)
    )


def _same_plugin_identity(cve_product: str, customer_product: str) -> bool:
    """CVE ürünü ile envanter kalemi AYNI eklenti mi?

    Tür ve eklenti kelimeleri atıldıktan sonra kimlik tokenları BİREBİR aynı
    olmalı. Kapsama/önek yeterli değil — ikisi de envanterdeki kısa jenerik adı
    ("Photos", "Games", "Maps") eklentinin kendisi sayıyordu.
    """
    from refimpl.disambiguation import identity_tokens

    def strip(name: str) -> set:
        return {t for t in identity_tokens(name) if not _PLUGIN_WORD_RE.search(t)}

    a, b = strip(cve_product), strip(customer_product)
    return bool(a) and bool(b) and a == b


def is_web_cms_plugin(
    cve_product: str,
    cve_text: str,
    cve_vendor: str = "",
    customer_product: str = "",
) -> bool:
    """CVE açıkça bir web/CMS eklentisi/teması (WordPress/WooCommerce/Jenkins ...)
    ise True. Bu tür CVE'ler masaüstü/uç-nokta uygulamalarına uygulanamaz.

    Sinyaller: (1) ürün adı VEYA metinde net bir CMS işareti (regex, kelime
    sınırıyla — 'uwp' gibi yanlış eşleşmeleri önler); (2) CVE ÜRÜN adının kendisi
    bir eklenti/tema/widget kelimesi içeriyorsa; (3) CVE vendor'ı bilinen bir
    salt-WordPress eklenti üreticisiyse.

    Kapı, envanterdeki ürünün KENDİSİ o CMS/host uygulama olduğunda çalışmaz:
    "WordPress 4.7" sorgulandığında WordPress CVE'lerini elemek, taranan ürünün
    tüm açıklarını yok saymak olurdu.
    """
    prod = (cve_product or "").lower()
    customer = (customer_product or "").lower()

    # Envanter ürünü CMS'in KENDİSİ ise (ör. "WordPress"), o CMS'in ÇEKİRDEK
    # CVE'leri uygulanabilir — aksi halde taranan ürünün tüm açıkları elenirdi.
    if customer and prod and _WEB_CMS_RE.search(customer) and _is_host_core(prod, customer):
        return False

    # Envanterdeki ürün EKLENTİNİN KENDİSİ ise kapı çalışmamalı. Kapının amacı
    # bir WordPress eklentisinin açığını ilgisiz bir masaüstü uygulamasına
    # yaymamaktır; taranan ürün eklentinin ta kendisiyse yayılma yok, CVE
    # doğrudan onu ilgilendirir ("Formcrafter" eklentisinin kendisi taranıyorsa).
    #
    # Ölçüt ÖZDEŞLİK, önek DEĞİL. Önek ölçütü çok gevşek: "Recipe Box" adı
    # "Recipe Box Importer"ın önekini oluşturur ve aynı adlı bir masaüstü
    # uygulaması bir WordPress eklentisinin CVE'lerini alır ("Weather" ↔
    # "Weather Widget Deluxe" aynı desen).
    #
    # CVE'nin TÜR kelimesi eklemesi ("... Plugin") özdeşliği bozmaz; ürün adı
    # eklemesi bozar.
    if customer and prod and _same_plugin_identity(cve_product, customer_product):
        return False

    hay = f"{prod} {(cve_text or '').lower()}"
    if _WEB_CMS_RE.search(hay):
        return True
    if _PLUGIN_WORD_RE.search(prod):
        return True
    if _PATCHSTACK_RE.search(cve_text or ""):
        return True
    return (cve_vendor or "").strip().lower() in _WEB_PLUGIN_VENDORS


def vendor_not_applicable(
    cve_vendor: str,
    customer_vendor: Optional[str],
    cve_product: str = "",
) -> bool:
    """CVE'nin satıcısı, envanterdeki ürünün satıcısıyla ÇELİŞİYOR mu?

    Üç tuzak bilinçli olarak elenir:

    1. CVE satıcısı BİLİNMİYORSA (boş ya da "n/a") uyuşmazlık çıkarılamaz.
       Eskiden bu da reddediliyordu ve kayıtların büyük kısmında satıcı alanı
       boş olduğu için DOĞRU satıcı bilgisi vermek taramayı bozuyordu:
       PostgreSQL 16, vendor="PostgreSQL" verilince THREAT yerine SAFE dönüyordu.

    2. Satıcı adları birebir yazılmaz — "PostgreSQL", "PostgreSQL Global
       Development Group" ve "PostgreSQL Project" aynı satıcıdır. Karşılaştırma
       dize eşitliğiyle değil, kurumsal ekler atılarak yapılır.

    3. **CNA satıcı alanına ÜRÜN adını yazmış olabilir.** Tek ürünlü projelerde
       çok yaygın: `vendor="Glimmerpost", product="Glimmerpost"`. Böyle bir alan
       satıcı bilgisi taşımaz — "n/a"dan farkı yoktur. Envanterdeki gerçek
       yazarla karşılaştırılınca çelişki üretir ve ürünün TÜM CVE'leri elenir;
       satıcı vermeden taramak sonucu düzeltir, ki bu tam tersi olmalı.
    """
    if not customer_vendor:
        return False

    cve_vendor = (cve_vendor or "").strip()
    if not cve_vendor or cve_vendor.lower() in ("n/a", "na", "unknown", "-"):
        return False  # bilinmeyen satıcıdan çelişki çıkarılamaz

    from refimpl.disambiguation import vendors_conflict

    # Ölçüt ÖRTÜŞME değil ÖZDEŞLİK. "Fabrikam" satıcısı ile "Fabrikam Calendar"
    # ürünü token paylaşır ama satıcı alanı gerçek ve ayırt edici bilgidir;
    # örtüşmeyi yeterli saymak başka bir satıcının "Calendar" uygulamasına
    # Fabrikam takviminin CVE'lerini sızdırır.
    if cve_product:
        from refimpl.disambiguation import identity_tokens

        vendor_core = identity_tokens(cve_vendor)
        if vendor_core and vendor_core == identity_tokens(cve_product):
            # Satıcı alanı ürün adının kendisi; "n/a"dan farkı yok.
            return False

    return vendors_conflict(cve_vendor, customer_vendor)


def is_language_binding_mismatch(
    cve_product: str, cve_text: str, customer_product: str
) -> bool:
    """CVE bir dil-binding'i/wrapper'ı (Perl/Python/Ruby...) iken müşteri ürünü
    temel kütüphane ise True → uygulanamaz. Yüksek precision:
      A) Perl/C++ namespace 'Foo::Bar' (müşteride '::' yoksa), VEYA
      B) net 'for <dil>' / '<dil> package' ifadesi VE CVE ürününün müşteride
         OLMAYAN ekstra spesifik kimlik tokenı taşıması (ör. Crypt/PKCS12).
    Böylece müşterinin kendisi o paket olduğunda (envanter 'cryptography') elenmez."""
    cp = cve_product or ""
    customer = customer_product or ""
    if "::" in cp and "::" not in customer:
        return True
    hay = f"{cp} {cve_text or ''}".lower()
    if not any(phrase in hay for phrase in _BINDING_PHRASES):
        return False
    cve_specific = tokenize_product(cp) - GENERIC_PRODUCT_TOKENS - _LANG_TOKENS
    cust_tokens = tokenize_product(customer)
    # CVE, müşteride olmayan ekstra spesifik bir ürün adı içeriyorsa → farklı ürün.
    return bool(cve_specific - cust_tokens)
