"""
Yanlış pozitif SINIFLARI — bağımsız tasarlanmış sentetik vakalar.

Her sınıf (OS'un kendisine ait CVE, "etkilenmiyor" ilan edilen platform, yaygın
kelime kimliği, bilinen ayrı ürün çifti, çapraz ürün metni, yabancı sürüm
sınırı, eklenti önek muafiyeti, katalog spesifikliği) bu paket için yazılmış
kurgusal ürün adları, sürümler ve bülten cümleleriyle kurulmuştur; hiçbir vaka
bir envanterden, olay kaydından ya da önceki bir vaka listesinin yeniden
adlandırılmasından türetilmemiştir. İşletim sistemi adları (Windows, Android,
macOS) ve büyük satıcı adları (IBM, Microsoft, Google) kuralların sözlüğü
olduğu için gerçektir. Aynı vakalar Go motorunda
(`goscan/falsepositive_test.go`) da kilitli, iki motor sessizce ayrışmasın diye.

Muafiyet testleri en az elemeler kadar önemli: her kural, muafiyeti olmadan
gerçek tehdit de eler.
"""
from __future__ import annotations

import pytest

from refimpl import applicability as app_gates
from refimpl import identity
from refimpl.scanner import _identity_covers, _specificity_reject


class TestIsletimSistemiUrunu:
    """CVE işletim sisteminin KENDİSİne aitse, üzerinde çalışan uygulamaya uygulanmaz."""

    @pytest.mark.parametrize(
        "cve_product,inventory",
        [
            # Adında bir OS adı geçen UYGULAMALAR; OS'un CVE'leri onlara yazılmamalı.
            ("Microsoft Windows Server 2022", "Windows Snip Studio"),
            ("Google Android", "Android Photo Courier"),
        ],
    )
    def test_os_cvesi_uygulamaya_yazilmaz(self, cve_product, inventory):
        assert identity.structured_identity_ok(cve_product, inventory)

    def test_envanterin_kendisi_os_ise_kural_islemez(self):
        assert identity.structured_identity_ok("Microsoft Windows", "Windows 11") is None
        assert identity.structured_identity_ok("Google Android", "Android 15") is None

    def test_uygulama_adi_os_urunu_sayilmaz(self):
        # Ad bir OS tokenı taşısa bile bütünü bir işletim sistemi değil.
        assert identity.is_same_operating_system("Windows Snip Studio") is False
        assert identity.is_same_operating_system("Windows 11") is True


class TestPlatformAcikcaEtkilenmiyor:
    """Satıcı bülteni etkilenmeyen platformları sayıyorsa OS ailesi kapısı çaresiz."""

    SYNC_AGENT = (
        "A path traversal flaw in the Woodgrove Sync Agent for Windows allows a "
        "local user to overwrite arbitrary files. Woodgrove Sync Agent for macOS, "
        "Linux, iOS and Android is not affected."
    )

    def test_etkilenmiyor_denen_platform_elenir(self):
        assert app_gates.platform_declared_unaffected(self.SYNC_AGENT, "macOS")

    def test_etkilenen_platform_elenmez(self):
        assert not app_gates.platform_declared_unaffected(self.SYNC_AGENT, "Windows")

    def test_os_ailesi_kapisi_bu_metinde_karar_veremiyor(self):
        # Kuralın var olma nedeni: birden çok aile geçtiği için `os_family`
        # None dönüyor ve klasik OS kapısı hiç yanmıyor.
        assert app_gates.os_family(self.SYNC_AGENT) is None

    def test_platformsuz_cumle_kapiyi_yakmaz(self):
        assert not app_gates.platform_declared_unaffected(
            "Releases before 8.4 are not affected.", "macOS"
        )


class TestYayginKelimeKimligi:
    def test_yalnizca_yaygin_kelime_kimlik_sayilmaz(self):
        # "IBM Secure Gateway" satıcı atılınca {secure, gateway}'e iner ve token
        # kapsaması onu "Kestrel Secure Gateway"in alt kümesi sayar.
        assert identity.structured_identity_ok("IBM Secure Gateway", "Kestrel Secure Gateway")

    def test_ayni_ad_yaygin_kelime_olsa_bile_gecer(self):
        # "Weather" ile "Weather" gerçekten aynı üründür.
        assert identity.structured_identity_ok("Weather", "Weather") is None

    def test_ayirt_edici_token_varsa_gecer(self):
        assert identity.structured_identity_ok("Litware Inkwell Notes", "Inkwell Notes") is None


class TestAyriUrunCiftleri:
    @pytest.mark.parametrize(
        "cve_product,inventory",
        [
            ("ravenmail server", "Ravenmail"),
            ("Ravenmail SDK", "Ravenmail"),
            ("Pinecrest", "Pinecrest Studio"),
            ("OrchardSync Enterprise", "OrchardSync"),
            ("Glasswing Publisher", "Glasswing Reader"),
        ],
    )
    def test_bilinen_ayri_urunler_elenir(self, cve_product, inventory):
        assert identity.distinct_product_pair(cve_product, inventory)

    def test_envanterin_kendisi_o_urunse_elenmez(self):
        # Ölçüt TAM AD; alt dize kullanmak "Pinecrest Studio"yu "Pinecrest"ın
        # kendisi sayar ve kuralı iptal eder.
        assert identity.distinct_product_pair("Pinecrest", "Pinecrest") is None
        assert identity.distinct_product_pair("OrchardSync Enterprise", "OrchardSync Enterprise") is None


class TestCaprazUrunMetni:
    """CVE METNİ envanterdekinden farklı bir ürünü adlandırıyorsa kimlik reddedilir."""

    def test_yabanci_urun_metinde_gecerse_reddedilir(self):
        ok, reason, method = identity.assess_threat_product_identity({
            "product_normalized": "brindle",
            "description": "An SSRF in the Brindle Cloud Console allows tenant data exposure.",
            "your_version": "3.2.0", "constraint_version": "< 5.0",
        })
        assert (ok, method) == (False, "rejected") and "Brindle Cloud Console" in reason

    def test_alt_urun_ailesi_reddedilir(self):
        # `_DISTINCT_SUBPRODUCTS`: envanterde "corvane", metinde "corvane relay".
        ok, _, method = identity.assess_threat_product_identity({
            "product_normalized": "corvane viewer",
            "description": "Corvane Relay before 2.8 mishandles session tokens.",
            "your_version": "6.1", "constraint_version": "< 2.8",
        })
        assert (ok, method) == (False, "rejected")

    def test_metin_yalnizca_envanterdeki_urunu_aniyorsa_gecer(self):
        ok, reason, method = identity.assess_threat_product_identity({
            "product_normalized": "brindle",
            "description": "A crafted project file crashes Brindle before 3.4.",
            "your_version": "3.2.0", "constraint_version": "< 3.4",
            "product_match_source": "catalog",
        })
        assert (ok, reason, method) == (True, None, "catalog")


class TestYabanciSurumSiniri:
    """Sınır metinde başka bir ürünün adının yanında geçiyorsa o ürüne aittir."""

    TEXT = ("Quillon desktop editor embeds quillon-py; quillon-py before 0.9.4 "
            "allows code execution through crafted notebooks.")

    def test_sinir_yabanci_urune_aitse_reddedilir(self):
        ok, reason, method = identity.assess_threat_product_identity({
            "product_normalized": "quillon",
            "description": self.TEXT,
            "your_version": "4.2.1", "constraint_version": "< 0.9.4",
        })
        assert (ok, method) == (False, "rejected")

    def test_envanterin_kendisi_o_paketse_kural_islemez(self):
        assert identity._foreign_version_binding("quillon-py", "0.9.1", "< 0.9.4", self.TEXT) is None


class TestEklentiMuafiyetiOzdeslikIster:
    """Web/CMS eklenti kapısının muafiyeti ÖNEK değil ÖZDEŞLİK ister."""

    @pytest.mark.parametrize(
        "cve_product,cve_text,inventory",
        [
            ("Recipe Box Importer", "WordPress plugin", "Recipe Box"),
            ("Weather Widget Deluxe", "WordPress plugin", "Weather"),
        ],
    )
    def test_onek_muafiyet_saglamaz(self, cve_product, cve_text, inventory):
        assert app_gates.is_web_cms_plugin(cve_product, cve_text, "", inventory)

    def test_eklentinin_kendisi_taranirsa_kapi_yanmaz(self):
        # Taranan ürün eklentinin ta kendisiyse yayılma yok.
        assert not app_gates.is_web_cms_plugin(
            "Formcrafter", "WordPress plugin", "", "Formcrafter"
        )

    def test_tur_kelimesi_ozdesligi_bozmaz(self):
        assert not app_gates.is_web_cms_plugin(
            "Tablewright Plugin", "WordPress plugin", "", "Tablewright"
        )


class TestKatalogSpesifikligi:
    """Katalog ürünü kendi adıyla tanıyorsa CVE en az o kadar spesifik olmalı."""

    def test_daha_genel_urun_elenir(self):
        # Daha genel bir ürünün ("Inkwell 2024") CVE'si "Inkwell Notes"a yazılmamalı.
        assert _specificity_reject(
            "Litware Inkwell 2024 version 9.1", "Inkwell Notes",
            "inkwell notes", exact_catalog=True,
        )

    def test_ayni_urun_gecer(self):
        assert _specificity_reject(
            "Litware Inkwell Notes", "Inkwell Notes",
            "inkwell notes", exact_catalog=True,
        ) is None

    def test_jenerik_adda_cve_adi_birebir_tutmali(self):
        # "Halcyon Music Player" kimlik olarak "music player"ı KAPSIYOR; kapsama yetmez.
        assert _specificity_reject(
            "Halcyon Music Player", "Music Player", "music player", exact_catalog=False,
        )

    def test_katalogda_yoksa_kural_islemez(self):
        assert _specificity_reject(
            "Unrelated Toolkit", "Marlin Toolkit", "marlin toolkit", exact_catalog=False,
        ) is None

    def test_bitisik_urun_ailesi_muaf(self):
        # "Woodgrove BrightwaveLinux" token düzeyinde "Brightwave Agent"ı
        # kapsamıyor; muafiyet olmasa aynı ürünün gerçek tehditleri düşerdi.
        assert _specificity_reject(
            "Woodgrove BrightwaveLinux", "Brightwave Agent",
            "brightwave agent", exact_catalog=True,
        ) is None

    def test_platform_tokenlari_kimlikten_sayilmaz(self):
        # Envanter "For Mac" yazarken CVE yalnızca "Proseware Driftguard Backup" der.
        assert _identity_covers("Proseware Driftguard Backup",
                                "Proseware Driftguard Backup For Mac")


class TestKimliksizUrunAlani:
    """CVE'nin ürün alanı kimlik taşımıyorsa satıcı öne eklenmeli."""

    def test_satici_eklenmeden_kural_calismaz(self):
        # Bazı kayıtlarda ürün alanı yalnızca "server" yazar (satıcı ayrı sütunda).
        assert identity.distinct_product_pair("server", "Ravenmail") is None
        assert identity.distinct_product_pair("ravenmail server", "Ravenmail")

    def test_kimlik_tokeni_yoklugu_saptanir(self):
        from refimpl.disambiguation import identity_tokens

        assert not identity_tokens("server")
        assert identity_tokens("ravenmail server")
