"""Belirsiz ürün adlarının çözümlenmesi — jenerik ad, paket bileşeni, edisyon."""
from __future__ import annotations

import pytest

from refimpl.applicability import is_web_cms_plugin, vendor_not_applicable
from refimpl.disambiguation import (
    component_conflict,
    infer_vendor_from_os,
    is_generic_product_name,
    match_aliases,
    strip_edition_tokens,
    suite_component,
)


class TestEditionTokens:
    @pytest.mark.parametrize(
        "name,expected",
        [
            ("Microsoft Office Word 2016", "microsoft office word"),
            ("Google Chrome x64", "google chrome"),
            ("Adobe Acrobat Reader DC", "adobe acrobat reader"),
            ("7-Zip 21.07 (x64 edition)", "7-zip"),
            ("Microsoft Office LTSC 2021", "microsoft office"),
        ],
    )
    def test_strips_year_edition_arch(self, name, expected):
        assert strip_edition_tokens(name) == expected


class TestGenericNames:
    @pytest.mark.parametrize("name", ["Calendar", "Notes", "Photos", "Terminal", "Mail"])
    def test_bare_generic_names(self, name):
        assert is_generic_product_name(name) is True

    @pytest.mark.parametrize(
        "name", ["Apple Calendar", "Zimbra Calendar", "Glimmerpost", "Apache Tomcat", "OpenSSL"]
    )
    def test_distinctive_names(self, name):
        assert is_generic_product_name(name) is False

    def test_edition_tokens_do_not_make_name_distinctive(self):
        # "Calendar 2016 x64" hâlâ hangi satıcının takvimi olduğunu söylemiyor.
        assert is_generic_product_name("Calendar 2016 x64") is True


class TestOsVendor:
    @pytest.mark.parametrize(
        "os_name,vendor",
        [("macOS", "apple"), ("mac os x", "apple"), ("iOS", "apple"),
         ("Windows 11", "microsoft"), ("Android 14", "google")],
    )
    def test_first_party_vendor_from_os(self, os_name, vendor):
        assert infer_vendor_from_os(os_name) == vendor

    def test_unknown_os(self):
        assert infer_vendor_from_os("FreeBSD") is None
        assert infer_vendor_from_os(None) is None


class TestSuiteComponent:
    def test_component_detected(self):
        assert suite_component("Microsoft Office Word 2016") == ("microsoft office", "word")

    def test_suite_itself_has_no_component(self):
        assert suite_component("Microsoft Office 2016") == ("microsoft office", None)

    def test_unrelated_product(self):
        assert suite_component("Apache Tomcat") is None


class TestComponentConflict:
    def test_sibling_components_conflict(self):
        # Excel CVE'si Word envanterine uygulanamaz.
        assert component_conflict("Microsoft Excel", "Microsoft Word") is not None
        assert component_conflict("Microsoft Outlook", "Microsoft Word") is not None

    def test_suite_covers_component(self):
        # Office paketinin CVE'si Word'ü de kapsar.
        assert component_conflict("Microsoft Office 2016", "Microsoft Word") is None

    def test_same_component(self):
        assert component_conflict("Microsoft Word 2016", "Microsoft Office Word 2016") is None

    def test_different_suites_do_not_conflict(self):
        assert component_conflict("LibreOffice Writer", "Microsoft Word") is None


class TestMatchAliases:
    def test_suite_and_component_forms(self):
        aliases = match_aliases("Microsoft Office Word 2016")
        assert "microsoft word" in aliases
        assert "microsoft office" in aliases

    def test_bare_component_is_not_an_alias(self):
        # Çıplak "word" WordPress gibi ilgisiz ürünlere eşleşirdi.
        assert "word" not in match_aliases("Microsoft Word")

    def test_plain_product_unchanged(self):
        assert match_aliases("Glimmerpost") == ["glimmerpost"]


class TestHostVsPlugin:
    """CMS'in kendisi taranırken çekirdek CVE'leri kalmalı, eklentiler elenmeli."""

    @pytest.mark.parametrize(
        "cve_product",
        ["WordPress", "Automattic WordPress", "WordPress.org WordPress", "WordPress Core"],
    )
    def test_core_is_applicable(self, cve_product):
        assert is_web_cms_plugin(cve_product, "", "", "WordPress") is False

    @pytest.mark.parametrize(
        "cve_product", ["GetResponse for WordPress", "Mask Passwords Plugin"]
    )
    def test_addons_are_rejected(self, cve_product):
        customer = "Jenkins" if "Passwords" in cve_product else "WordPress"
        assert is_web_cms_plugin(cve_product, "", "", customer) is True

    def test_drupal_core(self):
        assert is_web_cms_plugin("Drupal core", "", "", "Drupal") is False

    def test_plugin_cve_not_applied_to_desktop_app(self):
        assert is_web_cms_plugin("Countdown Timer", "A WordPress plugin flaw", "", "VLC") is True


class TestPluginIsTheScannedProduct:
    """Taranan ürün EKLENTİNİN KENDİSİ olduğunda kapı çalışmamalı.

    Kapının amacı bir WordPress eklentisinin açığını ilgisiz bir masaüstü
    uygulamasına yaymamak. Envanterdeki ürün eklentinin ta kendisiyse yayılma
    yoktur — CVE doğrudan onu ilgilendirir; aksi hâlde "Formcrafter 4.2.9"
    'etkilenmiyor' görünür.
    """

    PLUGIN_TEXT = (
        "The Formcrafter Pro plugin for WordPress is vulnerable to authorization "
        "bypass in all versions up to, and including, 4.3.0."
    )

    def test_scanning_the_plugin_itself_is_applicable(self):
        assert is_web_cms_plugin("Formcrafter Pro", self.PLUGIN_TEXT, "formcrafter", "Formcrafter") is False

    def test_exact_name_also_applicable(self):
        assert is_web_cms_plugin(
            "Formcrafter Pro", self.PLUGIN_TEXT, "formcrafter", "Formcrafter Pro"
        ) is False

    def test_unrelated_product_still_rejected(self):
        assert is_web_cms_plugin("Formcrafter Pro", self.PLUGIN_TEXT, "formcrafter", "VLC") is True

    def test_tail_match_is_not_enough(self):
        # "WordPress Countdown Timer" eklentisi, aynı adlı masaüstü uygulamasına
        # uygulanmamalı: envanter adı CVE adının BAŞI olmalı, kuyruğu değil.
        assert is_web_cms_plugin(
            "WordPress Countdown Timer", "A WordPress plugin flaw", "", "Countdown Timer"
        ) is True


class TestProductHead:
    @pytest.mark.parametrize(
        "cve_product,inventory,expected",
        [
            ("Formcrafter Pro", "Formcrafter", True),
            ("Acme NAC", "Acme", True),
            ("Formcrafter Pro", "Formcrafter Pro", True),
            ("WordPress Countdown Timer", "Countdown Timer", False),
            ("Countdown Timer", "VLC", False),
            # Envanter adı CVE adından UZUNSA önek olamaz.
            ("Acme", "Acme NAC Server", False),
        ],
    )
    def test_head_relationship(self, cve_product, inventory, expected):
        from refimpl.disambiguation import same_product_head

        assert same_product_head(cve_product, inventory) is expected


class TestVendorGate:
    """Satıcı kapısı: doğru satıcı bilgisi vermek taramayı BOZMAMALI."""

    @pytest.mark.parametrize(
        "cve_vendor",
        [
            "PostgreSQL",
            # Aynı satıcı, farklı yazım — CVE kayıtlarında hepsi geçiyor.
            "PostgreSQL Global Development Group",
            "PostgreSQL Project",
            # Satıcı bilinmiyorsa çelişki çıkarılamaz; kayıtların çoğu böyle.
            "",
            "n/a",
            "unknown",
        ],
    )
    def test_same_or_unknown_vendor_is_applicable(self, cve_vendor):
        assert vendor_not_applicable(cve_vendor, "postgresql") is False

    @pytest.mark.parametrize("cve_vendor", ["Red Hat", "Apple", "Microsoft"])
    def test_different_vendor_is_rejected(self, cve_vendor):
        assert vendor_not_applicable(cve_vendor, "postgresql") is True

    def test_gate_inactive_without_customer_vendor(self):
        assert vendor_not_applicable("Apple", None) is False
        assert vendor_not_applicable("Apple", "") is False


class TestShortInventoryName:
    """Envanter adı katalogdan KISA yazıldığında eşleşme.

    "Acme" ↔ "Acme NAC": kimlik tokenı kıyaslaması bunu farklı ürün sayıyor
    (CVE'de fazladan 'nac' var) ve tüm adayları eliyordu; ürünün 2026 CVE'leri
    bu yüzden bulunamıyordu. Kısa adı spesifik bir ürüne bağlamak ancak
    katalogda TEK karşılığı varsa güvenli — bu yüzden kural veriye danışır.
    """

    def test_single_family_member_is_bound(self, monkeypatch):
        from refimpl import scanner

        monkeypatch.setattr(
            "refimpl.store.product_family_names", lambda q, limit=6: ["acme nac"]
        )
        assert scanner._catalog_family("acme", "Acme") == ("acme nac", False)

    @pytest.mark.parametrize(
        "names",
        [
            ["mysql", "mysql cluster", "mysql connector"],   # birden çok ürün
            [],                                              # katalogda yok
        ],
    )
    def test_ambiguous_or_missing_family_is_not_bound(self, monkeypatch, names):
        from refimpl import scanner

        monkeypatch.setattr("refimpl.store.product_family_names", lambda q, limit=6: names)
        assert scanner._catalog_family("mysql", "MySQL")[0] is None

    def test_exact_name_needs_no_binding(self, monkeypatch):
        from refimpl import scanner

        monkeypatch.setattr("refimpl.store.product_family_names", lambda q, limit=6: ["glimmerpost"])
        # Katalog ürünü KENDİ adıyla tanıyor: bağlama gereksiz, ama spesifiklik
        # kapısı bu bayrağa dayanıyor (bkz. _specificity_reject).
        assert scanner._catalog_family("glimmerpost", "Glimmerpost") == (None, True)

    def test_generic_names_are_never_bound(self, monkeypatch):
        # "Calendar" tek karşılığa çözülse bile jenerik ad bağlanmamalı.
        from refimpl import scanner

        monkeypatch.setattr(
            "refimpl.store.product_family_names", lambda q, limit=6: ["calendar plus"]
        )
        assert scanner._catalog_family("calendar", "Calendar")[0] is None

    def test_db_failure_does_not_break_scanning(self, monkeypatch):
        from refimpl import scanner

        def boom(q, limit=6):
            raise RuntimeError("db yok")

        monkeypatch.setattr("refimpl.store.product_family_names", boom)
        assert scanner._catalog_family("acme", "Acme") == (None, False)
