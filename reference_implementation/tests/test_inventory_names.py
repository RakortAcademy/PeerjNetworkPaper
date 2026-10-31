"""Envanter adlarının yarattığı eşleşme sorunları (kurgusal ürün adlarıyla).

Kurulu-uygulama envanterlerinin genel biçim özellikleri: adlar satıcının
yazdığı gibi durur, sürümler derleme numarası taşır, satıcı alanı yazarı
gösterir. Vakalar bu paket için kurgusal adlarla yazılmıştır.
"""
from __future__ import annotations

import pytest

from refimpl import applicability as gates
from refimpl import disambiguation as d
from refimpl.search import _accepts, product_token_overlap
from refimpl.versioning.parser import is_build_of


class TestVendorFieldIsProductName:
    """CNA satıcı alanına ÜRÜN adını yazmış olabilir.

    Bazı kayıtlarda `vendor="Glimmerpost", product="Glimmerpost"`. Envanterde
    ise yazar var ("Ines Calder"). Karşılaştırma çelişki üretirse ürünün TÜM
    CVE'leri elenir — satıcı vermeden sorgulamak sonucu düzeltir, ki bu tam
    tersi olmalı.
    """

    def test_vendor_equal_to_product_carries_no_information(self):
        assert gates.vendor_not_applicable("Glimmerpost", "Ines Calder", "Glimmerpost") is False

    def test_real_vendor_conflict_still_vetoes(self):
        assert gates.vendor_not_applicable("Microsoft", "Oracle", "Windows") is True

    def test_unknown_vendor_never_vetoes(self):
        assert gates.vendor_not_applicable("n/a", "Ines Calder", "Glimmerpost") is False
        assert gates.vendor_not_applicable("Glimmerpost", None, "Glimmerpost") is False

    def test_corporate_suffixes_do_not_create_a_conflict(self):
        assert gates.vendor_not_applicable(
            "Woodgrove", "Woodgrove Systems Ltd", "BrightwaveLinux"
        ) is False


class TestCompoundProductFamily:
    """Bitişik yazılmış ürün aileleri: BrightwaveLinux / BrightwaveMac.

    Envanterde "Brightwave Agent" durur. Token kıyaslaması ortak TEK bir token
    bulamaz (katalog adı tek parça) ve ürünün CVE'leri aday listesine hiç
    giremez.
    """

    @pytest.mark.parametrize(
        "cve_name,inventory,same",
        [
            ("BrightwaveLinux", "Brightwave Agent", True),
            ("BrightwaveMac", "Brightwave Agent", True),
            ("Woodgrove BrightwaveLinux", "Brightwave", True),
            # Kökten sonrası platform eki DEĞİL → ayrı ürün.
            ("BrightwaveOS", "BrightwaveRouter", False),
            ("BrightwaveDocs", "BrightwaveChat", False),
            ("ChromeOS", "Chrome", False),
            # Yönetim konsolu ayrı bir üründür.
            ("BrightwaveConsole", "Brightwave", False),
        ],
    )
    def test_family_detection(self, cve_name, inventory, same):
        assert d.same_compound_family(cve_name, inventory) is same

    def test_names_conflict_respects_the_family(self):
        assert d.names_conflict("BrightwaveLinux", "Brightwave Agent") is False
        assert d.names_conflict("BrightwaveOS", "BrightwaveRouter") is True

    def test_search_accepts_the_family(self):
        # Aday elemesi de aynı kuralı kullanmalı; yoksa kapı hiç çalışmıyor.
        assert product_token_overlap("brightwave agent", "BrightwaveLinux") is True
        assert product_token_overlap("brightwaveos", "BrightwaveRouter") is False


class TestVendorMatchingInSearch:
    """Envanter satıcıyı kurumsal ekleriyle yazıyor, CVE kaydı sade.

    Birebir eşitlik aranırsa satıcı kolu hiç çalışmaz.
    """

    def test_corporate_suffix_still_matches(self):
        rec = {"product": "Bilinmeyen Ürün", "vendor": "Woodgrove"}
        assert _accepts("brightwave agent", "Woodgrove Systems Ltd", rec) is True

    def test_different_vendor_is_rejected(self):
        rec = {"product": "Bilinmeyen Ürün", "vendor": "Microsoft"}
        assert _accepts("brightwave agent", "Woodgrove Systems Ltd", rec) is False

    def test_missing_vendor_is_rejected(self):
        rec = {"product": "Bilinmeyen Ürün", "vendor": ""}
        assert _accepts("brightwave agent", "Woodgrove", rec) is False


class TestBuildNumberVersions:
    """Windows envanterleri sürümü derleme numarasıyla bildiriyor.

    Envanter "5.2.8.3141" der, CVE kaydı "5.2.8 ve altı" der. Saf sayısal
    kıyas 5.2.8.3141'i 5.2.8'in ÜSTÜNDE görür ve sürümü etkilenmiyor sayar.
    """

    @pytest.mark.parametrize(
        "version,release,expected",
        [
            ("5.2.8.3141", "5.2.8", True),
            ("12.31.40567.0", "12.31.40567", True),
            # Nokta sınırı şart: 5.2.80 bir 5.2.8 derlemesi DEĞİL.
            ("5.2.80", "5.2.8", False),
            ("5.2.9", "5.2.8", False),
            ("5.2.8", "5.2.8", False),   # aynı sürüm, "yapısı" değil
            ("5.2.8.3141", "5.2.9", False),
            ("", "5.2.8", False),
            ("5.2.8-rc1", "5.2.8", False),  # ön sürüm ayrı ele alınır
        ],
    )
    def test_is_build_of(self, version, release, expected):
        assert is_build_of(version, release) is expected

    def test_inclusive_bound_covers_the_build(self):
        from refimpl.scanner import _resolve_with_structured_bounds

        ranges = [{"greater_equal": "5.2.0", "less_than_or_equal": "5.2.8",
                   "less_than": "", "greater_than": ""}]
        resolved = _resolve_with_structured_bounds("5.2.8.3141", ranges)
        assert resolved is not None and resolved[0] == "THREAT"

    def test_exclusive_bound_does_not_cover_the_build(self):
        # "< 5.2.8" derken 5.2.8 zaten düzeltilmiş sürümdür; derlemeleri de öyle.
        from refimpl.scanner import _resolve_with_structured_bounds

        ranges = [{"greater_equal": "5.2.0", "less_than": "5.2.8",
                   "less_than_or_equal": "", "greater_than": ""}]
        resolved = _resolve_with_structured_bounds("5.2.8.3141", ranges)
        assert resolved is not None and resolved[0] == "SAFE"


class TestDirtyVersionField:
    """Envanter sürüm alanı sürüm dışında da şeyler taşıyor.

    Bir uygulama kendi ön ekini yazabilir ("qx 4.6.1"); ayrıştırılamazsa karar
    UNCERTAIN'e düşer, oysa sürüm bellidir.
    """

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("qx 4.6.1", "4.6.1"),
            ("v3.18.2", "3.18.2"),
            ("5.41.2 (64-bit)", "5.41.2"),
            ("release 2.17", "2.17"),
            ("5.2.8.3141", "5.2.8.3141"),
            ("9.0.90", "9.0.90"),
            # Tek başına sayı sürüm sayılmaz: yıl ya da derleme olabilir.
            ("2026", "2026"),
            ("", ""),
        ],
    )
    def test_clean(self, raw, expected):
        from refimpl.versioning.parser import clean_version_string

        assert clean_version_string(raw) == expected


class TestUpdatePackages:
    """Windows envanterleri kurulu YAMALARI da uygulama gibi listeliyor.

    "Update for x64-based Windows Systems (KB5099901)" sürüm 3.12.0.0 diye
    gelir. Ürün sanılırsa adı "Windows" ile eşleşir ve güncelleyicinin sürümü
    Windows derleme numaralarıyla kıyaslanır: yamanın KENDİSİ açık olarak
    raporlanır.
    """

    @pytest.mark.parametrize(
        "name,expected",
        [
            ("Update for x64-based Windows Systems (KB5099901)", True),
            ("Security Update for Microsoft Office (KB5099902)", True),
            ("Hotfix for Windows (KB123456)", True),
            ("Cumulative Update for Windows 10", True),
            ("Servicing Stack Update for Windows Server", True),
            ("Güvenlik Güncelleştirmesi (KB5099901)", True),
            # Gerçek ürünler yakalanmamalı.
            ("Microsoft Update Health Tools", False),
            ("Windows Update Assistant", False),
            ("Google Chrome", False),
            ("Relaydesk", False),
            ("", False),
        ],
    )
    def test_detection(self, name, expected):
        assert d.is_update_package(name) is expected

    def test_kb_number_alone_is_enough(self):
        # Ad dili ne olursa olsun KB numarası kesin işaret.
        assert d.is_update_package("2026-07 Toplu Güncelleştirme (KB5062553)") is True
