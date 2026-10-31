"""Ürün kapsama kuralı — CVE adı envanterdeki ürünü mü anlatıyor?

Dizi benzerliği bu kararı veremiyor: "MySQL Server" ile "MySQL" arasındaki
benzerlik 0.59'da kalıp eşiği geçemiyor, oysa aynı ürün. Kural bunun yerine
kimlik tokenlarının yönlü alt-küme ilişkisine bakar.
"""
from __future__ import annotations

import pytest

from refimpl.disambiguation import covers_product, identity_tokens, names_conflict


class TestIdentityTokens:
    @pytest.mark.parametrize(
        "name,expected",
        [
            ("MySQL Server", {"mysql"}),
            ("Oracle GlassFish Server", {"glassfish"}),
            ("Apache Tomcat", {"tomcat"}),
            # "office" kimlik tokenı olarak kalır: paket adı ("Microsoft Office")
            # bileşeni kapsayabilsin diye ({office} ⊆ {office, word}).
            ("Microsoft Office Word 2016", {"office", "word"}),
            ("MySQL Cluster", {"mysql", "cluster"}),
        ],
    )
    def test_type_and_vendor_words_removed(self, name, expected):
        assert identity_tokens(name) == expected


class TestCoversProduct:
    @pytest.mark.parametrize(
        "cve_product,inventory",
        [
            ("MySQL Server", "MySQL"),
            ("Oracle GlassFish Server", "GlassFish"),
            ("Eclipse Glassfish", "GlassFish"),
            ("Confluence Server", "Confluence"),
            ("Google Chrome", "Chrome"),
            # Envanter Maven koordinatından temizlenmiş bileşen adı taşıyabilir.
            ("Apache Tomcat", "tomcat catalina"),
        ],
    )
    def test_general_cve_name_covers_inventory(self, cve_product, inventory):
        assert covers_product(cve_product, inventory) is True

    @pytest.mark.parametrize(
        "cve_product,inventory",
        [
            # Farklı ürün — ortak kelime yeterli değil.
            ("MySQL Cluster", "MySQL"),
            ("Microsoft Excel", "Microsoft Word"),
            ("WordPress", "VLC media player"),
            # Farklı büyük sürüm hattı ayrı üründür (Log4j 1.x ↔ Log4j2).
            ("Apache Log4j Core", "Apache Log4j2"),
        ],
    )
    def test_unrelated_or_sibling_products_rejected(self, cve_product, inventory):
        assert covers_product(cve_product, inventory) is False

    def test_direction_matters(self):
        """CVE daha genel olabilir; daha spesifik olamaz.

        Bir bileşenin açığını tüm ürüne yaymak yanlış pozitif üretir.
        """
        assert covers_product("MySQL", "MySQL Server") is True
        assert covers_product("MySQL Cluster", "MySQL Server") is False

    def test_empty_names(self):
        assert covers_product("", "MySQL") is False
        assert covers_product("MySQL", "") is False


class TestNamesConflict:
    """Ekli adlar dizi benzerliğiyle ayrılamaz; kimlik tokenları ayırır."""

    @pytest.mark.parametrize(
        "first,second",
        [
            # "ChromeOS" ile "Chrome" %86 benzer — ama ayrı ürünler.
            ("ChromeOS", "Chrome"),
            ("Microsoft Excel", "Microsoft Word"),
            ("xBrindle", "Brindle"),
        ],
    )
    def test_distinct_products_conflict(self, first, second):
        assert names_conflict(first, second) is True

    @pytest.mark.parametrize(
        "first,second",
        [
            ("Chrome", "Google Chrome"),
            # Dosya adından gelen sürüm rakamı kimliği değiştirmez.
            ("TOMCAT9", "Apache Tomcat"),
            ("Tomcat", "TOMCAT9"),
            ("MySQL Server", "MySQL"),
        ],
    )
    def test_same_product_does_not_conflict(self, first, second):
        assert names_conflict(first, second) is False

    def test_only_type_words_cannot_decide(self):
        """Kimlik tokenı kalmayan adlarda karar verilemez — engelleme yapılmaz."""
        assert names_conflict("Server", "MySQL") is False
