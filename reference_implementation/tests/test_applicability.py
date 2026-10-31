"""Uygulanabilirlik kapıları — yanlış pozitif üreten CVE'leri eleme testleri."""
from __future__ import annotations

from refimpl.applicability import (
    is_language_binding_mismatch,
    is_web_cms_plugin,
    os_family,
    platform_mismatch,
    product_identity_ok,
)


class TestOsFamily:
    def test_single_signal_detected(self):
        assert os_family("Microsoft Windows Defender") == "windows"

    def test_cross_platform_text_is_ambiguous(self):
        # Birden çok OS geçiyorsa aile belirlenemez → kapı devreye girmez.
        assert os_family("runs on windows, linux and macos") is None

    def test_no_signal(self):
        assert os_family("Apache Tomcat") is None


class TestProductIdentity:
    def test_shared_specific_token_matches(self):
        assert product_identity_ok("Apache Tomcat", "Apache Tomcat 9") is True

    def test_only_generic_tokens_do_not_match(self):
        # 'Agent'/'Manager' tek başına ürün kimliği belirlemez.
        assert product_identity_ok("Agent Manager", "Backup Agent") is False

    def test_unrelated_products(self):
        assert product_identity_ok("Redis", "Visual C++ Runtime") is False


class TestWebPluginGate:
    def test_wordpress_plugin_detected(self):
        assert is_web_cms_plugin("Countdown Timer", "A WordPress plugin flaw", "") is True

    def test_plugin_word_in_product_name(self):
        assert is_web_cms_plugin("Mask Passwords Plugin", "", "") is True

    def test_patchstack_template_detected(self):
        assert is_web_cms_plugin("Some Tool", "This issue affects X: from n/a through 1.2", "")

    def test_desktop_app_not_flagged(self):
        assert is_web_cms_plugin("VLC media player", "Buffer overflow in VLC", "") is False


class TestLanguageBinding:
    def test_perl_namespace_is_mismatch(self):
        assert is_language_binding_mismatch(
            "Crypt::OpenSSL::PKCS12", "module for Perl", "OpenSSL"
        ) is True

    def test_perl_module_on_library_is_mismatch(self):
        # Same pair is pinned on the Go side (compiled_engine/goscan/divergence_test.go),
        # where the snapshot has no language-binding gate.
        assert is_language_binding_mismatch("Net::SSLeay", "Perl module", "OpenSSL") is True

    def test_customer_is_the_package_itself(self):
        # Envanterdeki ürün paketin kendisiyse elenmemeli.
        assert is_language_binding_mismatch(
            "cryptography", "python package cryptography", "cryptography"
        ) is False


class TestPlatformMismatch:
    def test_android_cve_on_windows_endpoint(self):
        assert platform_mismatch("Chrome for Android", "", "Google Chrome", "windows") is True

    def test_matching_platform_is_fine(self):
        assert platform_mismatch("Chrome", "windows build", "Google Chrome", "windows") is False
