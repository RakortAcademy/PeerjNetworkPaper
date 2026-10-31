"""Birinci-parti uygulama → vendor çıkarımı ve vendor eşanlam normalizasyonu.

Envanter kaydında ``vendor`` çoğu zaman boş / ``nan`` gelir (özellikle macOS
endpoint export'unda). Bu modül bilinen birinci-parti uygulamaları (Apple
yerleşikleri, Microsoft, Google ...) vendor'a bağlar; böylece CVE eşleşmesinde
vendor-çatışma kapısı çalışabilir:

    "Clock" (Apple)  vs  CVE vendor "Adam Skaat" (WordPress plugin)  -> çatışma
    => bu CVE Apple "Clock" uygulamasına uygulanamaz.

Önemli güvenlik özelliği: çıkarım yalnızca NON-eşleşen vendor'ları eler. Gerçek
bir Apple CVE'sinin vendor'ı da "Apple" olduğu için çatışma oluşmaz ve geçer.
"""
from __future__ import annotations

import re
from typing import Optional

# Kanonik vendor -> bilinen eşanlamlar (hepsi lowercase).
_VENDOR_SYNONYMS = {
    "apple": {"apple", "apple inc", "apple inc.", "apple computer", "apple, inc."},
    "microsoft": {"microsoft", "microsoft corporation", "microsoft corp", "msft", "ms"},
    "google": {"google", "google llc", "google inc", "alphabet"},
    "adobe": {"adobe", "adobe inc", "adobe systems", "adobe systems incorporated"},
    "mozilla": {"mozilla", "mozilla foundation", "mozilla corporation"},
    "oracle": {"oracle", "oracle corporation"},
}


def normalize_vendor(vendor: Optional[str]) -> Optional[str]:
    """Vendor string'ini kanonik bir token'a indirger. Boş/anlamsız ise None."""
    if not vendor:
        return None
    v = re.sub(r"\s+", " ", str(vendor).strip().lower())
    if v in ("", "n/a", "nan", "none", "null", "unknown", "-"):
        return None
    for canon, aliases in _VENDOR_SYNONYMS.items():
        if v == canon or v in aliases:
            return canon
    for canon in _VENDOR_SYNONYMS:
        if re.search(rf"\b{re.escape(canon)}\b", v):
            return canon
    return v  # bilinmeyen ama dolu vendor -> kendi token'ı (yine de kıyaslanabilir)


# macOS birinci-parti (Apple) yerleşik uygulama adları (lowercase).
_APPLE_MACOS_APPS = {
    "app store", "automator", "books", "calculator", "calendar", "chess",
    "clock", "contacts", "dictionary", "facetime", "find my", "findmy",
    "font book", "freeform", "games", "home", "image capture",
    "image playground", "journal", "mail", "maps", "messages",
    "mission control", "music", "news", "notes", "passwords", "phone",
    "photo booth", "photos", "podcasts", "preview", "quicktime player",
    "reminders", "safari", "shortcuts", "siri", "stickies", "stocks",
    "system settings", "tv", "textedit", "time machine", "tips",
    "voice memos", "voicememos", "weather", "iphone mirroring",
    "stage manager", "launchpad", "finder", "spotlight",
    "keynote", "numbers", "pages", "garageband", "imovie",
}

_MACOS_PLATFORMS = {"", "macos", "mac", "mac os", "osx", "os x", "darwin"}


def infer_vendor(product_name: str, platform: Optional[str] = None) -> Optional[str]:
    """Bilinen birinci-parti uygulamalar için kanonik vendor döndürür; yoksa None.

    Apple yerleşikleri yalnızca macOS (veya platform boş) uç noktada çıkarılır;
    bu sayede gerçek bir Windows uygulamasıyla isim çakışması riski düşer.
    """
    if not product_name:
        return None
    name = re.sub(r"\s+", " ", str(product_name).strip().lower())
    plat = (platform or "").strip().lower()
    if name in _APPLE_MACOS_APPS and plat in _MACOS_PLATFORMS:
        return "apple"
    return None


def vendors_conflict(cve_vendor: Optional[str], customer_vendor: Optional[str]) -> bool:
    """İki vendor da BİLİNİYOR ve kanonik olarak FARKLI ise True döner.

    Taraflardan biri bilinmiyorsa (None) çatışma yok sayılır → karar verme.
    """
    cv = normalize_vendor(cve_vendor)
    cu = normalize_vendor(customer_vendor)
    if not cv or not cu:
        return False
    return cv != cu
