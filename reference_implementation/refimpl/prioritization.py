"""Tehditleri önceliklendirir — "340 açığın var" yerine "şu 3'ü bugün".

Çok CVE'li bir ürün için tarayıcı yüzlerce doğru tehdit bulabilir. Böyle bir
liste "hangisinden başlayacağım" sorusunu yanıtlamıyor; yanıtlamadığı için de
okunmuyor.

Öncelik ÜÇ bağımsız sinyalden türetilir ve üçü de yanıtta ayrı ayrı kalır:

| Sinyal | Ne söyler | Doğası |
|---|---|---|
| KEV | Bu açık vahşi doğada sömürülüyor | Gözlem — kesin, ama dar (CVE'lerin %0,5'i) |
| EPSS | 30 günde sömürülme olasılığı | Tahmin — geniş, ama olasılık |
| CVSS | Sömürülürse ne kadar kötü | Teknik şiddet; olasılıktan bağımsız |

Tek bir sayıya indirgemek bu ayrımı siler: CVSS 9.8 olup hiç sömürülmeyen
açıklar da var, CVSS 6.1 olup KEV'de olanlar da.

Eşikler:

    acil    KEV'de — tahmin değil, gözlem. Başka hiçbir şeye bakılmaz.
    yüksek  EPSS ≥ %10  ya da  CVSS ≥ 9.0
    orta    EPSS ≥ %1   ya da  CVSS ≥ 7.0
    düşük   diğer

%10 eşiğinin amacı, yüzlerce tehditlik bir listeyi bir günde bitirilebilecek
boyuta indirmektir; daha düşük bir eşik (%1) listeyi yeniden okunamaz hâle
getirir.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)

#: Sıralama ve raporlama için sabit sıra. Değiştirirken `PRIORITY_ORDER`
#: sözlüğünü de düşünün: yanıttaki tehdit sırası buna göre kuruluyor.
PRIORITIES = ("acil", "yüksek", "orta", "düşük")
PRIORITY_ORDER = {name: i for i, name in enumerate(PRIORITIES)}

#: EPSS eşikleri (olasılık, 0..1).
_EPSS_HIGH = 0.10
_EPSS_MEDIUM = 0.01

#: CVSS eşikleri (temel puan).
_CVSS_HIGH = 9.0
_CVSS_MEDIUM = 7.0


def priority_for(risk: Optional[Dict[str, Any]]) -> str:
    """Tek bir tehdidin öncelik sınıfı."""
    if not risk:
        return "düşük"
    if risk.get("kev"):
        return "acil"

    epss = risk.get("epss") or 0.0
    cvss = risk.get("cvss") or 0.0
    if epss >= _EPSS_HIGH or cvss >= _CVSS_HIGH:
        return "yüksek"
    if epss >= _EPSS_MEDIUM or cvss >= _CVSS_MEDIUM:
        return "orta"
    return "düşük"


def _reason_tr(risk: Dict[str, Any], priority: str) -> str:
    """Önceliğin NEDEN o olduğunu tek cümlede söyler.

    Rakam vermeden "yüksek öncelik" demek, kullanıcının karara güvenmesini
    engelliyor; gerekçe her zaman ölçülebilir bir dayanak taşımalı.
    """
    if risk.get("kev"):
        parts = ["CISA bu açığın aktif olarak sömürüldüğünü doğruladı"]
        if risk.get("ransomware"):
            parts.append("fidye yazılımı kampanyalarında kullanılıyor")
        if risk.get("kev_due_date"):
            parts.append(f"CISA son yama tarihi {risk['kev_due_date']}")
        return "; ".join(parts) + "."

    bits: List[str] = []
    epss = risk.get("epss")
    if epss is not None and epss >= _EPSS_MEDIUM:
        bits.append(f"30 günde sömürülme olasılığı %{epss * 100:.1f}")
    cvss = risk.get("cvss")
    if cvss is not None and cvss >= _CVSS_MEDIUM:
        bits.append(f"CVSS {cvss:g}")
    if risk.get("exploit_known"):
        bits.append("yayımlanmış sömürü kodu var")
    if not bits:
        return "Aktif sömürü belirtisi yok; rutin yama döngüsünde ele alınabilir."
    return ", ".join(bits) + "."


def attach(threats: List[Dict[str, Any]]) -> Dict[str, int]:
    """Tehdit satırlarına risk bloğunu ekler ve listeyi ÖNCELİĞE göre sıralar.

    Sıralama isteğe bağlı bir güzellik değil: yanıt `CVE_MAX_DETAIL_ROWS`
    satırından sonra açıklama metnini kırpıyor ve panel sayfa sayfa okuyor.
    Sıralanmazsa ilk sayfada rastgele CVE'ler, aktif sömürülen açık ise 14.
    sayfada çıkıyordu.

    Döner: öncelik sınıfı → adet.
    """
    if not threats:
        return {}

    try:
        from refimpl import store as cve_repo

        risks = cve_repo.risk_for([t["cve_id"] for t in threats if t.get("cve_id")])
    except Exception:
        # Risk tabloları okunamıyorsa tarama düşmez: tehditler yine döner,
        # yalnızca sıralanmamış ve önceliksiz olur.
        logger.warning("Risk sinyalleri okunamadı", exc_info=True)
        risks = {}

    counts: Dict[str, int] = {}
    for threat in threats:
        risk = dict(risks.get(threat.get("cve_id")) or {})
        priority = priority_for(risk)
        risk["priority"] = priority
        risk["priority_reason_tr"] = _reason_tr(risk, priority)
        threat["risk"] = risk
        counts[priority] = counts.get(priority, 0) + 1

    # Öncelik → EPSS → CVSS → kimlik. Son anahtar kesin sıralama içindir:
    # eşit riskli iki CVE her çağrıda aynı sırada dönmeli.
    threats.sort(key=lambda t: (
        PRIORITY_ORDER.get((t.get("risk") or {}).get("priority"), 99),
        -((t.get("risk") or {}).get("epss") or 0.0),
        -((t.get("risk") or {}).get("cvss") or 0.0),
        t.get("cve_id") or "",
    ))
    return counts


def summarize(threats: Sequence[Dict[str, Any]], counts: Dict[str, int]) -> Dict[str, Any]:
    """Ürün düzeyinde tek bakışta risk özeti.

    En acil CVE'ler ADIYLA verilir: "10 açık acil" cümlesi tek başına yine bir
    arama işi doğuruyor, kimlikler doğrudan eyleme çevrilebiliyor.
    """
    if not threats:
        return {}

    kev = [t for t in threats if (t.get("risk") or {}).get("kev")]
    ransomware = [t for t in kev if (t.get("risk") or {}).get("ransomware")]
    due = sorted(
        d for d in ((t.get("risk") or {}).get("kev_due_date") for t in kev) if d
    )

    out: Dict[str, Any] = {
        "counts": {p: counts.get(p, 0) for p in PRIORITIES if counts.get(p)},
        "total": len(threats),
        "kev": len(kev),
        "ransomware": len(ransomware),
        "top_cves": [t["cve_id"] for t in threats[:5] if t.get("cve_id")],
    }
    if due:
        out["earliest_due_date"] = due[0]

    if kev:
        line = f"{len(threats)} açıktan {len(kev)}'i şu anda aktif olarak sömürülüyor"
        if ransomware:
            line += f" ({len(ransomware)}'i fidye yazılımı kampanyalarında)"
        line += ". Önce bunlar kapatılmalı: " + ", ".join(t["cve_id"] for t in kev[:5])
        if len(kev) > 5:
            line += f" ve {len(kev) - 5} tane daha"
        out["summary_tr"] = line + "."
    elif counts.get("yüksek"):
        out["summary_tr"] = (
            f"{len(threats)} açıktan {counts['yüksek']}'i yüksek riskli "
            "(yakın vadede sömürülme olasılığı ya da kritik şiddet). "
            "Aktif sömürüldüğü bilinen açık yok."
        )
    else:
        out["summary_tr"] = (
            f"{len(threats)} açık bulundu; hiçbiri aktif sömürülmüyor ve "
            "yakın vadeli sömürü olasılığı düşük. Rutin yama döngüsü yeterli."
        )
    return out
