"""Envanter listesini taranabilir bir plana çevirir.

Gerçek envanterler iki tür tekrar taşır ve ikisi farklı şey ister:

1. **Birebir yinelenen kayıt** — aynı uygulama, aynı sürüm, aynı satıcı/OS
   birden çok uç noktada kurulu olduğu için listede defalarca geçer. Bunlar tek
   kez taranıp sonuç tüm kopyalara dağıtılır.

2. **Aynı uygulama, farklı sürüm** — bunlar ayrı kayıtlardır ve BİRLEŞTİRİLEMEZ;
   her sürüm kendi kararını almalıdır. Ama tarama maliyetinin tamamına yakını
   sürümden bağımsızdır (aday CVE araması + CRF çıkarımı), o yüzden aynı ürünün
   sürümleri tek grupta toplanıp hazırlık paylaşılır (`ThreatScanner.check_many`).

Plan, girdideki sırayı ve kalem sayısını korur: çağıran ne gönderdiyse aynı
uzunlukta ve aynı sırada sonuç alır.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

# Ürün adı, sürümü ve satıcı/OS bağlamı — bir taramayı benzersiz kılan dörtlü.
DedupKey = Tuple[str, str, str, str, str]


def _norm(value: Optional[str]) -> str:
    """Anahtar için sadeleştirme: kenar boşlukları, iç boşluklar ve harf durumu.

    'Apache  Tomcat' ile 'apache tomcat' envanterde aynı kurulumdur; ikisini
    ayrı taramak aynı işi iki kez yapmak olur. Kullanıcının yazdığı ad yanıtta
    olduğu gibi korunur — sadeleştirme yalnızca gruplama içindir.
    """
    return " ".join((value or "").split()).lower()


def dedup_key(item) -> DedupKey:
    """Bir kalemi benzersiz kılan alanlar.

    Sürüm anahtarın PARÇASIDIR: aynı uygulamanın 8.5 ve 9.0 sürümleri farklı
    kararlar alır ve asla tek kayda indirgenmemelidir.
    """
    return (
        _norm(getattr(item, "product", None)),
        _norm(getattr(item, "version", None)),
        _norm(getattr(item, "vendor", None)),
        _norm(getattr(item, "operating_system", None)),
        _norm(getattr(item, "platform", None)),
    )


def product_key(item) -> Tuple[str, str, str, str]:
    """Aynı hazırlığı paylaşabilecek kalemler — sürüm hariç her şey."""
    k = dedup_key(item)
    return (k[0], k[2], k[3], k[4])


@dataclass
class ProductGroup:
    """Tek bir ürün bağlamı ve onun altında taranacak farklı sürümler."""

    sample_index: int          # gruptaki ilk kalemin girdideki sırası
    versions: List[str] = field(default_factory=list)
    # versions[i] -> bu sürümün sonucunu alacak benzersiz-kalem indeksleri
    targets: List[int] = field(default_factory=list)


@dataclass
class ScanPlan:
    """Girdi listesinin taranabilir hâli.

    - `unique_items`: gerçekten taranacak kalemler (birebir yinelenenler ayıklanmış)
    - `assignment[i]`: girdideki i. kalemin sonucunu `unique_items` içindeki hangi
      indeksten alacağı
    - `groups`: aynı hazırlığı paylaşan ürün grupları
    """

    unique_items: List = field(default_factory=list)
    assignment: List[int] = field(default_factory=list)
    groups: List[ProductGroup] = field(default_factory=list)
    source_items: List = field(default_factory=list)

    def targets_of(self) -> Dict[int, List[int]]:
        """Benzersiz kalem indeksi -> o sonucu alacak girdi konumları."""
        out: Dict[int, List[int]] = {}
        for position, unique_idx in enumerate(self.assignment):
            out.setdefault(unique_idx, []).append(position)
        return out

    @property
    def total(self) -> int:
        return len(self.assignment)

    @property
    def duplicates(self) -> int:
        """Tarama yapılmadan sonucu kopyalanacak kalem sayısı."""
        return self.total - len(self.unique_items)

    @property
    def products(self) -> int:
        return len(self.groups)

    def summary(self) -> Dict[str, int]:
        return {
            "received": self.total,
            "unique": len(self.unique_items),
            "duplicates": self.duplicates,
            "product_groups": self.products,
        }


def build_plan(items: Sequence) -> ScanPlan:
    """Envanter listesinden tarama planı çıkarır.

    Girdi sırası korunur; aynı dörtlünün ilk görüldüğü yer kanonik kabul edilir.
    """
    plan = ScanPlan()
    seen: Dict[DedupKey, int] = {}
    groups: Dict[Tuple[str, str, str, str], ProductGroup] = {}

    plan.source_items = list(items)

    for item in items:
        key = dedup_key(item)
        idx = seen.get(key)
        if idx is None:
            idx = len(plan.unique_items)
            seen[key] = idx
            plan.unique_items.append(item)

            pkey = product_key(item)
            group = groups.get(pkey)
            if group is None:
                group = ProductGroup(sample_index=idx)
                groups[pkey] = group
                plan.groups.append(group)
            group.versions.append(getattr(item, "version", "") or "")
            group.targets.append(idx)
        plan.assignment.append(idx)

    return plan
