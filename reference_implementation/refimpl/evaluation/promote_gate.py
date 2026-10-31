"""Model promotion gate (manuscript Section 5 / Verdict Preservation: "release gates").

`should_promote` is the decision rule of the production promotion script verbatim. The
surrounding checkpoint file operations (staging → serving → backup) are
deployment plumbing and are not included.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

# Mutlak taban yalnızca akıl sağlığı kontrolü — kalite hedefi DEĞİL. Kalite
# kararı GÖRELİ verilir, çünkü altın küme değiştikçe mutlak sayı anlamını
# yitirir: aynı model farklı altın kümelerde çok farklı mutlak isabet alabilir.
MIN_ACCEPTED_ACCURACY = 0.50

# Ölçüm gürültüsüne takılmamak için küçük tolerans; bunun ötesindeki düşüş
# gerileme sayılır.
ACCURACY_TOLERANCE = 0.02


def should_promote(
    report: Dict[str, Any],
    baseline: Optional[Dict[str, Any]] = None,
) -> tuple[bool, str]:
    """Ölçüm sonucuna göre terfi kararı — (uygun_mu, gerekçe).

    Üç kural:
      1. Akıl sağlığı tabanı — model bariz bozuksa geçmesin.
      2. Kaçan THREAT gerilemesi: mevcut modelden fazla tehdit kaçırıyorsa
         terfi etmez. Kaçan THREAT müşteriyi açıkta bıraktığı için toplam
         isabet artmış olsa bile bu takas kabul edilmez.
      3. Genel isabet gerilemesi: tolerans dışında düşüş varsa terfi etmez.

    Karar ağırlıklı olarak GÖRELİdir; altın küme her genişletildiğinde mutlak
    eşikler yeniden kalibrasyon gerektirir, göreli kıyas gerektirmez.
    """
    accepted = float(report.get("accepted_accuracy") or 0)
    missed = int(report.get("missed_threats") or 0)

    if accepted < MIN_ACCEPTED_ACCURACY:
        return False, (
            f"kabul edilebilir isabet %{100 * accepted:.1f} < "
            f"%{100 * MIN_ACCEPTED_ACCURACY:.0f} akıl sağlığı tabanı"
        )

    if baseline:
        baseline_missed = int(baseline.get("missed_threats") or 0)
        if missed > baseline_missed:
            return False, f"kaçan THREAT arttı ({baseline_missed} → {missed})"

        baseline_accepted = float(baseline.get("accepted_accuracy") or 0)
        if accepted < baseline_accepted - ACCURACY_TOLERANCE:
            return False, (
                f"kabul edilebilir isabet geriledi "
                f"(%{100 * baseline_accepted:.1f} → %{100 * accepted:.1f})"
            )

    return True, "ölçüm eşikleri geçildi"
