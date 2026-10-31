"""
THREAT/SAFE politikası — bir THREAT kararının yayınlanmadan önce geçmesi gereken kapılar.

Bu katman precision içindir: ürün kimliği yapısal olarak doğrulanamayan ya da
sürüm çıkarımı şüpheli görünen adaylar THREAT yerine UNCERTAIN olarak işaretlenir.
Bilinen false-positive sınıflarının her biri bu kapılardan birine takılır.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, Optional, Tuple


def threat_product_gate_enabled() -> bool:
    raw = os.environ.get("CVE_THREAT_PRODUCT_GATE")
    if raw is not None:
        return raw.strip().lower() in ("1", "true", "yes")
    return True


def is_kernel_inventory_mismatch(data: Dict[str, Any]) -> bool:
    """Journal 2.0 ↔ Linux kernel CVE gibi bariz domain kayması."""
    if not data:
        return False
    desc = (data.get("description") or "").lower()
    if "linux kernel" not in desc and "in the linux kernel" not in desc:
        return False
    inv = (data.get("product_normalized") or data.get("your_product") or "").lower()
    if any(k in inv for k in ("linux", "kernel", "ubuntu", "debian", "rhel", "centos")):
        return False
    return True


def is_suspect_line_number_constraint(data: Dict[str, Any]) -> bool:
    """BiLSTM kaynak kod satır numarasını sürüm sanmış (< 48, LINE#1794)."""
    if not data:
        return False
    cv = (data.get("constraint_version") or "").strip()
    yv = (data.get("your_version") or "").strip()
    desc = data.get("description") or ""
    if not cv or not yv:
        return False
    if re.search(r"LINE#\d+", desc, re.I):
        if re.match(r"^<\s*\d+$", cv) or re.match(r"^<=\s*\d+$", cv):
            return True
    if re.match(r"^<\s*\d+$", cv) and re.search(r"\d+\.\d+", yv):
        bound = re.sub(r"^<\s*", "", cv)
        try:
            if int(bound) >= 10 and "." not in bound:
                return True
        except ValueError:
            pass
    return False


def is_suspect_broad_range_row(data: Dict[str, Any]) -> bool:
    """BiLSTM'in ürettiği 1..10.x gibi geniş aralıklar — THREAT güvenilmez."""
    if not data:
        return False
    if (data.get("constraint_type") or "") != "range":
        return False
    cv = (data.get("constraint_version") or "").strip().lower()
    if cv.startswith(("1 ..", "1.0 ..", "0 ..", "0.0 ..")):
        return True
    for chk in data.get("checks") or []:
        if chk.get("type") == "range":
            c = (chk.get("constraint") or "").lower()
            if c.startswith(("1 <=", "0 <=", "1.0 <=")):
                return True
    return False


def _block_threat_as_uncertain(
    data: Dict[str, Any],
    reason: str,
    block_tag: str,
) -> Tuple[str, Dict[str, Any]]:
    from refimpl.rationale import uncertain_row

    u = uncertain_row(
        data.get("cve_id") or "?",
        data.get("description") or "",
        reason,
        affected_product=data.get("affected_product"),
        your_version=data.get("your_version"),
    )
    u["blocked_" + block_tag] = True
    u["original_constraint"] = data.get("constraint_version")
    u["product_normalized"] = data.get("product_normalized")
    return "uncertain", u


def _enforce_threat_product_gate(data: Dict[str, Any]) -> Tuple[str, Optional[Dict[str, Any]]]:
    from refimpl.identity import assess_threat_product_identity

    confirmed, block_reason, method = assess_threat_product_identity(data)
    if not confirmed and block_reason:
        return _block_threat_as_uncertain(
            data,
            f"{block_reason} — THREAT is not reliable, marked UNCERTAIN.",
            "product_identity",
        )
    if confirmed:
        data = dict(data)
        data["threat_product_gate"] = method
        return "threat", data

    # Yapısal kanıt yok. Ürün adı çakışmaları (Autodesk↔NetIQ "Identity Manager",
    # Surveillance↔Dell "Unity", Visual J#↔Redis) burada elenir.
    return _block_threat_as_uncertain(
        data,
        "Product identity could not be structurally verified; false-positive risk "
        "from product name collision — UNCERTAIN.",
        "needs_structural",
    )


def enforce_outcome_policy(
    outcome: str,
    data: Optional[Dict[str, Any]],
) -> Tuple[str, Optional[Dict[str, Any]]]:
    """THREAT adaylarını politika kapılarından geçirir; geçemeyen UNCERTAIN olur."""
    if outcome != "threat" or not data:
        return outcome, data

    if is_kernel_inventory_mismatch(data) or is_suspect_line_number_constraint(data):
        return _block_threat_as_uncertain(
            data,
            "Product/CVE domain mismatch or incorrect version inference "
            "(e.g. kernel source line number); THREAT is not reliable — UNCERTAIN.",
            "domain_mismatch",
        )

    if is_suspect_broad_range_row(data):
        return _block_threat_as_uncertain(
            data,
            "CVE version range is too broad (likely incorrect inference); "
            "structural verification is not reliable — UNCERTAIN.",
            "broad_range",
        )

    if threat_product_gate_enabled():
        return _enforce_threat_product_gate(data)

    return "threat", data
