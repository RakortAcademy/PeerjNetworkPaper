"""
Her THREAT/SAFE/UNCERTAIN kararı için CVE description referanslı gerekçe metni.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def truncate_description(text: Optional[str], max_len: int = 1500) -> str:
    t = (text or "").strip().replace("\n", " ")
    if len(t) <= max_len:
        return t
    return t[: max_len - 3] + "..."


def format_constraint_label(constraint_type: str, constraint_version: str) -> str:
    ct = constraint_type or "eq"
    cv = constraint_version or ""
    if ct == "le":
        return f"<= {cv}"
    if ct == "lt":
        return f"< {cv}"
    if ct == "ge":
        return f">= {cv}"
    if ct == "range":
        return cv
    if ct == "llm_direct":
        return cv or "LLM"
    return f"== {cv}" if cv else "—"


_SEVERITY_KEYWORDS = [
    (100, ("remote code execution", "arbitrary code", "execute code", "code execution", "rce")),
    (80, ("deserialization", "sql injection", "command injection", "authentication bypass",
          "privilege escalation", "use after free", "buffer overflow")),
    (60, ("cross-site scripting", "xss", "server-side request forgery", "ssrf",
          "path traversal", "directory traversal", "xml external entity", "xxe",
          "information disclosure", "sensitive information")),
    (40, ("denial of service", "uncontrolled recursion", "infinite loop", "resource exhaustion")),
    (30, ("man-in-the-middle", "man in the middle", "interception", "hostname verification",
          "improper certificate")),
]


def severity_rank(text: Optional[str]) -> int:
    """Rough severity score from CVE description (no CVSS field is available in rows)."""
    t = (text or "").lower()
    for score, kws in _SEVERITY_KEYWORDS:
        if any(k in t for k in kws):
            return score
    return 10


def _lead_sort_key(row: Dict[str, Any]):
    # Highest severity first; tie-break by CVE id ascending (older/landmark CVEs lead).
    return (-severity_rank(row.get("description")), row.get("cve_id") or "")


def explain_cve_row(row: Dict[str, Any], verdict: str) -> Dict[str, Any]:
    """
    Adds decision_explanation and reference fields onto the row (in-place + return).
    verdict: THREAT | SAFE | UNCERTAIN
    """
    cve_id = row.get("cve_id") or "?"
    desc = truncate_description(row.get("description"))
    product = row.get("affected_product") or row.get("product") or "?"
    your_ver = row.get("your_version") or row.get("version") or "?"
    constraint = format_constraint_label(
        row.get("constraint_type", ""),
        row.get("constraint_version", ""),
    )
    reason = (row.get("reason") or "").strip()

    if verdict == "THREAT":
        explanation = (
            f"THREAT: According to reference CVE {cve_id}, for '{product}' the version "
            f"constraint ({constraint}) places your version ({your_ver}) within the affected range. "
            f"Comparison: {reason}. "
            f"CVE text: «{desc}»"
        )
    elif verdict == "SAFE":
        explanation = (
            f"SAFE: According to reference CVE {cve_id}, for '{product}' the version "
            f"constraint ({constraint}) does not place your version ({your_ver}) within the affected range. "
            f"Comparison: {reason}. "
            f"CVE text: «{desc}»"
        )
    else:
        why = row.get("uncertain_reason") or reason or "Version constraint or product match is unclear."
        explanation = (
            f"UNCERTAIN: CVE {cve_id} was reviewed; no definitive decision could be made. "
            f"Reason: {why} "
            f"CVE text: «{desc}»"
        )

    row["verdict"] = verdict
    row["reference_cve_id"] = cve_id
    row["reference_cve_description"] = desc
    row["decision_explanation"] = explanation
    return row


def uncertain_row(
    cve_id: str,
    description: str,
    reason: str,
    *,
    affected_product: Optional[str] = None,
    your_version: Optional[str] = None,
) -> Dict[str, Any]:
    base = {
        "cve_id": cve_id,
        "description": description,
        "uncertain_reason": reason,
        "affected_product": affected_product,
        "your_version": your_version,
        "constraint_type": "",
        "constraint_version": "",
        "reason": reason,
    }
    return explain_cve_row(base, "UNCERTAIN")


def build_product_decision_summary(result: Dict[str, Any]) -> Dict[str, Any]:
    """Ürün bazlı nihai karar özeti + referans CVE listesi."""
    status = (result.get("status") or "SAFE").upper()
    product = result.get("product", "")
    version = result.get("version", "")
    threats: List[Dict[str, Any]] = result.get("threats") or []
    safe_reasons: List[Dict[str, Any]] = result.get("safe_reasons") or []
    uncertain_items: List[Dict[str, Any]] = result.get("uncertain_items") or []

    primary_refs: List[Dict[str, str]] = []

    if status == "THREAT" and threats:
        # Lead = most critical CVE (severity heuristic), not just the first scanned.
        ordered = sorted(threats, key=_lead_sort_key)
        lead = ordered[0]
        primary_refs.append(
            {
                "cve_id": lead.get("cve_id", ""),
                "description_excerpt": truncate_description(lead.get("description"), 800),
                "role": "primary_threat",
            }
        )
        summary = (
            f"Result THREAT: {len(threats)} CVE match(es) found for {product} v{version}. "
            f"Primary reference: {lead.get('cve_id')} — based on the version constraint in this CVE, "
            f"your version is affected ({lead.get('reason', '')}). "
            f"CVE summary: «{truncate_description(lead.get('description'), 400)}»"
        )
        for t in ordered[1:5]:
            primary_refs.append(
                {
                    "cve_id": t.get("cve_id", ""),
                    "description_excerpt": truncate_description(t.get("description"), 400),
                    "role": "additional_threat",
                }
            )
    elif status == "SAFE" and safe_reasons:
        # Prefer a genuinely-applicable safe reason as the showcased example;
        # only fall back to a 'not applicable / different product' entry if that
        # is all we have, so we never parade an irrelevant CVE as the reference.
        lead = next(
            (r for r in safe_reasons if not r.get("not_applicable")),
            safe_reasons[0],
        )
        primary_refs.append(
            {
                "cve_id": lead.get("cve_id", ""),
                "description_excerpt": truncate_description(lead.get("description"), 800),
                "role": "primary_safe",
            }
        )
        summary = (
            f"Result SAFE: for {product} v{version}, your version does not fall within the "
            f"threat range among the scanned CVEs. "
            f"Example reference: {lead.get('cve_id')} — per the CVE description: {lead.get('reason', '')}. "
            f"CVE summary: «{truncate_description(lead.get('description'), 400)}»"
        )
        n_show = min(3, len(safe_reasons))
        if len(safe_reasons) > 1:
            summary += f" ({len(safe_reasons)} CVEs deemed safe; {n_show} sample(s) shown in the report.)"
    elif status == "UNCERTAIN":
        if uncertain_items:
            lead = uncertain_items[0]
            primary_refs.append(
                {
                    "cve_id": lead.get("cve_id", ""),
                    "description_excerpt": truncate_description(lead.get("description"), 800),
                    "role": "uncertain_sample",
                }
            )
            summary = (
                f"Result UNCERTAIN: {product} v{version} — for {result.get('n_uncertain', 0)} CVE(s) "
                f"the product matched but the version constraint could not be clearly derived from the "
                f"CVE description, or the comparison could not be made. "
                f"Example: {lead.get('cve_id')}: {lead.get('uncertain_reason', '')}. "
                f"CVE text: «{truncate_description(lead.get('description'), 400)}»"
            )
        else:
            summary = (
                f"Result UNCERTAIN: {product} v{version} — a reliable version constraint "
                f"could not be derived."
            )
    elif status == "NOT_FOUND":
        na = [r for r in safe_reasons if r.get("not_applicable")]
        if na:
            summary = (
                f"Result NOT_FOUND: no CVE in the reference database applies to "
                f"{product} v{version}. {len(na)} nearby CVE(s) matched only by keyword "
                f"and reference different products/vendors, so they were excluded."
            )
        else:
            summary = (
                f"Result NOT_FOUND: no product match for {product} v{version} in the "
                f"reference CVE database."
            )
    else:
        summary = f"Result {status}: {product} v{version}."

    return {
        "status": status,
        "summary": summary,
        # Backward-compat key kept; content is English now for a single-language pipeline.
        "summary_tr": summary,
        "reference_cves": primary_refs,
        "how_to_verify": (
            "To verify the decision, compare the CVE ID in decision_explanation and the "
            "reference_cve_description text against the official NVD/CVE record."
        ),
    }
