"""
Version scheme inference for CVE extraction.
Distinguishes build numbers, dates, and semantic versions
so downstream can avoid comparing incompatible constraint types.
"""

import re


# Date patterns: "8/29/2019", "2019-08-29", "29.08.2019", "August 29, 2019" etc.
_DATE_PATTERNS = [
    re.compile(r"^\d{1,2}/\d{1,2}/\d{4}$"),           # 8/29/2019, 08/29/2019
    re.compile(r"^\d{4}-\d{2}-\d{2}$"),                # 2019-08-29
    re.compile(r"^\d{1,2}\.\d{1,2}\.\d{4}$"),          # 29.08.2019
    re.compile(r"^\d{4}/\d{2}/\d{2}$"),                # 2019/08/29
]


def _looks_like_date(version_str: str) -> bool:
    """True if the string is a date, not a version number."""
    s = version_str.strip()
    if not s or len(s) > 30:
        return False
    for pat in _DATE_PATTERNS:
        if pat.match(s):
            return True
    # Optional: "August 29, 2019" style — month name + day + year
    if re.search(r"\d{4}", s) and re.search(r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2}", s, re.I):
        return True
    return False


def infer_version_scheme(json_output: dict) -> str:
    """
    Infer the type of CVE version constraint.

    - "date": date constraint (e.g. "before 8/29/2019") — not comparable to version 1.6
    - "build": single large integer (e.g. 8684) — not comparable to semantic 1.6
    - "semantic": dotted version (e.g. 1.6, 9.0.5) — comparable with user versions
    - "unknown": cannot tell

    Returns:
        "date" | "build" | "semantic" | "unknown"
    """
    version_str = (
        json_output.get("less_than_or_equal")
        or json_output.get("less_than")
        or json_output.get("app_version")
        or json_output.get("greater_equal")
    )
    if not version_str or not isinstance(version_str, str):
        return "unknown"
    version_str = version_str.strip()
    version_str = re.sub(r"^[vV]", "", version_str)
    if not version_str:
        return "unknown"
    # Date first (e.g. "8/29/2019" from "before 8/29/2019")
    if _looks_like_date(version_str):
        return "date"
    # Single integer (no dot) and large → likely build number
    if re.match(r"^\d+$", version_str):
        try:
            n = int(version_str)
            if n >= 500:
                return "build"
            return "semantic"  # small integer like "2" can be semantic
        except ValueError:
            return "unknown"
    # Contains dot and not a date → semantic (1.6, 9.0.5, 141.0.7390.66)
    if "." in version_str:
        return "semantic"
    return "unknown"
