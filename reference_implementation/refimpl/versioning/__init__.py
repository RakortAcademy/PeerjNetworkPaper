"""Sürüm ayrıştırma, karşılaştırma ve aralık eşleme."""
from .comparator import VersionComparator
from .parser import Version, compare_versions, parse_version
from .range_matcher import check_version_in_range

__all__ = [
    "Version",
    "VersionComparator",
    "check_version_in_range",
    "compare_versions",
    "parse_version",
]
