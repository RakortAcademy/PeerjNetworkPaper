"""
Semantic Version Parser
Parses version strings into comparable components
"""

import re
from functools import lru_cache
from typing import Optional, Tuple


class Version:
    """
    Represents a semantic version
    Format: major.minor.patch.revision[-prerelease][+build]
    Supports 2, 3, or 4+ segment versions
    """
    
    def __init__(self, major=0, minor=0, patch=0, revision=0, extra=None, prerelease=None, build=None, letter=None):
        self.major = major
        self.minor = minor
        self.patch = patch
        self.revision = revision  # 4th segment
        self.extra = extra or []  # 5th+ segments
        self.prerelease = prerelease
        self.build = build
        # OpenSSL-style trailing release letter (1.0.1f). Bir POST-release artışıdır:
        # harfsiz sürüm harfliden ÖNCE gelir (1.0.1 < 1.0.1a < 1.0.1f < 1.0.1g).
        # prerelease'in (1.0.1-rc1 < 1.0.1) tam tersi sırada çalışır.
        self.letter = (letter or "").lower() or None
    
    def __repr__(self):
        version = f"{self.major}.{self.minor}.{self.patch}"
        if self.revision > 0 or self.extra:
            version += f".{self.revision}"
        for e in self.extra:
            version += f".{e}"
        if self.letter:
            version += self.letter
        if self.prerelease:
            version += f"-{self.prerelease}"
        if self.build:
            version += f"+{self.build}"
        return version
    
    def __eq__(self, other):
        if not isinstance(other, Version):
            return False
        return (self.major == other.major and
                self.minor == other.minor and
                self.patch == other.patch and
                self.revision == other.revision and
                self.extra == other.extra and
                (self.letter or "") == (other.letter or ""))
    
    def __lt__(self, other):
        if not isinstance(other, Version):
            return NotImplemented

        # Compare major.minor.patch.revision
        if self.major != other.major:
            return self.major < other.major
        if self.minor != other.minor:
            return self.minor < other.minor
        if self.patch != other.patch:
            return self.patch < other.patch
        if self.revision != other.revision:
            return self.revision < other.revision

        # Compare extra segments
        for a, b in zip(self.extra, other.extra):
            if a != b:
                return a < b
        if len(self.extra) != len(other.extra):
            return len(self.extra) < len(other.extra)

        # OpenSSL-style release letter: harfsiz < harfli, sonra leksikal (a<b<...<g).
        # ör. 1.0.1 < 1.0.1a, 1.0.1f < 1.0.1g (yamalı). prerelease'ten ÖNCE bakılır.
        sl, ol = self.letter or "", other.letter or ""
        if sl != ol:
            return sl < ol

        # If versions are equal, check prerelease (SemVer 2.0)
        # Version with prerelease is less than without
        if self.prerelease and not other.prerelease:
            return True
        if not self.prerelease and other.prerelease:
            return False

        # Both have prerelease - compare them
        if self.prerelease and other.prerelease:
            return self._compare_prerelease(self.prerelease, other.prerelease) < 0

        return False

    @staticmethod
    def _compare_prerelease(pre1: str, pre2: str) -> int:
        """
        Compare two prerelease version strings following SemVer 2.0

        Returns:
            -1 if pre1 < pre2
             0 if pre1 == pre2
             1 if pre1 > pre2
        """
        if pre1 == pre2:
            return 0

        # Split by dots
        parts1 = pre1.split('.')
        parts2 = pre2.split('.')

        # Compare each part
        for p1, p2 in zip(parts1, parts2):
            # If both are numeric, compare as numbers
            if p1.isdigit() and p2.isdigit():
                if int(p1) != int(p2):
                    return -1 if int(p1) < int(p2) else 1
            # If one is numeric and one is not, numeric is less
            elif p1.isdigit():
                return -1
            elif p2.isdigit():
                return 1
            # Both are alphanumeric, compare lexically
            else:
                if p1 != p2:
                    return -1 if p1 < p2 else 1

        # If all parts are equal so far, shorter version is less
        if len(parts1) != len(parts2):
            return -1 if len(parts1) < len(parts2) else 1

        return 0
    
    def __le__(self, other):
        return self == other or self < other
    
    def __gt__(self, other):
        return not self <= other
    
    def __ge__(self, other):
        return not self < other
    
    def to_tuple(self):
        """Convert to tuple for comparison"""
        return (self.major, self.minor, self.patch, self.revision, *self.extra)


_RELEASE_LINE_RE = re.compile(r"^\d+(\.\d+)*$")

# Envanterden gelen sürüm alanı sürüm dışında da şeyler taşıyor:
#   "ad 9.7.3"        (AnyDesk kendi ön ekini yazıyor)
#   "v7.22.0"         (v ön eki)
#   "3.70.6 (64-bit)" (mimari eki)
# Ayrıştırılamayınca karar UNCERTAIN'e düşüyordu; oysa sürüm belliydi.
_VERSION_IN_TEXT_RE = re.compile(r"\d+(?:\.\d+)+(?:[-+][0-9A-Za-z.]+)?")


def clean_version_string(raw: Optional[str]) -> str:
    """Envanter sürüm alanından karşılaştırılabilir sürümü çıkarır.

    Metnin İÇİNDEKİ ilk nokta ayraçlı sayı dizisi alınır. Tek başına duran
    sayılar ("2026") kasten kabul edilmez: yıl, derleme ya da başka bir alan
    olabilir ve sürüm sanmak yanlış karar üretir.
    """
    text = (raw or "").strip()
    if not text:
        return ""
    if _RELEASE_LINE_RE.match(text):
        return text
    match = _VERSION_IN_TEXT_RE.search(text)
    return match.group(0) if match else text


def is_build_of(version_str: str, release_str: str) -> bool:
    """`version_str`, `release_str` sürümünün bir YAPISI mı?

    Windows envanterleri sürümü derleme numarasıyla birlikte bildirebilir:
    envanter "5.2.8.3141" der, CVE kaydı ise "5.2.8 ve altı" der. Saf sayısal
    kıyas 5.2.8.3141'i 5.2.8'in ÜSTÜNDE görür ve sürümü etkilenmiyor sayar —
    oysa 3141, 5.2.8 sürümünün derleme numarasıdır.

    Ölçüt nokta sınırında ön ek olmaktır; "5.2.80" bu kurala takılmaz çünkü
    "5.2.8." ile başlamıyor. Yalnızca kapsayıcı üst sınırlarda (`<=`) kullanılır:
    "5.2.8'e kadar dahil" ifadesi 5.2.8'ün tüm derlemelerini kapsar. Dışlayıcı
    sınırda (`< 5.2.8`) kullanılmaz — orada 5.2.8 zaten düzeltilmiş sürümdür.
    """
    version_str = (version_str or "").strip()
    release_str = (release_str or "").strip()
    if not version_str or not release_str or version_str == release_str:
        return False
    if not (_RELEASE_LINE_RE.match(version_str) and _RELEASE_LINE_RE.match(release_str)):
        return False
    return version_str.startswith(release_str + ".")


def version_scheme_mismatch(v1: Version, v2: Version) -> bool:
    """
    Detect when two versions likely use different versioning schemes and should
    not be compared (e.g. 1.0.0 vs 111.0.1661.41, or 1.6 vs build 8684).
    Returns True if comparison should be skipped (treat as uncertain).
    """
    if not v1 or not v2:
        return False
    # Aralık şemaları: biri küçük semver (1.x), diğeri büyük (Chrome 111.x, build 8684)
    lo = min(v1.major, v2.major)
    hi = max(v1.major, v2.major)
    if lo == 0:
        return hi >= 500  # e.g. "0.8" vs "8684"
    ratio = hi / (lo + 1)
    # Küçük major (< 20) vs büyük major (>= 50) → farklı şema (1.0.0 vs 111.0.x)
    if v1.major < 20 and v2.major >= 50:
        return True
    if v2.major < 20 and v1.major >= 50:
        return True
    if ratio <= 50:
        return False
    has_big_single = (v1.major >= 500 and v1.minor == 0 and v1.patch == 0) or (
        v2.major >= 500 and v2.minor == 0 and v2.patch == 0
    )
    has_small_semantic = (v1.major < 100 and (v1.minor != 0 or v1.patch != 0)) or (
        v2.major < 100 and (v2.minor != 0 or v2.patch != 0)
    )
    return ratio > 50 and (has_big_single or has_small_semantic)


#: Sürüm ayrıştırma tek bir taramada aday sayısı × aralık sayısı kadar
#: çağrılıyor, girdi kümesi ise görece az sayıda ayrı dizgeden ibaret; bu yüzden
#: sonuç önbelleklenir.
#:
#: Dönen `Version` nesnesi PAYLAŞILIR. Güvenli, çünkü nesne yalnızca okunuyor:
#: kod tabanında hiçbir yerde alanlarına atama yapılmıyor (yalnızca `__init__`).
#: Bu değişirse önbellek kaldırılmalı.
@lru_cache(maxsize=100_000)
def parse_version(version_str: str) -> Optional[Version]:
    """
    Parse a version string into Version object

    Supports formats:
    - 1.2.3
    - 1.2.3-alpha
    - 1.2.3+build123
    - 1.2.3-rc1+build456
    - v1.2.3 (strips 'v' prefix)
    - Complex formats: "prior to 1.7.4", "up to 0.8.2", "through 2.5.0", "before 9.0.5"
    - Range formats: "1.x before 1.7.4", "1.0.4 and earlier"

    Args:
        version_str (str): Version string

    Returns:
        Version: Parsed version object or None if invalid
    """
    if not version_str:
        return None

    # Strip whitespace
    version_str = version_str.strip()

    # Remove 'v' or 'V' prefix
    if version_str.lower().startswith('v'):
        version_str = version_str[1:]

    # IMPROVEMENT 1: Normalize comma decimals (European format: "2,4" → "2.4")
    version_str = version_str.replace(',', '.')

    # IMPROVEMENT 2: Handle build number concatenation ("10.0 build 19045" → "10.0.19045")
    build_pattern = r'^(\d+(?:\.\d+)*)\s+build\s+(\d+)$'
    build_match = re.match(build_pattern, version_str, re.IGNORECASE)
    if build_match:
        version_str = f"{build_match.group(1)}.{build_match.group(2)}"

    # IMPROVEMENT 3: Handle wildcard versions ("2.x" → "2.0", "2.4.x" → "2.4.0")
    # Note: Wildcard expansion to range is handled in range_matcher
    wildcard_pattern = r'^(\d+(?:\.\d+)*)\.x$'
    wildcard_match = re.match(wildcard_pattern, version_str, re.IGNORECASE)
    if wildcard_match:
        version_str = f"{wildcard_match.group(1)}.0"

    # Handle complex version string patterns (e.g., "prior to 465.0", "up to 0.8.2")
    complex_patterns = [
        (r'(?:prior\s+to|before)\s+v?(\d+(?:\.\d+)*)', 1),     # "prior to X" or "before vX" → X
        (r'(?:up\s+to|through)\s+(?:version\s+)?(\d+(?:\.\d+)*(?:\s+[A-Z]+\d*)?)', 1),  # "up to version 2.0 RC2" → 2.0
        (r'(\d+(?:\.\d+)*)\s+and\s+earlier', 1),               # "X and earlier" → X
        (r'(\d+\.x)\s+before\s+(\d+(?:\.\d+)*)', 2),           # "1.x before X" → X
    ]

    for pattern, group_idx in complex_patterns:
        match = re.search(pattern, version_str, re.IGNORECASE)
        if match:
            # Extract the version number from the matched group
            version_str = match.group(group_idx)
            break

    # OpenSSL-tipi sondaki release harfini ayrı yakala (1.0.1f → "1.0.1" + "f").
    # Yalnızca rakamı doğrudan izleyen TEK harf; "1.0.1-alpha" (tireli prerelease)
    # ve "111.0.1661.41" (tümü rakam) etkilenmez. Böylece yamalı 1.0.1g, zafiyetli
    # 1.0.1f'ten ayrılır (önceden ikisi de 1.0.1'e düşüp FP üretiyordu).
    letter = None
    _letter_match = re.match(r'^(.*\d)([a-zA-Z])$', version_str)
    if _letter_match:
        version_str = _letter_match.group(1)
        letter = _letter_match.group(2)

    # Pattern: major.minor.patch[-prerelease][+build]
    pattern = r'^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([a-zA-Z0-9.-]+))?(?:\+([a-zA-Z0-9.-]+))?$'
    match = re.match(pattern, version_str)

    if not match:
        # Try to extract numeric parts (handles 1.2.3.4.5... format)
        numeric_pattern = r'^(\d+(?:\.\d+)*)'
        numeric_match = re.match(numeric_pattern, version_str)
        if numeric_match:
            parts = numeric_match.group(1).split('.')
            parts = [int(p) for p in parts]
            major = parts[0] if len(parts) > 0 else 0
            minor = parts[1] if len(parts) > 1 else 0
            patch = parts[2] if len(parts) > 2 else 0
            revision = parts[3] if len(parts) > 3 else 0
            extra = parts[4:] if len(parts) > 4 else []
            return Version(major, minor, patch, revision, extra, letter=letter)
        return None

    major = int(match.group(1))
    minor = int(match.group(2)) if match.group(2) else 0
    patch = int(match.group(3)) if match.group(3) else 0
    prerelease = match.group(4) if match.group(4) else None
    build = match.group(5) if match.group(5) else None

    return Version(major, minor, patch, 0, [], prerelease, build, letter=letter)


def expand_wildcard_version(version_str: str) -> Optional[dict]:
    """
    Expand wildcard version to range

    Examples:
        "2.x" → {'version': '2.0.0', 'less_than': '3.0.0'}
        "2.4.x" → {'version': '2.4.0', 'less_than': '2.5.0'}
        "2.4.*" → {'version': '2.4.0', 'less_than': '2.5.0'}

    Args:
        version_str (str): Version string with wildcard

    Returns:
        dict: {'version': lower_bound, 'less_than': upper_bound} or None
    """
    if not version_str:
        return None

    # Handle X.x format (e.g., "2.x")
    match = re.match(r'^(\d+)\.(?:x|\*)$', version_str, re.IGNORECASE)
    if match:
        major = int(match.group(1))
        return {
            'version': f'{major}.0.0',
            'less_than': f'{major + 1}.0.0'
        }

    # Handle X.Y.x format (e.g., "2.4.x")
    match = re.match(r'^(\d+)\.(\d+)\.(?:x|\*)$', version_str, re.IGNORECASE)
    if match:
        major = int(match.group(1))
        minor = int(match.group(2))
        return {
            'version': f'{major}.{minor}.0',
            'less_than': f'{major}.{minor + 1}.0'
        }

    # Handle X.Y.Z.x format (e.g., "2.4.1.x")
    match = re.match(r'^(\d+)\.(\d+)\.(\d+)\.(?:x|\*)$', version_str, re.IGNORECASE)
    if match:
        major = int(match.group(1))
        minor = int(match.group(2))
        patch = int(match.group(3))
        return {
            'version': f'{major}.{minor}.{patch}.0',
            'less_than': f'{major}.{minor}.{patch + 1}.0'
        }

    return None


def detect_adobe_version_family(version_str: str) -> Optional[str]:
    """
    Detect Adobe Acrobat version family (year-based vs number-based)

    Year-based: 2015.x.y.z, 2017.x.y.z, 2020.x.y.z
    Number-based: 11.x.y.z, 20.x.y.z, 21.x.y.z

    Args:
        version_str (str): Version string

    Returns:
        str: 'year-based' or 'number-based' or None
    """
    if not version_str:
        return None

    ver = parse_version(version_str)
    if not ver:
        return None

    # If major version >= 1000, it's year-based
    if ver.major >= 1000:
        return 'year-based'
    else:
        return 'number-based'


def are_adobe_versions_compatible(version1_str: str, version2_str: str) -> bool:
    """
    Check if two Adobe Acrobat versions are from the same family

    Args:
        version1_str (str): First version
        version2_str (str): Second version

    Returns:
        bool: True if same family, False otherwise
    """
    family1 = detect_adobe_version_family(version1_str)
    family2 = detect_adobe_version_family(version2_str)

    if family1 is None or family2 is None:
        return False

    return family1 == family2


def compare_versions(v1_str: str, v2_str: str) -> int:
    """
    Compare two version strings
    
    Args:
        v1_str (str): First version string
        v2_str (str): Second version string
    
    Returns:
        int: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
    """
    v1 = parse_version(v1_str)
    v2 = parse_version(v2_str)
    
    if v1 is None or v2 is None:
        return 0
    
    if v1 < v2:
        return -1
    elif v1 == v2:
        return 0
    else:
        return 1


if __name__ == '__main__':
    # Test version parsing
    print("="*80)
    print("VERSION PARSER TEST")
    print("="*80)
    
    test_versions = [
        "1.2.3",
        "v1.2.3",
        "1.2.3-alpha",
        "1.2.3-rc1+build456",
        "2.0.0",
        "1.18.0",
        "9.0.1",
        "460.32.03"
    ]
    
    for ver_str in test_versions:
        ver = parse_version(ver_str)
        print(f"{ver_str:20s} → {ver}")
    
    # Test comparison
    print("\n" + "="*80)
    print("VERSION COMPARISON TEST")
    print("="*80)
    
    comparisons = [
        ("1.2.3", "1.2.4"),
        ("1.2.3", "1.2.3"),
        ("1.2.3", "1.2.2"),
        ("2.0.0", "1.9.9"),
        ("1.18.0", "1.9.0"),
        ("9.0.1", "9.0.5"),
        ("460.32.03", "465.0"),
    ]
    
    for v1, v2 in comparisons:
        result = compare_versions(v1, v2)
        if result == -1:
            symbol = "<"
        elif result == 0:
            symbol = "=="
        else:
            symbol = ">"
        print(f"{v1:15s} {symbol} {v2:15s}")
