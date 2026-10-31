"""
Fuzzy Matcher
Implements fuzzy string matching for product names
"""

from difflib import SequenceMatcher
from functools import lru_cache
import re

# Handle both standalone and package imports
try:
    from .vendor_aliases import normalize_vendor, should_apply_vendor_normalization
except ImportError:
    from vendor_aliases import normalize_vendor, should_apply_vendor_normalization


def levenshtein_distance(s1, s2):
    """
    Calculate Levenshtein distance between two strings
    
    Args:
        s1 (str): First string
        s2 (str): Second string
    
    Returns:
        int: Edit distance
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            # Cost of insertions, deletions, or substitutions
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]


# source_v2 MAKE_THE_PRODUCT_BETTER: kaldırılacak token setleri
_ARCHITECTURE_TOKENS = {
    'x86', 'x64', 'x86_64', 'arm', 'arm64', 'aarch64',
    '32-bit', '64-bit', '32bit', '64bit', 'win32', 'win64'
}
_CHANNEL_TOKENS = {
    'beta', 'rc', 'canary', 'dev', 'insider', 'nightly', 'preview',
    'alpha', 'technical', 'stable', 'release'
}
_PACKAGING_TOKENS = {
    'installer', 'msi', 'exe', 'pkg', 'dmg', 'deb', 'rpm', 'setup',
    'appx', 'snap', 'flatpak'
}
_PLATFORM_SUFFIX_TOKENS = {'windows', 'linux', 'mac', 'macos', 'android', 'ios'}
_LOCALE_TOKENS = {
    'en-us', 'en_us', 'tr-tr', 'tr_tr', 'english', 'türkçe', 'turkce',
    'german', 'de-de', 'french', 'fr-fr', 'spanish', 'japanese', 'chinese'
}
_EDITION_TOKENS = {
    'professional', 'pro', 'enterprise', 'standard', 'community',
    'education', 'home', 'ultimate', 'ltsc', 'ltsb', 'lts', 'dc'
}


#: Ürün adı normalizasyonu bir taramada çok kez çağrılıyor, girdi kümesi ise
#: aday sayısıyla sınırlı; bu yüzden sonuç önbelleklenir.
@lru_cache(maxsize=50_000)
def normalize_product_name(name):
    """
    Normalize product name for better matching.
    source_v2: x86/beta/installer/platform/language/edition kaldır.
    """
    if not name:
        return ""
    # Turkish suffix
    turkish_suffixes = [
        r'\s+Çalışma Zamanı$', r'\s+Yazılımı$', r'\s+Uygulaması$',
        r'\s+Programı$', r'\s+Sürümü$', r'\s+İstemcisi$', r'\s+Sunucusu$',
    ]
    for suffix in turkish_suffixes:
        name = re.sub(suffix, '', name, flags=re.IGNORECASE)
    # "for Windows/Mac/Linux" kaldır
    name = re.sub(r'\s+for\s+(windows|linux|mac|macos|android|ios)\b', '', name, flags=re.IGNORECASE)
    # Parantez içi mimari/channel (64-bit), (x64), (32-bit) tek blok kaldır
    name = re.sub(r'\s*\(\s*(?:64|32)\s*[-]?\s*bit\s*\)', '', name, flags=re.IGNORECASE)
    name = re.sub(r'\s*\(\s*x64\s*\)', '', name, flags=re.IGNORECASE)
    name = name.lower()
    name = re.sub(r'([a-z])([A-Z])', r'\1 \2', name)
    name = re.sub(r'[_/\\\-]+', ' ', name)
    stopwords = [
        'the', 'a', 'an', 'for', 'by', 'with', 'in', 'on', 'at', 'of', 'and',
        'inc', 'llc', 'ltd', 'corp', 'corporation', 'company', 'co'
    ]
    tokens = [t for t in name.split() if t not in stopwords]
    # Mimari / kanal / paket / dil / edition token'larını at; platform
    # isimlerini (windows/linux/macos vs.) genel olarak TUT (sadece "for X"
    # kalıbında yukarıda temizleniyor). Böylece "Linux Kernel" → "linux kernel"
    # gibi anlamlı birleşik isimler korunur.
    remove_set = (
        _ARCHITECTURE_TOKENS | _CHANNEL_TOKENS | _PACKAGING_TOKENS
        | _LOCALE_TOKENS | _EDITION_TOKENS
    )
    new_tokens = []
    for t in tokens:
        t_clean = re.sub(r'[^\w]', '', t).lower()
        if t_clean in remove_set:
            continue
        new_tokens.append(t)
    tokens = new_tokens
    new_tokens = [t for t in tokens if not re.match(r'^\d+\.\d+', t)]
    tokens = [re.sub(r'[^\w\s]', '', t) for t in new_tokens]
    tokens = [t for t in tokens if t.strip() and len(t.strip()) > 1]
    return ' '.join(tokens)


def _best_similarity(a, b):
    """Return best similarity score between two strings"""
    seq_score = SequenceMatcher(None, a, b).ratio()
    distance = levenshtein_distance(a, b)
    max_len = max(len(a), len(b))
    lev_score = 1 - (distance / max_len) if max_len > 0 else 0.0
    return max(seq_score, lev_score)


def fuzzy_match(cve_product, inventory_product, threshold=0.8):
    """
    Perform fuzzy matching between CVE product and inventory product

    Args:
        cve_product (str): Product name from CVE
        inventory_product (str): Product name from customer inventory
        threshold (float): Similarity threshold (0-1)

    Returns:
        dict: {
            'match': bool,
            'score': float,
            'method': str
        }
    """
    if not cve_product or not inventory_product:
        return {'match': False, 'score': 0.0, 'method': 'null'}

    # Apply vendor normalization first (if beneficial)
    cve_normalized = cve_product
    inv_normalized = inventory_product

    if should_apply_vendor_normalization(cve_product, inventory_product):
        cve_normalized = normalize_vendor(cve_product)
        inv_normalized = normalize_vendor(inventory_product)

    # Normalize product names
    cve_norm = normalize_product_name(cve_normalized)
    inv_norm = normalize_product_name(inv_normalized)

    # Product alias: OpenJDK <-> Java SE / JDK / Oracle Java (CVE often uses these for same product)
    if inv_norm == 'openjdk' and cve_norm:
        cve_lower = cve_norm.lower()
        if cve_norm in ('openjdk', 'jdk', 'java se', 'oracle java se', 'oracle java', 'java runtime') or 'openjdk' in cve_lower:
            return {'match': True, 'score': 0.9, 'method': 'product_alias'}
        cve_tokens = set(cve_norm.split())
        if 'jdk' in cve_tokens and 'javascript' not in cve_lower:
            return {'match': True, 'score': 0.85, 'method': 'product_alias'}
        if 'java' in cve_tokens and ('se' in cve_tokens or 'runtime' in cve_tokens):
            return {'match': True, 'score': 0.85, 'method': 'product_alias'}
        if 'oracle' in cve_tokens and 'java' in cve_tokens:
            return {'match': True, 'score': 0.85, 'method': 'product_alias'}
    
    # Method 1: Exact match (after normalization)
    if cve_norm == inv_norm:
        return {'match': True, 'score': 1.0, 'method': 'exact'}
    
    # Method 2: Token-based matching (NEW! - Best for partial matches)
    # Compare token overlap - robust against extra words like "chromium based"
    cve_tokens = set(cve_norm.split())
    inv_tokens = set(inv_norm.split())
    
    # Remove very common/generic tokens that don't help matching
    generic_tokens = {'runtime', 'application', 'software', 'program', 'app', 'based', 'chromium'}
    cve_tokens = cve_tokens - generic_tokens
    inv_tokens = inv_tokens - generic_tokens
    
    if cve_tokens and inv_tokens:
        # Calculate Jaccard similarity (intersection / union)
        intersection = cve_tokens & inv_tokens
        union = cve_tokens | inv_tokens
        token_score = len(intersection) / len(union) if union else 0
        
        # Also check if significant tokens overlap (at least 2 important tokens)
        if len(intersection) >= 2 and token_score >= (threshold * 0.75):  # Lower threshold for token matching
            return {'match': True, 'score': token_score, 'method': 'token_overlap'}
    
    # Method 3: Substring match
    if cve_norm in inv_norm or inv_norm in cve_norm:
        score = min(len(cve_norm), len(inv_norm)) / max(len(cve_norm), len(inv_norm))
        if score >= threshold:
            return {'match': True, 'score': score, 'method': 'substring'}
    
    # Uzunluk kapısı — Method 4 ve 5'ten ÖNCE.
    #
    # Her iki ölçüt de uzunluk farkıyla sınırlıdır:
    #   levenshtein: 1 - dist/max_len ≤ 1 - |la-lb|/max_len
    #   difflib    : 2M/(la+lb) ≤ 2·min(la,lb)/(la+lb)
    # İkisi de eşiğin altında kalıyorsa hesaplamaya gerek yok. Bu iki yöntem
    # bir taramanın belirgin bir payını tutuyordu ve çağrıların
    # ezici çoğunluğu adları uzunlukça hiç yakın olmayan çiftlerdi.
    la, lb = len(cve_norm), len(inv_norm)
    max_len = max(la, lb)
    if max_len == 0:
        return {'match': False, 'score': token_score if 'token_score' in locals() else 0,
                'method': 'none'}
    lev_ceiling = 1 - abs(la - lb) / max_len
    seq_ceiling = 2 * min(la, lb) / (la + lb)
    if max(lev_ceiling, seq_ceiling) < threshold:
        return {'match': False,
                'score': max(token_score if 'token_score' in locals() else 0, seq_ceiling),
                'method': 'length_gate'}

    # Method 4: SequenceMatcher (Python difflib)
    seq_score = SequenceMatcher(None, cve_norm, inv_norm).ratio()
    if seq_score >= threshold:
        return {'match': True, 'score': seq_score, 'method': 'sequence_matcher'}

    # Method 5: Levenshtein distance
    lev_score = 0.0
    if lev_ceiling >= threshold:
        distance = levenshtein_distance(cve_norm, inv_norm)
        lev_score = 1 - (distance / max_len)
        if lev_score >= threshold:
            return {'match': True, 'score': lev_score, 'method': 'levenshtein'}

    # No match - return best score we found
    best_score = max(
        token_score if 'token_score' in locals() else 0,
        seq_score,
        lev_score,
    )
    return {'match': False, 'score': best_score, 'method': 'none'}


class FuzzyMatcher:
    """
    Fuzzy matching for product names
    """
    
    def __init__(self, threshold=0.8):
        """
        Initialize fuzzy matcher
        
        Args:
            threshold (float): Similarity threshold (0-1)
        """
        self.threshold = threshold
    
    def match(self, cve_product, inventory_products):
        """
        Find best match from inventory
        
        Args:
            cve_product (str): Product name from CVE
            inventory_products (list): List of inventory product names
        
        Returns:
            dict: {
                'matched': bool,
                'best_match': str or None,
                'score': float,
                'method': str,
                'all_scores': list
            }
        """
        if not cve_product or not inventory_products:
            return {
                'matched': False,
                'best_match': None,
                'score': 0.0,
                'method': 'none',
                'all_scores': []
            }
        
        # Try matching with each inventory product
        results = []
        for inv_product in inventory_products:
            match_result = fuzzy_match(cve_product, inv_product, self.threshold)
            results.append({
                'product': inv_product,
                'score': match_result['score'],
                'method': match_result['method']
            })
        
        # Sort by score
        results.sort(key=lambda x: x['score'], reverse=True)
        
        # Best match
        best = results[0] if results else None
        
        # Token overlap uses lower threshold (0.75 * threshold), so check method too
        if best and (best['score'] >= self.threshold or best['method'] == 'token_overlap'):
            return {
                'matched': True,
                'best_match': best['product'],
                'score': best['score'],
                'method': best['method'],
                'all_scores': results
            }
        else:
            return {
                'matched': False,
                'best_match': best['product'] if best else None,
                'score': best['score'] if best else 0.0,
                'method': best['method'] if best else 'none',
                'all_scores': results
            }

    def match_in_text(self, text, inventory_products):
        """
        Try to match inventory products inside free-form text by scanning n-grams.

        Args:
            text (str): Source text (e.g., CVE description)
            inventory_products (list): List of inventory product names

        Returns:
            dict: Same structure as match()
        """
        if not text or not inventory_products:
            return {
                'matched': False,
                'best_match': None,
                'score': 0.0,
                'method': 'none',
                'all_scores': []
            }

        text_norm = normalize_product_name(text)
        tokens = text_norm.split()
        if not tokens:
            return {
                'matched': False,
                'best_match': None,
                'score': 0.0,
                'method': 'none',
                'all_scores': []
            }

        results = []
        for inv_product in inventory_products:
            inv_norm = normalize_product_name(inv_product)
            inv_tokens = inv_norm.split()
            if not inv_tokens:
                continue

            n = len(inv_tokens)
            best_score = 0.0

            # Evaluate n-grams (n and n+1) to allow minor splits/joins
            for size in (n, n + 1):
                if size <= 0 or size > len(tokens):
                    continue
                for i in range(len(tokens) - size + 1):
                    candidate = ' '.join(tokens[i:i + size])
                    score = _best_similarity(candidate, inv_norm)
                    if score > best_score:
                        best_score = score

            results.append({
                'product': inv_product,
                'score': best_score,
                'method': 'text_ngram'
            })

        results.sort(key=lambda x: x['score'], reverse=True)
        best = results[0] if results else None

        if best and best['score'] >= self.threshold:
            return {
                'matched': True,
                'best_match': best['product'],
                'score': best['score'],
                'method': best['method'],
                'all_scores': results
            }
        return {
            'matched': False,
            'best_match': best['product'] if best else None,
            'score': best['score'] if best else 0.0,
            'method': best['method'] if best else 'none',
            'all_scores': results
        }


if __name__ == '__main__':
    # Test fuzzy matching
    print("="*80)
    print("FUZZY MATCHING TEST")
    print("="*80)
    
    test_cases = [
        {
            'cve_product': 'Apache Tomcat',
            'inventory': ['Tomcat', 'Apache HTTP Server', 'Apache Kafka']
        },
        {
            'cve_product': 'NVIDIA GPU Display Driver',
            'inventory': ['NVIDIA Display Driver', 'AMD Graphics Driver', 'Intel Graphics']
        },
        {
            'cve_product': 'Log4j',
            'inventory': ['Apache Log4j', 'Logback', 'SLF4J']
        }
    ]
    
    matcher = FuzzyMatcher(threshold=0.7)
    
    for test in test_cases:
        print(f"\nCVE Product: {test['cve_product']}")
        print(f"Inventory: {test['inventory']}")
        
        result = matcher.match(test['cve_product'], test['inventory'])
        
        print(f"  Matched: {result['matched']}")
        print(f"  Best Match: {result['best_match']}")
        print(f"  Score: {result['score']:.3f}")
        print(f"  Method: {result['method']}")
        
        if result['all_scores']:
            print(f"  All Scores:")
            for score in result['all_scores'][:3]:
                print(f"    - {score['product']}: {score['score']:.3f} ({score['method']})")
