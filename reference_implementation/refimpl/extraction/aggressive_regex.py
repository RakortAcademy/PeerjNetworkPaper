"""
Aggressive Regex Extractor
Last-resort product extraction when all other methods fail.

Uses aggressive pattern matching with low confidence scores.
Better to extract something imperfect than nothing at all.
"""

import re


class AggressiveRegexExtractor:
    """
    Aggressive product name extraction using broad regex patterns.
    This is the last resort when BiLSTM-CRF and rule-based methods fail.
    
    Trade-off: Higher recall, lower precision.
    Confidence: 0.3-0.5 (intentionally low to flag uncertainty)
    """
    
    def __init__(self):
        """Initialize with aggressive patterns."""
        # Known vendor names (for boosting confidence)
        self.known_vendors = [
            'microsoft', 'adobe', 'google', 'apple', 'mozilla', 'oracle',
            'cisco', 'vmware', 'ibm', 'sap', 'amazon', 'facebook', 'meta',
            'twitter', 'linkedin', 'salesforce', 'zoom', 'slack', 'atlassian',
            'apache', 'redis', 'postgresql', 'mongodb', 'mysql', 'mariadb',
            'nginx', 'docker', 'kubernetes', 'jenkins', 'gitlab', 'github'
        ]
        
        # Software-related keywords (for validation)
        self.software_keywords = [
            'server', 'client', 'driver', 'service', 'plugin', 'extension',
            'module', 'component', 'library', 'framework', 'engine', 'runtime',
            'api', 'sdk', 'ide', 'editor', 'browser', 'database', 'application'
        ]

    def extract_product(self, cve_description):
        """
        Aggressively extract product name from CVE description.
        
        Args:
            cve_description (str): CVE description text
        
        Returns:
            dict: {
                'product': str or None,
                'confidence': float (0.3-0.5),
                'method': str
            }
        """
        if not cve_description:
            return {'product': None, 'confidence': 0.0, 'method': 'none'}
        
        # Strategy 1: Capitalized terms before "vulnerability" (confidence: 0.45)
        product = self._extract_before_vulnerability(cve_description)
        if product:
            confidence = 0.45
            # Boost if known vendor is present
            if any(vendor in product.lower() for vendor in self.known_vendors):
                confidence = 0.5
            return {
                'product': product,
                'confidence': confidence,
                'method': 'aggressive_before_vulnerability'
            }
        
        # Strategy 2: First capitalized phrase with software keyword (confidence: 0.4)
        product = self._extract_capitalized_software(cve_description)
        if product:
            confidence = 0.4
            if any(vendor in product.lower() for vendor in self.known_vendors):
                confidence = 0.45
            return {
                'product': product,
                'confidence': confidence,
                'method': 'aggressive_capitalized_software'
            }
        
        # Strategy 3: Any known vendor name found (confidence: 0.35)
        product = self._extract_vendor_name(cve_description)
        if product:
            return {
                'product': product,
                'confidence': 0.35,
                'method': 'aggressive_vendor_only'
            }
        
        # Strategy 4: First 2-3 capitalized words (confidence: 0.3)
        product = self._extract_first_capitalized(cve_description)
        if product:
            return {
                'product': product,
                'confidence': 0.3,
                'method': 'aggressive_first_caps'
            }
        
        # Give up
        return {'product': None, 'confidence': 0.0, 'method': 'none'}

    def _extract_before_vulnerability(self, description):
        """Extract capitalized words/phrases before 'vulnerability'."""
        # Find text before first occurrence of vulnerability/flaw/issue
        match = re.search(r'^(.+?)\s+(?:vulnerability|vulnerabilities|flaw|issue|bug)', description, re.IGNORECASE)
        if not match:
            return None
        
        text_before = match.group(1).strip()
        
        # Look for capitalized sequence
        # Match: "Microsoft Edge WebView2" or "Windows Error Reporting Service"
        cap_match = re.search(r'\b([A-Z][A-Za-z0-9]*(?:\s+[A-Z][A-Za-z0-9]*)*(?:\s+[A-Z][A-Za-z0-9]+)?)\s*$', text_before)
        if cap_match:
            product = cap_match.group(1).strip()
            product = self._clean_aggressive(product)
            if product and len(product) > 2:
                return product
        
        return None

    def _extract_capitalized_software(self, description):
        """Extract capitalized phrase that contains software-related keywords."""
        # Find capitalized sequences with 2-4 words
        matches = re.findall(r'\b([A-Z][A-Za-z0-9]+(?:\s+[A-Z][A-Za-z0-9]+){1,3})\b', description)
        
        for match in matches:
            match_lower = match.lower()
            # Check if it contains software keyword
            if any(kw in match_lower for kw in self.software_keywords):
                product = self._clean_aggressive(match)
                if product and len(product) > 2:
                    return product
        
        return None

    def _extract_vendor_name(self, description):
        """Extract first known vendor name found."""
        for vendor in self.known_vendors:
            # Look for vendor name (case-insensitive)
            pattern = r'\b' + re.escape(vendor) + r'\b'
            match = re.search(pattern, description, re.IGNORECASE)
            if match:
                # Try to get vendor + next word(s)
                extended = re.search(
                    pattern + r'\s+([A-Z][A-Za-z0-9]+(?:\s+[A-Z][A-Za-z0-9]+)?)',
                    description,
                    re.IGNORECASE
                )
                if extended:
                    product = match.group(0) + ' ' + extended.group(1)
                else:
                    product = match.group(0)
                
                product = self._clean_aggressive(product)
                if product:
                    return product.title()  # Capitalize properly
        
        return None

    def _extract_first_capitalized(self, description):
        """Extract first 2-3 capitalized words from description."""
        # Match first capitalized sequence
        match = re.search(r'^\s*([A-Z][A-Za-z0-9]+(?:\s+[A-Z][A-Za-z0-9]+){0,2})', description)
        if match:
            product = match.group(1).strip()
            product = self._clean_aggressive(product)
            if product and len(product) > 2:
                return product
        
        return None

    def _clean_aggressive(self, product):
        """Clean extracted product name (aggressive mode - minimal cleaning)."""
        if not product:
            return None
        
        # Remove trailing generic words
        product = re.sub(r'\s+(in|on|at|by|with|from|for|the|a|an)$', '', product, flags=re.IGNORECASE)
        
        # Remove trailing punctuation
        product = product.strip('.,;:!?')
        
        # Remove multiple spaces
        product = re.sub(r'\s+', ' ', product)
        
        product = product.strip()
        
        # Reject if too short or too generic
        if len(product) < 3:
            return None
        
        # Reject pure numbers
        if product.replace(' ', '').isdigit():
            return None
        
        # Reject common generic words
        generic = ['this', 'that', 'vulnerability', 'issue', 'flaw', 'bug', 'error']
        if product.lower() in generic:
            return None
        
        return product


# Convenience function
def extract_aggressive(cve_description):
    """
    Convenience function for aggressive extraction.
    
    Usage:
        result = extract_aggressive("Some Product allows remote code execution...")
        # result = {'product': 'Some Product', 'confidence': 0.45, 'method': 'aggressive_before_vulnerability'}
    """
    extractor = AggressiveRegexExtractor()
    return extractor.extract_product(cve_description)


if __name__ == '__main__':
    # Test aggressive extraction on difficult cases
    test_cases = [
        "Some Obscure Product contains a vulnerability in the authentication module",
        "XYZ Server allows remote attackers to execute arbitrary code",
        "The service daemon in ACME Software crashes when processing malformed input",
        "Unspecified vulnerability in FooBar Framework prior to version 2.0",
        "Buffer overflow in the legacy component of Old System",
        "Authentication bypass in Custom Application 3.2.1",
    ]
    
    extractor = AggressiveRegexExtractor()
    
    print("Aggressive Regex Extraction Test (Last Resort)")
    print("=" * 80)
    
    for i, description in enumerate(test_cases, 1):
        result = extractor.extract_product(description)
        status = "✅" if result['product'] else "❌"
        
        print(f"\n{i}. {status} {description[:60]}...")
        print(f"   Product: \"{result['product']}\"")
        print(f"   Confidence: {result['confidence']:.2f} (LOW - aggressive extraction)")
        print(f"   Method: {result['method']}")
