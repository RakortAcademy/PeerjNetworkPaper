"""
Rule-Based Product Extractor
Fallback layer when BiLSTM-CRF model fails to extract product names.

High-confidence patterns for common vendors and products.
"""

import re


class RuleBasedExtractor:
    """
    Rule-based product name extraction from CVE descriptions.
    Uses vendor+product patterns and generic extraction rules.
    """
    
    def __init__(self):
        """Initialize with predefined patterns."""
        # Vendor + Product patterns (high confidence: 0.9)
        self.vendor_patterns = [
            # Microsoft products
            (r'\bMicrosoft\s+(Edge|Office|Windows|Word|Excel|PowerPoint|Outlook|Access|Teams|SharePoint|OneDrive|Publisher|Visio|Project|Exchange|SQL\s+Server|Internet\s+Explorer|Defender|Dynamics|Message\s+Queuing|MSMQ)\b', 0.9),
            
            # Adobe products
            (r'\bAdobe\s+(Acrobat|Reader|Photoshop|Illustrator|Premiere|After\s+Effects|InDesign|Lightroom|Flash|ColdFusion|Experience\s+Manager|Creative\s+Cloud)\b', 0.9),
            
            # Google products
            (r'\bGoogle\s+(Chrome|Android|Cloud|Drive|Workspace)\b', 0.9),
            
            # Mozilla products
            (r'\bMozilla\s+(Firefox|Thunderbird)\b', 0.9),
            
            # Apple products
            (r'\bApple\s+(Safari|macOS|iOS|iPadOS|watchOS|tvOS|iTunes|iCloud)\b', 0.9),
            
            # Apache products
            (r'\bApache\s+(Tomcat|HTTP\s+Server|Struts|Maven|Kafka|Hadoop|Spark|ActiveMQ|Cassandra|CouchDB)\b', 0.9),
            
            # Oracle products
            (r'\bOracle\s+(Database|Java|WebLogic|MySQL|VirtualBox|Solaris)\b', 0.9),
            
            # Other common vendors
            (r'\bCisco\s+(IOS|ASA|Webex|AnyConnect)\b', 0.9),
            (r'\bVMware\s+(vSphere|ESXi|Workstation|Fusion|vCenter)\b', 0.9),
            (r'\bIBM\s+(WebSphere|DB2|MQ|Notes|Domino)\b', 0.9),
            (r'\bSAP\s+(NetWeaver|HANA|Business\s+One)\b', 0.9),
            (r'\bZoom\s+(Client|Rooms|for\s+Windows)\b', 0.9),
        ]
        
        # Known standalone products (confidence: 0.8)
        self.product_patterns = [
            (r'\b(WordPress|Drupal|Joomla|Magento|PrestaShop)\b', 0.8),
            (r'\b(Node\.js|npm|Python|Ruby|PHP|Perl|Go)\b', 0.8),
            (r'\b(PostgreSQL|MongoDB|Redis|MariaDB|SQLite)\b', 0.8),
            (r'\b(Jenkins|GitLab|GitHub|Bitbucket)\b', 0.8),
            (r'\b(Docker|Kubernetes|Ansible|Terraform)\b', 0.8),
            (r'\b(Nginx|HAProxy|Varnish)\b', 0.8),
            (r'\b(Visual\s+Studio|Eclipse|IntelliJ|VS\s+Code|Atom)\b', 0.8),
            (r'\b(Wireshark|Nmap|Metasploit|Burp\s+Suite)\b', 0.8),
        ]
        
        # Generic patterns (medium confidence: 0.6-0.7)
        self.generic_patterns = [
            # "Product contains a vulnerability"
            (r'^(.+?)\s+contains\s+a\s+vulnerability', 0.65),
            
            # "Product allows attackers"
            (r'^(.+?)\s+allows\s+(?:remote|local)?\s*attackers', 0.65),
            
            # "vulnerability in Product"
            (r'vulnerability\s+in\s+(.+?)\s+(?:prior\s+to|before|through|version|allows|that)', 0.65),
            
            # "Product version X.Y.Z"
            (r'^(.+?)\s+version\s+\d+\.\d+', 0.65),
            
            # "Product X.Y.Z and earlier"
            (r'^(.+?)\s+\d+\.\d+[.\d]*\s+and\s+earlier', 0.65),
            
            # "Product prior to version"
            (r'^(.+?)\s+(?:prior\s+to|before|through)\s+version', 0.65),
            
            # "The Product component"
            (r'[Tt]he\s+(.+?)\s+(?:component|module|feature|service|driver|plugin)', 0.6),
            
            # Product at sentence start with version nearby
            (r'^([A-Z][A-Za-z0-9\s._-]+?)\s+\d+\.\d+', 0.6),
        ]
        
        # Words to remove from extracted products (noise)
        self.noise_patterns = [
            r'\s+for\s+(Windows|Linux|Mac|macOS|iOS|Android|Unix).*$',
            r'\s+on\s+(Windows|Linux|Mac|macOS|iOS|Android).*$',
            r'\s*\([^)]*\)\s*$',  # Trailing parentheses
            r'\s+in\s+.*$',
            r'\s+with\s+.*$',
            r'\s+that\s+.*$',
            r'\s+which\s+.*$',
        ]
        
        # Stop words at start
        self.stop_words_start = ['the', 'a', 'an', 'this', 'that']

    def extract_product(self, cve_description):
        """
        Extract product name from CVE description.
        
        Args:
            cve_description (str): CVE description text
        
        Returns:
            dict: {
                'product': str or None,
                'confidence': float (0-1),
                'method': str (pattern type used)
            }
        """
        if not cve_description:
            return {'product': None, 'confidence': 0.0, 'method': 'none'}
        
        # Try vendor+product patterns first (highest confidence)
        for pattern, confidence in self.vendor_patterns:
            match = re.search(pattern, cve_description, re.IGNORECASE)
            if match:
                product = match.group(0)
                product = self._clean_product(product)
                if product:
                    return {
                        'product': product,
                        'confidence': confidence,
                        'method': 'vendor_pattern'
                    }
        
        # Try known product patterns
        for pattern, confidence in self.product_patterns:
            match = re.search(pattern, cve_description, re.IGNORECASE)
            if match:
                product = match.group(1) if match.lastindex else match.group(0)
                product = self._clean_product(product)
                if product:
                    return {
                        'product': product,
                        'confidence': confidence,
                        'method': 'product_pattern'
                    }
        
        # Try generic patterns
        for pattern, confidence in self.generic_patterns:
            match = re.search(pattern, cve_description, re.IGNORECASE)
            if match:
                product = match.group(1)
                product = self._clean_product(product)
                if product and self._is_valid_product(product):
                    return {
                        'product': product,
                        'confidence': confidence,
                        'method': 'generic_pattern'
                    }
        
        # No match found
        return {'product': None, 'confidence': 0.0, 'method': 'none'}

    def _clean_product(self, product):
        """Clean extracted product name from noise."""
        if not product:
            return None
        
        # Strip whitespace
        product = product.strip()
        
        # Remove noise patterns
        for noise_pattern in self.noise_patterns:
            product = re.sub(noise_pattern, '', product, flags=re.IGNORECASE)
        
        # Remove leading stop words
        words = product.split()
        while words and words[0].lower() in self.stop_words_start:
            words = words[1:]
        product = ' '.join(words)
        
        # Remove trailing punctuation
        product = product.strip('.,;:!?')
        
        # Remove multiple spaces
        product = re.sub(r'\s+', ' ', product)
        
        # Final trim
        product = product.strip()
        
        # Validate minimum length
        if len(product) < 3:
            return None
        
        return product

    def _is_valid_product(self, product):
        """
        Validate if extracted string looks like a real product name.
        Filters out generic words that are too vague.
        """
        if not product or len(product) < 3:
            return False
        
        # Too short (single letter products are unlikely)
        if len(product) == 1:
            return False
        
        # Check for at least one letter (not just numbers/symbols)
        if not re.search(r'[a-zA-Z]', product):
            return False
        
        # Reject overly generic terms
        generic_terms = [
            'vulnerability', 'issue', 'flaw', 'bug', 'error', 'problem',
            'system', 'software', 'application', 'program', 'service',
            'component', 'module', 'feature', 'function', 'method',
            'remote', 'local', 'code', 'execution', 'privilege',
            'denial', 'disclosure', 'injection', 'overflow', 'bypass'
        ]
        
        if product.lower() in generic_terms:
            return False
        
        # Reject if it's just common words
        common_words = [
            'this', 'that', 'these', 'those', 'what', 'which', 'who',
            'when', 'where', 'why', 'how', 'all', 'some', 'any', 'none'
        ]
        
        if product.lower() in common_words:
            return False
        
        return True


# Convenience function
def extract_product_fallback(cve_description):
    """
    Convenience function to extract product using rule-based method.
    
    Usage:
        result = extract_product_fallback("Microsoft Edge contains a vulnerability...")
        # result = {'product': 'Microsoft Edge', 'confidence': 0.9, 'method': 'vendor_pattern'}
    """
    extractor = RuleBasedExtractor()
    return extractor.extract_product(cve_description)


if __name__ == '__main__':
    # Test cases
    test_cases = [
        "Microsoft Edge (Chromium-based) Webview2 Spoofing Vulnerability",
        "Microsoft Message Queuing (MSMQ) Remote Code Execution Vulnerability",
        "Visual Studio Remote Code Execution Vulnerability less than or equal to 17.11.5",
        "Windows Error Reporting Service Elevation of Privilege Vulnerability prior to version 10.0.19045.3324",
        "Adobe Acrobat Reader DC allows remote attackers to execute arbitrary code",
        "Google Chrome contains a vulnerability in the V8 engine",
        "Apache Tomcat 9.0.1 through 9.0.30 allows remote code execution",
        "WordPress plugin vulnerable to SQL injection",
        "Node.js before version 18.19.0 allows denial of service",
    ]
    
    extractor = RuleBasedExtractor()
    
    print("Rule-Based Product Extraction Test")
    print("=" * 80)
    
    for i, description in enumerate(test_cases, 1):
        result = extractor.extract_product(description)
        status = "✅" if result['product'] else "❌"
        
        print(f"\n{i}. {status} {description[:60]}...")
        print(f"   Product: \"{result['product']}\"")
        print(f"   Confidence: {result['confidence']:.2f}")
        print(f"   Method: {result['method']}")
