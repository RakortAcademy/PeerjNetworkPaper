from functools import lru_cache
"""
Vendor Alias Mapping
Maps vendor names to their common aliases for better matching
"""

# Vendor alias mappings
# Format: canonical_name -> [list of aliases]
VENDOR_ALIASES = {
    # NVIDIA variants
    'nvidia': ['nvidia corp', 'nvidia corporation', 'nv', 'nvda'],

    # Microsoft variants
    'microsoft': ['ms', 'msft', 'microsoft corp', 'microsoft corporation'],

    # Apache variants
    'apache': ['apache software foundation', 'asf', 'apache foundation'],

    # Google variants
    'google': ['google llc', 'google inc', 'alphabet'],

    # Oracle variants
    'oracle': ['oracle corp', 'oracle corporation', 'sun microsystems', 'sun micro'],

    # Adobe variants
    'adobe': ['adobe systems', 'adobe inc', 'adobe systems inc'],

    # Intel variants
    'intel': ['intel corp', 'intel corporation'],

    # AMD variants
    'amd': ['advanced micro devices', 'amd inc'],

    # IBM variants
    'ibm': ['international business machines', 'ibm corp', 'red hat'],

    # Cisco variants
    'cisco': ['cisco systems', 'cisco systems inc'],

    # VMware variants
    'vmware': ['vmware inc', 'vm ware'],

    # Samsung variants
    'samsung': ['samsung electronics', 'samsung elec'],

    # Dell variants
    'dell': ['dell inc', 'dell technologies', 'dell emc'],

    # HP variants
    'hp': ['hewlett packard', 'hewlett-packard', 'hpe', 'hp inc'],

    # Qualcomm variants
    'qualcomm': ['qualcomm inc', 'qualcomm technologies'],
}

# Reverse mapping: alias -> canonical
ALIAS_TO_CANONICAL = {}
for canonical, aliases in VENDOR_ALIASES.items():
    for alias in aliases:
        ALIAS_TO_CANONICAL[alias] = canonical
    # Also map canonical to itself
    ALIAS_TO_CANONICAL[canonical] = canonical


#: Bir taramada çok kez çağrılıyor; bu yüzden sonuç önbelleklenir.
@lru_cache(maxsize=50_000)
def normalize_vendor(product_name):
    """
    Normalize vendor name in product string

    Examples:
        "NVIDIA Corp Display Driver" -> "NVIDIA Display Driver"
        "MS Office" -> "Microsoft Office"
        "Apache Software Foundation Tomcat" -> "Apache Tomcat"

    Args:
        product_name (str): Product name possibly containing vendor

    Returns:
        str: Normalized product name
    """
    if not product_name:
        return product_name

    # Lowercase for matching
    lower_name = product_name.lower()

    # Check each alias
    for alias, canonical in ALIAS_TO_CANONICAL.items():
        # Create pattern to match vendor prefix
        # e.g., "nvidia corp" at start of string
        import re

        # Try to replace alias with canonical at start
        pattern = r'\b' + re.escape(alias) + r'\b'

        if re.search(pattern, lower_name):
            # Replace first occurrence with canonical form
            # Preserve original casing style
            if product_name[0].isupper():
                canonical_cased = canonical.title()
            else:
                canonical_cased = canonical

            # Replace the alias with canonical
            normalized = re.sub(pattern, canonical_cased, product_name, count=1, flags=re.IGNORECASE)
            return normalized

    return product_name


def get_vendor_variants(product_name):
    """
    Generate vendor variants for a product name

    If product contains a known vendor, returns list with all alias variations.
    Useful for expanding search when matching fails.

    Args:
        product_name (str): Product name

    Returns:
        list: List of product name variants with different vendor forms

    Example:
        "NVIDIA Display Driver" -> [
            "NVIDIA Display Driver",
            "NVIDIA Corp Display Driver",
            "NVIDIA Corporation Display Driver",
            ...
        ]
    """
    if not product_name:
        return [product_name]

    variants = [product_name]
    lower_name = product_name.lower()

    # Find which vendor (if any) is in the product name
    detected_vendor = None
    for canonical in VENDOR_ALIASES.keys():
        if canonical in lower_name:
            detected_vendor = canonical
            break

    if not detected_vendor:
        return variants

    # Generate variants with each alias
    import re
    for alias in VENDOR_ALIASES[detected_vendor]:
        # Replace vendor with alias
        pattern = r'\b' + re.escape(detected_vendor) + r'\b'

        # Preserve casing
        if product_name[0].isupper():
            alias_cased = alias.title()
        else:
            alias_cased = alias

        variant = re.sub(pattern, alias_cased, product_name, flags=re.IGNORECASE)
        if variant not in variants:
            variants.append(variant)

    return variants


def should_apply_vendor_normalization(cve_product, inventory_product):
    """
    Determine if vendor normalization would help matching

    Args:
        cve_product (str): CVE product name
        inventory_product (str): Inventory product name

    Returns:
        bool: True if normalization might improve matching
    """
    if not cve_product or not inventory_product:
        return False

    cve_lower = cve_product.lower()
    inv_lower = inventory_product.lower()

    # Check if both contain potential vendor names
    for canonical, aliases in VENDOR_ALIASES.items():
        # Check if canonical or any alias is in either string
        all_forms = [canonical] + aliases

        cve_has_vendor = any(form in cve_lower for form in all_forms)
        inv_has_vendor = any(form in inv_lower for form in all_forms)

        # If one has vendor and other doesn't, normalization could help
        if cve_has_vendor != inv_has_vendor:
            return True

        # If both have vendor but different forms, normalization could help
        if cve_has_vendor and inv_has_vendor:
            # Check if they use different forms
            cve_form = None
            inv_form = None

            for form in all_forms:
                if form in cve_lower:
                    cve_form = form
                if form in inv_lower:
                    inv_form = form

            if cve_form != inv_form:
                return True

    return False


if __name__ == '__main__':
    # Test vendor normalization
    print("="*80)
    print("VENDOR ALIAS NORMALIZATION TEST")
    print("="*80)

    test_cases = [
        "NVIDIA Corp Display Driver",
        "MS Office",
        "Apache Software Foundation Tomcat",
        "Intel Corporation Graphics Driver",
        "Adobe Systems Acrobat",
        "Regular Product Name",  # No vendor
    ]

    print("\n1. Vendor Normalization:")
    for test in test_cases:
        normalized = normalize_vendor(test)
        print(f"  {test:45s} -> {normalized}")

    print("\n2. Vendor Variants:")
    product = "NVIDIA Display Driver"
    variants = get_vendor_variants(product)
    print(f"  Product: {product}")
    for i, variant in enumerate(variants[:5], 1):  # Show first 5
        print(f"    {i}. {variant}")

    print("\n3. Should Normalize Check:")
    test_pairs = [
        ("NVIDIA Display Driver", "NVIDIA Corp Display Driver"),
        ("MS Office", "Microsoft Office"),
        ("Apache Tomcat", "Tomcat"),
        ("Random Product", "Another Product"),
    ]

    for cve_prod, inv_prod in test_pairs:
        should_norm = should_apply_vendor_normalization(cve_prod, inv_prod)
        print(f"  '{cve_prod}' vs '{inv_prod}': {should_norm}")
