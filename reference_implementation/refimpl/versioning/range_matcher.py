"""
Range Matcher: Check if version is in vulnerable range
Main threat detection logic
"""

from .parser import parse_version, are_adobe_versions_compatible, version_scheme_mismatch
from .comparator import VersionComparator


def _is_adobe_acrobat_product(app_name: str) -> bool:
    """True if CVE product is Adobe Acrobat/Reader (source_v2: version family rule)."""
    if not app_name:
        return False
    lower = app_name.lower()
    return "adobe" in lower and ("acrobat" in lower or "reader" in lower)


def platform_matching(cve_platform, customer_platform):
    """source_v2: CVE applies to customer platform? 'all' matches any."""
    cve = (cve_platform or "all").lower().strip()
    cust = (customer_platform or "all").lower().strip()
    if cve == "all" or cust == "all":
        return True
    return cve == cust


def check_upper_bound(customer_version, constraint_version, constraint_type, comp):
    """
    Boundary-aware upper bound check

    Args:
        customer_version (str): Customer's version
        constraint_version (str): CVE upper bound version
        constraint_type (str): 'lt' (exclusive <) or 'le' (inclusive <=)
        comp (VersionComparator): Comparator instance

    Returns:
        dict: {
            'satisfied': bool,
            'constraint_type': str,
            'description': str
        }
    """
    if constraint_type == 'lt':
        # "prior to X.Y.Z" - X.Y.Z is EXCLUDED
        satisfied = comp.less_than(customer_version, constraint_version)
        description = f"{customer_version} < {constraint_version} (exclusive)"
    elif constraint_type == 'le':
        # "X.Y.Z and earlier" - X.Y.Z is INCLUDED.
        # Derleme numaralı sürüm (5.2.8.3141) o sürümün İÇİNDEdir; saf sayısal
        # kıyas onu üstte görüp etkilenmiyor sayıyordu. Bkz. `is_build_of`.
        from .parser import is_build_of

        satisfied = (
            comp.less_than_or_equal(customer_version, constraint_version)
            or is_build_of(customer_version, constraint_version)
        )
        description = f"{customer_version} <= {constraint_version} (inclusive)"
    else:
        raise ValueError(f"Unknown constraint type: {constraint_type}")

    return {
        'satisfied': satisfied,
        'constraint_type': constraint_type,
        'description': description
    }


def check_lower_bound(customer_version, constraint_version, constraint_type, comp):
    """
    Boundary-aware lower bound check

    Args:
        customer_version (str): Customer's version
        constraint_version (str): CVE lower bound version
        constraint_type (str): 'ge' (inclusive >=) or 'gt' (exclusive >)
        comp (VersionComparator): Comparator instance

    Returns:
        dict: {
            'satisfied': bool,
            'constraint_type': str,
            'description': str
        }
    """
    if constraint_type == 'ge':
        # "X.Y.Z and later" - X.Y.Z is INCLUDED
        satisfied = comp.greater_than_or_equal(customer_version, constraint_version)
        description = f"{customer_version} >= {constraint_version} (inclusive)"
    elif constraint_type == 'gt':
        # "after X.Y.Z" - X.Y.Z is EXCLUDED
        satisfied = comp.greater_than(customer_version, constraint_version)
        description = f"{customer_version} > {constraint_version} (exclusive)"
    else:
        raise ValueError(f"Unknown constraint type: {constraint_type}")

    return {
        'satisfied': satisfied,
        'constraint_type': constraint_type,
        'description': description
    }


def check_version_in_range(customer_version, cve_json):
    """
    Check if customer version is vulnerable based on CVE version range
    
    Args:
        customer_version (str): Customer's product version
        cve_json (dict): CVE JSON with version constraints
            {
                'app_version': str (exact version),
                'less_than': str (< this version),
                'less_than_or_equal': str (<= this version),
                'greater_equal': str (>= this version)
            }
    
    Returns:
        dict: {
            'vulnerable': bool,
            'reason': str,
            'checks': list of check results
        }
    """
    checks = []
    vulnerable = False
    reason = "Not vulnerable"

    # Parse customer version
    customer_ver = parse_version(customer_version)
    if customer_ver is None:
        return {
            'vulnerable': False,
            'reason': 'Invalid customer version format',
            'checks': []
        }

    # source_v2 rule: Adobe Acrobat/Reader – version family must match (year-based vs number-based)
    app_name = cve_json.get('app_name') or cve_json.get('product') or ''
    if _is_adobe_acrobat_product(app_name):
        constraint_ver = (
            cve_json.get('less_than_or_equal')
            or cve_json.get('less_than')
            or cve_json.get('app_version')
        )
        if constraint_ver and not are_adobe_versions_compatible(customer_version, constraint_ver):
            return {
                'vulnerable': False,
                'reason': 'Adobe version family mismatch (year vs number)',
                'checks': [{'type': 'adobe_family', 'result': False, 'description': 'Version families not compatible'}]
            }

    comp = VersionComparator()
    
    # Check 1: Exact version match
    exact_version = cve_json.get('app_version')
    if exact_version:
        is_match = comp.equal(customer_version, exact_version)
        checks.append({
            'type': 'exact',
            'constraint': f"== {exact_version}",
            'result': is_match
        })
        if is_match:
            vulnerable = True
            reason = f"Exact version match: {exact_version}"
    
    # Check 2: Less than constraint (exclusive boundary)
    less_than = cve_json.get('less_than')
    if less_than:
        upper_check = check_upper_bound(customer_version, less_than, 'lt', comp)
        checks.append({
            'type': 'less_than',
            'constraint': f"< {less_than}",
            'result': upper_check['satisfied'],
            'boundary': 'exclusive',
            'description': upper_check['description']
        })
        if upper_check['satisfied']:
            vulnerable = True
            reason = f"Version {customer_version} < {less_than} (exclusive)"

    # Check 2b: Less than or equal constraint (inclusive boundary)
    less_than_or_equal = cve_json.get('less_than_or_equal')
    if less_than_or_equal:
        upper_check = check_upper_bound(customer_version, less_than_or_equal, 'le', comp)
        checks.append({
            'type': 'less_than_or_equal',
            'constraint': f"<= {less_than_or_equal}",
            'result': upper_check['satisfied'],
            'boundary': 'inclusive',
            'description': upper_check['description']
        })
        if upper_check['satisfied']:
            vulnerable = True
            reason = f"Version {customer_version} <= {less_than_or_equal} (inclusive)"
    
    # Check 3: Greater than or equal constraint (inclusive boundary)
    greater_equal = cve_json.get('greater_equal')
    if greater_equal:
        lower_check = check_lower_bound(customer_version, greater_equal, 'ge', comp)
        checks.append({
            'type': 'greater_equal',
            'constraint': f">= {greater_equal}",
            'result': lower_check['satisfied'],
            'boundary': 'inclusive',
            'description': lower_check['description']
        })
        if lower_check['satisfied']:
            # When only lower bound exists (no upper), avoid false positive: e.g. CVE "Java 7 (1.7.0_04 to 1.7.0_10)" vs customer "Java 11 (11.0.19)" - different major line
            if not (less_than or less_than_or_equal):
                constraint_ver = parse_version(greater_equal)
                if constraint_ver and customer_ver.major > constraint_ver.major and constraint_ver.major <= 2 and customer_ver.major >= 5:
                    vulnerable = False
                    reason = "Customer major version exceeds CVE constraint major (different product line)"
                else:
                    vulnerable = True
                    reason = f"Version {customer_version} >= {greater_equal} (inclusive)"
            else:
                vulnerable = True
                reason = f"Version {customer_version} >= {greater_equal} (inclusive)"
    
    # Combined logic for range
    # If range constraints exist, evaluate combined logic with explicit boundary handling
    if (less_than or less_than_or_equal) and greater_equal:
        # Aralık sınırları farklı version şemalarındaysa karşılaştırma (1.0.0 vs 111.0.x)
        upper_str = less_than_or_equal or less_than
        lower_ver = parse_version(greater_equal)
        upper_ver = parse_version(upper_str) if upper_str else None
        if lower_ver and upper_ver and version_scheme_mismatch(lower_ver, upper_ver):
            return {
                'vulnerable': False,
                'reason': 'Version scheme mismatch in CVE range (incomparable bounds)',
                'checks': [{
                    'type': 'range_scheme_mismatch',
                    'constraint': f"{greater_equal} .. {upper_str}",
                    'result': False,
                    'description': 'Lower and upper bounds use different version schemes'
                }]
            }

        # Determine upper bound
        upper_check = None
        upper_label = None

        if less_than_or_equal:
            upper_check = check_upper_bound(customer_version, less_than_or_equal, 'le', comp)
            upper_label = f"<= {less_than_or_equal}"
        elif less_than:
            upper_check = check_upper_bound(customer_version, less_than, 'lt', comp)
            upper_label = f"< {less_than}"

        # Determine lower bound
        lower_check = check_lower_bound(customer_version, greater_equal, 'ge', comp)

        # Version is vulnerable if it's in the range
        in_range = lower_check['satisfied'] and upper_check['satisfied']

        if in_range:
            vulnerable = True
            reason = f"Version in range: {greater_equal} <= {customer_version} {upper_label}"
        else:
            vulnerable = False
            reason = f"Version outside range: {greater_equal} <= v {upper_label}"

        # Add range check details
        checks.append({
            'type': 'range',
            'constraint': f"{greater_equal} <= v {upper_label}",
            'result': in_range,
            'lower_satisfied': lower_check['satisfied'],
            'upper_satisfied': upper_check['satisfied'],
            'description': f"{lower_check['description']} AND {upper_check['description']}"
        })
    
    return {
        'vulnerable': vulnerable,
        'reason': reason,
        'checks': checks
    }


class ThreatDetector:
    """
    Detect threats from matched CVE-Inventory pairs
    """
    
    def __init__(self):
        pass
    
    def check_single(self, matched_item):
        """
        Check a single matched CVE-Inventory pair
        
        Args:
            matched_item (dict): Output from Model Beta matching
                {
                    'cve_id': str,
                    'matched': bool,
                    'inventory_match': {'product': str, 'version': str, ...},
                    'cve_json': {'app_version': ..., 'less_than': ..., ...}
                }
        
        Returns:
            dict: Threat assessment result
        """
        if not matched_item.get('matched'):
            return {
                'cve_id': matched_item.get('cve_id'),
                'threat': False,
                'reason': 'CVE not matched with inventory'
            }
        
        inventory = matched_item.get('inventory_match', {})
        cve_json = matched_item.get('cve_json', {})
        
        customer_version = inventory.get('version')
        if not customer_version:
            return {
                'cve_id': matched_item.get('cve_id'),
                'threat': False,
                'reason': 'No version in inventory'
            }
        
        # Platform matching (source_v2)
        cve_platform = cve_json.get('platform') or 'all'
        customer_platform = inventory.get('platform', 'all')
        if not platform_matching(cve_platform, customer_platform):
            return {
                'cve_id': matched_item.get('cve_id'),
                'threat': False,
                'reason': f'Platform mismatch (CVE: {cve_platform}, customer: {customer_platform})',
                'customer_product': inventory.get('product'),
                'customer_version': customer_version,
                'customer_hostname': inventory.get('hostname'),
                'cve_constraints': {
                    'exact': cve_json.get('app_version'),
                    'less_than': cve_json.get('less_than'),
                    'less_than_or_equal': cve_json.get('less_than_or_equal'),
                    'greater_equal': cve_json.get('greater_equal')
                },
                'checks': []
            }
        
        # Check version range
        result = check_version_in_range(customer_version, cve_json)
        
        return {
            'cve_id': matched_item.get('cve_id'),
            'threat': result['vulnerable'],
            'reason': result['reason'],
            'customer_product': inventory.get('product'),
            'customer_version': customer_version,
            'customer_hostname': inventory.get('hostname'),
            'cve_constraints': {
                'exact': cve_json.get('app_version'),
                'less_than': cve_json.get('less_than'),
                'less_than_or_equal': cve_json.get('less_than_or_equal'),
                'greater_equal': cve_json.get('greater_equal')
            },
            'checks': result['checks']
        }
    
    def check_batch(self, matched_items):
        """
        Check a batch of matched items
        
        Args:
            matched_items (list): List of matched CVE-Inventory pairs
        
        Returns:
            dict: {
                'total': int,
                'threats': int,
                'safe': int,
                'threat_rate': float,
                'results': list
            }
        """
        results = []
        threat_count = 0
        
        for item in matched_items:
            threat_result = self.check_single(item)
            results.append(threat_result)
            
            if threat_result['threat']:
                threat_count += 1
        
        total = len(matched_items)
        threat_rate = (threat_count / total * 100) if total > 0 else 0.0
        
        return {
            'total': total,
            'threats': threat_count,
            'safe': total - threat_count,
            'threat_rate': threat_rate,
            'results': results
        }
    
    def get_threats_only(self, batch_result):
        """Filter to get only threat CVEs"""
        return [r for r in batch_result['results'] if r['threat']]


if __name__ == '__main__':
    # Test threat detection
    print("="*80)
    print("THREAT DETECTION TEST")
    print("="*80)
    
    # Mock matched items (from Model Beta)
    mock_matched = [
        {
            'cve_id': 'CVE-2021-1234',
            'matched': True,
            'inventory_match': {
                'product': 'Apache Tomcat',
                'version': '9.0.1',
                'hostname': 'web-server-01'
            },
            'cve_json': {
                'app_name': 'Apache Tomcat',
                'app_version': None,
                'less_than': '9.0.5',
                'greater_equal': None
            }
        },
        {
            'cve_id': 'CVE-2021-5678',
            'matched': True,
            'inventory_match': {
                'product': 'NVIDIA Display Driver',
                'version': '460.32.03',
                'hostname': 'gpu-server-01'
            },
            'cve_json': {
                'app_name': 'NVIDIA GPU Display Driver',
                'app_version': None,
                'less_than': '465.0',
                'greater_equal': None
            }
        },
        {
            'cve_id': 'CVE-2021-9999',
            'matched': True,
            'inventory_match': {
                'product': 'PostgreSQL',
                'version': '13.5',
                'hostname': 'db-server-01'
            },
            'cve_json': {
                'app_name': 'PostgreSQL',
                'app_version': None,
                'less_than': '13.2',
                'greater_equal': None
            }
        }
    ]
    
    # Test threat detection
    detector = ThreatDetector()
    results = detector.check_batch(mock_matched)
    
    print(f"\n📊 RESULTS:")
    print(f"  Total Matched CVEs: {results['total']}")
    print(f"  Threats: {results['threats']}")
    print(f"  Safe: {results['safe']}")
    print(f"  Threat Rate: {results['threat_rate']:.1f}%")
    
    print(f"\n🚨 THREAT CVEs:")
    threats = detector.get_threats_only(results)
    for threat in threats:
        print(f"\n  CVE: {threat['cve_id']}")
        print(f"    Product: {threat['customer_product']}")
        print(f"    Version: {threat['customer_version']}")
        print(f"    Hostname: {threat['customer_hostname']}")
        print(f"    Reason: {threat['reason']}")
        print(f"    Constraints: {threat['cve_constraints']}")
    
    print(f"\n✅ SAFE:")
    for result in results['results']:
        if not result['threat']:
            print(f"  {result['cve_id']}: {result['reason']}")
