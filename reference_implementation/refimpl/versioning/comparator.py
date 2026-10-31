"""
Version Comparator
Compares versions with operators: <, <=, >=, >, ==
"""

from .parser import parse_version, Version


class VersionComparator:
    """
    Compare versions with different operators
    """
    
    @staticmethod
    def equal(v1_str: str, v2_str: str) -> bool:
        """Check if v1 == v2"""
        v1 = parse_version(v1_str)
        v2 = parse_version(v2_str)
        if v1 is None or v2 is None:
            return False
        return v1 == v2
    
    @staticmethod
    def less_than(v1_str: str, v2_str: str) -> bool:
        """Check if v1 < v2"""
        v1 = parse_version(v1_str)
        v2 = parse_version(v2_str)
        if v1 is None or v2 is None:
            return False
        return v1 < v2
    
    @staticmethod
    def less_than_or_equal(v1_str: str, v2_str: str) -> bool:
        """Check if v1 <= v2"""
        v1 = parse_version(v1_str)
        v2 = parse_version(v2_str)
        if v1 is None or v2 is None:
            return False
        return v1 <= v2
    
    @staticmethod
    def greater_than(v1_str: str, v2_str: str) -> bool:
        """Check if v1 > v2"""
        v1 = parse_version(v1_str)
        v2 = parse_version(v2_str)
        if v1 is None or v2 is None:
            return False
        return v1 > v2
    
    @staticmethod
    def greater_than_or_equal(v1_str: str, v2_str: str) -> bool:
        """Check if v1 >= v2"""
        v1 = parse_version(v1_str)
        v2 = parse_version(v2_str)
        if v1 is None or v2 is None:
            return False
        return v1 >= v2
    
    @staticmethod
    def compare(v1_str: str, operator: str, v2_str: str) -> bool:
        """
        Compare with operator
        
        Args:
            v1_str (str): First version
            operator (str): Operator (<, <=, >, >=, ==, !=)
            v2_str (str): Second version
        
        Returns:
            bool: Comparison result
        """
        operators = {
            '<': VersionComparator.less_than,
            '<=': VersionComparator.less_than_or_equal,
            '>': VersionComparator.greater_than,
            '>=': VersionComparator.greater_than_or_equal,
            '==': VersionComparator.equal,
            '!=': lambda a, b: not VersionComparator.equal(a, b)
        }
        
        if operator not in operators:
            raise ValueError(f"Invalid operator: {operator}")
        
        return operators[operator](v1_str, v2_str)


if __name__ == '__main__':
    # Test version comparator
    print("="*80)
    print("VERSION COMPARATOR TEST")
    print("="*80)
    
    test_cases = [
        ("1.2.3", "<", "1.2.4", True),
        ("1.2.3", "==", "1.2.3", True),
        ("1.2.3", ">", "1.2.2", True),
        ("2.0.0", ">", "1.9.9", True),
        ("1.5.2", "<", "1.7.0", True),
        ("9.0.1", "<", "9.0.5", True),
        ("460.32.03", "<", "465.0", True),
        ("1.18.0", ">=", "1.9.0", True),
    ]
    
    comp = VersionComparator()
    
    for v1, op, v2, expected in test_cases:
        result = comp.compare(v1, op, v2)
        status = "✅" if result == expected else "❌"
        print(f"{status} {v1:15s} {op:3s} {v2:15s} → {result} (expected: {expected})")
