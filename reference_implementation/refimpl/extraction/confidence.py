"""
Binary Case Confidence Scoring
Calculates confidence scores for extracted CVE information
"""

import re


def calculate_confidence(json_output, cve_description):
    """
    Calculate confidence score for extraction quality

    Combines multiple heuristics to determine how confident we are
    in the extraction results. Binary cases should score higher.

    Args:
        json_output (dict): Extracted JSON from Model Alpha
        cve_description (str): Original CVE description text

    Returns:
        float: Confidence score [0.0, 1.0]
            0.9-1.0: High confidence (auto-approve candidate)
            0.7-0.9: Medium confidence (needs validation)
            0.0-0.7: Low confidence (manual review required)
    """
    score = 0.5  # Baseline

    # 1. Product Name Quality (max +0.25)
    app_name = json_output.get('app_name', '')

    if app_name:
        # Length check
        if len(app_name) > 3:
            score += 0.10

        # Multi-word products are more specific
        word_count = len(app_name.split())
        if word_count >= 2:
            score += 0.10
        elif word_count >= 3:
            score += 0.05  # Extra bonus for very specific names

        # Product name should NOT contain version numbers (bad extraction)
        if any(char.isdigit() for char in app_name):
            # Check if it's a legitimate part of the name (e.g., "Windows 10", "Office 365")
            if not re.search(r'\b(Windows|Office|MS|IE)\s+\d+', app_name, re.IGNORECASE):
                score -= 0.20  # Penalty for version in product name

        # Generic product names are less reliable
        generic_terms = ['driver', 'component', 'software', 'application', 'system']
        if any(term in app_name.lower() for term in generic_terms):
            if word_count < 3:  # "Display Driver" vs "NVIDIA Display Driver"
                score -= 0.15
    else:
        # No product name is a critical failure
        score -= 0.40

    # 2. Version Field Quality (max +0.30)
    version_fields = [
        json_output.get('app_version'),
        json_output.get('less_than'),
        json_output.get('less_than_or_equal'),
        json_output.get('greater_equal')
    ]

    valid_versions = [v for v in version_fields if v]

    if len(valid_versions) == 1:
        # Binary case: exactly one version constraint
        score += 0.20

        # Validate version format
        version_str = valid_versions[0]
        if re.match(r'^\d+\.\d+', version_str):
            score += 0.10  # Valid X.Y or X.Y.Z format
        else:
            score -= 0.05  # Unusual format

    elif len(valid_versions) == 0:
        # No version info (might be acceptable for some CVEs)
        score -= 0.20

    elif len(valid_versions) == 2:
        # Range (e.g., ">= 1.0 and < 2.0") - non-binary
        score -= 0.10

    else:
        # 3+ version fields - very complex, likely extraction error
        score -= 0.30

    # 3. Product Name Presence in CVE Description (max +0.15)
    if app_name and cve_description:
        # Normalize for comparison
        app_lower = app_name.lower()
        desc_lower = cve_description.lower()

        # Exact match
        if app_lower in desc_lower:
            score += 0.15
        # Partial match (at least 70% of words)
        else:
            app_words = set(app_lower.split())
            matches = sum(1 for word in app_words if word in desc_lower)
            match_ratio = matches / len(app_words) if app_words else 0

            if match_ratio >= 0.7:
                score += 0.10
            elif match_ratio >= 0.5:
                score += 0.05
            else:
                # Product name not found in description (suspicious)
                score -= 0.10

    # 4. Version Validation (if present)
    if valid_versions:
        for version_str in valid_versions:
            # Check for malformed versions
            if len(version_str) > 20:
                score -= 0.10  # Too long

            # Check for trailing garbage
            if re.search(r'[^\d\w.-]', version_str):
                score -= 0.05  # Contains special chars

    # 5. Binary Case Bonus
    # Check if this is truly a binary case
    has_product = json_output.get('app_name') is not None
    version_count = len(valid_versions)

    if has_product and version_count <= 1:
        score += 0.10  # Binary case bonus

    # Cap at [0.0, 1.0]
    return max(0.0, min(1.0, score))


def calculate_hybrid_confidence(model_score, json_output, cve_description):
    """
    Hybrid confidence: Combine model CRF score + heuristic score

    Args:
        model_score (float): Raw CRF path score from BiLSTM-CRF (typically in range [-20, 0])
        json_output (dict): Extracted JSON
        cve_description (str): Original CVE text

    Returns:
        float: Combined confidence score [0.0, 1.0]
    """
    # Normalize model score to [0, 1]
    # CRF scores are typically negative, higher (closer to 0) is better
    # Use sigmoid-like transformation
    import math

    if model_score is not None:
        # Normalize: score in [-20, 0] → [0, 1]
        # Using: 1 / (1 + exp(-score/k)) where k controls steepness
        normalized_model_score = 1 / (1 + math.exp(-model_score / 10))
    else:
        # No model score available, use neutral value
        normalized_model_score = 0.5

    # Calculate heuristic score
    heuristic_score = calculate_confidence(json_output, cve_description)

    # Weighted combination: 70% model, 30% heuristic
    # Model has more weight because it's trained on data
    final_confidence = 0.7 * normalized_model_score + 0.3 * heuristic_score

    return final_confidence


def get_confidence_category(confidence):
    """
    Categorize confidence score

    Args:
        confidence (float): Confidence score [0.0, 1.0]

    Returns:
        str: Category ('high', 'medium', 'low')
    """
    if confidence >= 0.85:
        return 'high'
    elif confidence >= 0.70:
        return 'medium'
    else:
        return 'low'


def should_auto_approve(confidence, threat_detected):
    """
    Determine if extraction can be auto-approved

    Args:
        confidence (float): Confidence score
        threat_detected (bool): Whether a threat was detected

    Returns:
        bool: True if can be auto-approved
    """
    # Only auto-approve if:
    # 1. High confidence (>= 0.90)
    # 2. Threat is detected (we're conservative)
    return confidence >= 0.90 and threat_detected


def should_manual_review(confidence):
    """
    Determine if extraction needs manual review

    Args:
        confidence (float): Confidence score

    Returns:
        bool: True if manual review needed
    """
    # Manual review if confidence is low
    return confidence < 0.70


if __name__ == '__main__':
    # Test confidence scoring
    test_cases = [
        {
            'name': 'High Confidence (Good Extraction)',
            'json': {
                'app_name': 'NVIDIA Display Driver',
                'app_version': None,
                'less_than': '460.32.03',
                'less_than_or_equal': None,
                'greater_equal': None
            },
            'description': 'NVIDIA Display Driver for Linux prior to 460.32.03 has vulnerability'
        },
        {
            'name': 'Medium Confidence (Generic Product)',
            'json': {
                'app_name': 'Display Driver',
                'app_version': None,
                'less_than': '460.32.03',
                'less_than_or_equal': None,
                'greater_equal': None
            },
            'description': 'NVIDIA Display Driver for Linux prior to 460.32.03 has vulnerability'
        },
        {
            'name': 'Low Confidence (Version in Product)',
            'json': {
                'app_name': 'Driver 460',
                'app_version': '460.32.03',
                'less_than': None,
                'less_than_or_equal': None,
                'greater_equal': None
            },
            'description': 'NVIDIA Display Driver for Linux prior to 460.32.03'
        },
        {
            'name': 'Low Confidence (No Product)',
            'json': {
                'app_name': None,
                'app_version': None,
                'less_than': '1.0.0',
                'less_than_or_equal': None,
                'greater_equal': None
            },
            'description': 'Some CVE description'
        },
        {
            'name': 'Medium Confidence (Range - Non-Binary)',
            'json': {
                'app_name': 'Apache Tomcat',
                'app_version': None,
                'less_than': '9.0.5',
                'less_than_or_equal': None,
                'greater_equal': '9.0.0'
            },
            'description': 'Apache Tomcat 9.0.0 through 9.0.5 has vulnerability'
        }
    ]

    print("="*80)
    print("CONFIDENCE SCORING TEST")
    print("="*80)

    for test in test_cases:
        print(f"\n{'='*80}")
        print(f"Test: {test['name']}")
        print(f"{'='*80}")
        print(f"Product: {test['json']['app_name']}")
        print(f"Versions: {[v for v in [test['json']['app_version'], test['json']['less_than'], test['json']['less_than_or_equal'], test['json']['greater_equal']] if v]}")

        confidence = calculate_confidence(test['json'], test['description'])
        category = get_confidence_category(confidence)

        print(f"\nConfidence: {confidence:.3f} ({category})")
        print(f"Auto-approve: {should_auto_approve(confidence, True)}")
        print(f"Manual review: {should_manual_review(confidence)}")

    # Test hybrid scoring
    print(f"\n{'='*80}")
    print("HYBRID CONFIDENCE TEST (with model scores)")
    print("="*80)

    # Simulate different model CRF scores
    model_scores = [-15.0, -8.0, -3.0]  # Low, medium, high

    for model_score in model_scores:
        print(f"\nModel CRF Score: {model_score}")
        hybrid_conf = calculate_hybrid_confidence(
            model_score,
            test_cases[0]['json'],  # Use good extraction
            test_cases[0]['description']
        )
        print(f"Hybrid Confidence: {hybrid_conf:.3f} ({get_confidence_category(hybrid_conf)})")
