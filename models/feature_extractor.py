"""
Feature Extractor - Extracts features for ML model
Must produce the same features the model was trained on
"""

import os
import sys
import numpy as np

def extract_features(file_path, report):
    """Extract features from analysis report for ML prediction"""
    
    # Basic features
    file_size = 0
    try:
        file_size = os.path.getsize(file_path)
    except:
        pass
    
    pe_info = report.get('pe_info', {})
    strings_info = report.get('strings', {})
    
    # Extract all features (must match training features exactly)
    features = {
        'filesize': file_size,
        'num_sections': len(pe_info.get('sections', [])),
        'num_imports': len(pe_info.get('imports', [])),
        'entropy': report.get('entropy', 0),
        'has_yara_match': 1 if report.get('yara_matches') else 0,
        'num_urls': len(strings_info.get('urls', [])),
        'num_ips': len(strings_info.get('ips', [])),
        'num_registry_keys': len(strings_info.get('registry_keys', [])),
        'is_pe': 1 if pe_info.get('is_pe') else 0,
        'header_sections': pe_info.get('number_of_sections', 0),
    }
    
    # Derived features (engineered)
    features['entropy_squared'] = features['entropy'] ** 2
    features['imports_per_section'] = features['num_imports'] / (features['num_sections'] + 1)
    features['indicators_total'] = features['num_urls'] + features['num_ips'] + features['num_registry_keys']
    features['size_per_section'] = features['filesize'] / (features['num_sections'] + 1)
    features['high_entropy'] = 1 if features['entropy'] > 7.0 else 0
    features['suspicious_score'] = (
        features['has_yara_match'] * 3 +
        features['high_entropy'] * 2 +
        (1 if features['indicators_total'] > 10 else 0) * 3 +
        (1 if features['num_imports'] > 100 else 0) * 2
    )
    
    # Return as ordered list matching training feature order
    feature_order = [
        'filesize', 'num_sections', 'num_imports', 'entropy',
        'has_yara_match', 'num_urls', 'num_ips', 'num_registry_keys',
        'is_pe', 'header_sections', 'entropy_squared', 'imports_per_section',
        'indicators_total', 'size_per_section', 'high_entropy', 'suspicious_score'
    ]
    
    feature_vector = [features[name] for name in feature_order]
    
    # Debug output
    print(f"[*] Extracted {len(feature_vector)} features", file=sys.stderr)
    print(f"    Key features: filesize={features['filesize']}, "
          f"entropy={features['entropy']}, "
          f"sections={features['num_sections']}, "
          f"imports={features['num_imports']}", file=sys.stderr)
    
    return feature_vector

