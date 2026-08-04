def extract_features(file_path, report):
    """Create a feature vector for the ML model."""
    file_size = 0
    try:
        file_size = os.path.getsize(file_path)
    except:
        pass

    features = [
        file_size,
        len(report['pe_info']['sections']),
        len(report['pe_info']['imports']),
        report['entropy'],
        1 if report['yara_matches'] else 0, # Binary: any YARA match?
        len(report['strings']['urls']),
        len(report['strings']['ips']),
        # Add more features based on your model's training
    ]
    
    # A real model would need consistent feature ordering.
    # This is a placeholder. The actual feature names must match your trained model.
    feature_names = [
        "filesize", "num_sections", "num_imports", 
        "entropy", "has_yara_match", "num_urls", "num_ips"
    ]
    print(f"Extracted features: {dict(zip(feature_names, features))}", file=sys.stderr)
    return features
