import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# docker/analyzer.py
import sys
import json
import os
from analysis import hash_analysis, pe_analysis, string_analysis, entropy, yara_scan, feature_extractor, ml_predict, ioc

def main():
    # The sample path is passed as a command-line argument by the Flask app
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: analyzer.py <sample_path>"}))
        sys.exit(1)

    sample_path = sys.argv[1]

    if not os.path.exists(sample_path):
        print(json.dumps({"error": f"Sample not found: {sample_path}"}))
        sys.exit(1)

    print(f"Starting analysis for: {sample_path}", file=sys.stderr) # Log to stderr, not stdout which is for the final JSON
    #print("Debug message", file=sys.stderr)  # Use stderr for logs
    # Initialize the final report dictionary
    report = {
        "filename": os.path.basename(sample_path),
        "hashes": {},
        "pe_info": {},
        "strings": {},
        "entropy": 0,
        "yara_matches": [],
        "ml_prediction": {"label": "Unknown", "confidence": 0.0},
        "iocs": {}
    }

    # 1. Hash Analysis
    report['hashes'] = hash_analysis.get_hashes(sample_path)

    # 2. PE Analysis
    report['pe_info'] = pe_analysis.analyze_pe(sample_path)

    # 3. String Analysis
    report['strings'] = string_analysis.extract_indicators(sample_path)

    # 4. Entropy Analysis
    report['entropy'] = entropy.calculate_file_entropy(sample_path)

    # 5. YARA Scan
    rules_dir = "/app/yara_rules/" # Path inside the container
    report['yara_matches'] = yara_scan.scan_with_yara(sample_path, rules_dir)

    # 6. Feature Extraction
    features = feature_extractor.extract_features(sample_path, report)

    # 7. ML Prediction
    model_path = "/app/models/malware_model.pkl"
    report['ml_prediction'] = ml_predict.get_prediction(model_path, features)

    # 8. IOC Extraction (This often happens during string analysis, but we structure it here)
    report['iocs'] = ioc.extract_iocs(report['strings']['all_strings']) # Pass all raw strings

    # Output the final JSON report to stdout. Flask will capture this.
    print(json.dumps(report, indent=4))

if __name__ == "__main__":
    main()
