"""
Test script to verify the trained model works correctly
"""

import joblib
import numpy as np
import os
import sys

def test_model():
    """Load and test the trained model"""
    
    model_path = 'models/malware_model.pkl'
    
    # Check if model exists
    if not os.path.exists(model_path):
        print(f"[✗] Model not found at {model_path}")
        print("    Run 'python3 train_model.py' first")
        return False
    
    # Load model
    print("[*] Loading model...")
    model = joblib.load(model_path)
    print(f"[✓] Model loaded successfully")
    print(f"    Model type: {type(model.named_steps['classifier']).__name__}")
    
    # Get expected features
    print("\n[*] Model expects these features:")
    if os.path.exists('models/feature_names.pkl'):
        feature_names = joblib.load('models/feature_names.pkl')
        for i, name in enumerate(feature_names):
            print(f"    {i}: {name}")
    else:
        print("    Feature names file not found")
    
    # Test prediction with sample data
    print("\n[*] Testing predictions...")
    
    # Test case 1: Malware-like features
    test_malware = np.array([[500000, 5, 150, 7.5, 1, 10, 5, 8, 1, 5, 
                              56.25, 25.0, 23, 100000, 1, 11]])
    
    # Test case 2: Benign-like features  
    test_benign = np.array([[2000000, 4, 30, 4.5, 0, 1, 0, 1, 1, 4,
                             20.25, 7.5, 2, 500000, 0, 0]])
    
    try:
        # Predict malware
        pred1 = model.predict(test_malware)[0]
        proba1 = model.predict_proba(test_malware)[0]
        print(f"\n  Test 1 (Malware-like):")
        print(f"    Prediction: {'MALICIOUS' if pred1 == 1 else 'BENIGN'}")
        print(f"    Confidence: {proba1[1]*100:.1f}% malicious")
        print(f"    Probabilities: Benign={proba1[0]*100:.1f}%, Malicious={proba1[1]*100:.1f}%")
        
        # Predict benign
        pred2 = model.predict(test_benign)[0]
        proba2 = model.predict_proba(test_benign)[0]
        print(f"\n  Test 2 (Benign-like):")
        print(f"    Prediction: {'MALICIOUS' if pred2 == 1 else 'BENIGN'}")
        print(f"    Confidence: {proba2[0]*100:.1f}% benign")
        print(f"    Probabilities: Benign={proba2[0]*100:.1f}%, Malicious={proba2[1]*100:.1f}%")
        
        print(f"\n[✓] Model is working correctly!")
        return True
        
    except Exception as e:
        print(f"\n[✗] Prediction failed: {e}")
        print("    Feature count mismatch. Model expects different features.")
        print("    Ensure feature_extractor.py produces the same features as the model was trained on.")
        return False

if __name__ == "__main__":
    print("=" * 50)
    print("MALWARE MODEL VERIFICATION")
    print("=" * 50)
    
    success = test_model()
    
    if success:
        print("\n[✓] Model is ready for use in the sandbox!")
    else:
        print("\n[✗] Model needs to be retrained or fixed")
    
    sys.exit(0 if success else 1)

