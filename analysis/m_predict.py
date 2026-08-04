import joblib
import os
import sys

def get_prediction(model_path, features):
    """Load a trained model and make a prediction."""
    prediction = {"label": "Error", "confidence": 0.0}
    if not os.path.exists(model_path):
        print(f"Model file not found at {model_path}", file=sys.stderr)
        return prediction

    try:
        model = joblib.load(model_path)
        # The model expects a 2D array: predict([[f1, f2, ...]])
        probas = model.predict_proba([features])[0]
        pred_class = model.predict([features])[0]
        
        # Assuming your model has classes_ attribute: [0, 1] where 1 is malicious
        malicious_index = list(model.classes_).index(1) # Adjust this as needed
        prediction = {
            "label": "Malicious" if pred_class == 1 else "Benign",
            "confidence": round(probas[malicious_index] * 100, 2)
        }
    except Exception as e:
        print(f"ML prediction error: {e}", file=sys.stderr)
    
    return prediction
