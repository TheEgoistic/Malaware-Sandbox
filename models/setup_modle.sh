#!/bin/bash

echo "========================================="
echo " MALWARE MODEL SETUP"
echo "========================================="

# Create models directory
mkdir -p models

# Install dependencies
echo -e "\n[1/3] Installing dependencies..."
pip3 install --user scikit-learn pandas numpy joblib 2>/dev/null

# Train model
echo -e "\n[2/3] Training model..."
python3 train_model.py

# Verify model
echo -e "\n[3/3] Verifying model..."
if [ -f "models/malware_model.pkl" ]; then
    echo "[✓] Model file created: models/malware_model.pkl"
    ls -lh models/malware_model.pkl
    
    # Quick test
    python3 -c "
import joblib
model = joblib.load('models/malware_model.pkl')
print('[✓] Model loads successfully')
print(f'    Model type: {type(model).__name__}')
"
else
    echo "[✗] Model file not created"
    exit 1
fi

echo -e "\n[✓] Model setup complete!"
echo "    Model location: $(pwd)/models/malware_model.pkl"
