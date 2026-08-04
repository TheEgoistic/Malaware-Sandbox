"""
Malware Detection Model Training Script
Creates and trains a Random Forest classifier for malware detection
"""

import numpy as np
import pandas as pd
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.pipeline import Pipeline
import warnings
warnings.filterwarnings('ignore')

def generate_synthetic_data(n_samples=10000):
    """
    Generate synthetic malware/benign sample data for training
    In production, you would use real datasets like EMBER or BODMAS
    """
    np.random.seed(42)
    
    data = []
    
    for i in range(n_samples):
        is_malware = np.random.choice([0, 1], p=[0.7, 0.3])  # 70% benign, 30% malware
        
        if is_malware == 1:
            # Malware characteristics
            features = {
                'filesize': np.random.randint(50000, 5000000),
                'num_sections': np.random.randint(3, 10),
                'num_imports': np.random.randint(10, 200),
                'entropy': np.random.uniform(6.5, 8.0),
                'has_yara_match': np.random.choice([0, 1], p=[0.2, 0.8]),
                'num_urls': np.random.randint(1, 20),
                'num_ips': np.random.randint(1, 10),
                'num_registry_keys': np.random.randint(2, 15),
                'is_pe': 1,
                'header_sections': np.random.randint(3, 8),
                'is_malware': 1
            }
        else:
            # Benign file characteristics
            features = {
                'filesize': np.random.randint(1000, 10000000),
                'num_sections': np.random.randint(2, 6),
                'num_imports': np.random.randint(5, 50),
                'entropy': np.random.uniform(3.0, 6.0),
                'has_yara_match': np.random.choice([0, 1], p=[0.9, 0.1]),
                'num_urls': np.random.randint(0, 3),
                'num_ips': np.random.randint(0, 2),
                'num_registry_keys': np.random.randint(0, 3),
                'is_pe': np.random.choice([0, 1], p=[0.1, 0.9]),
                'header_sections': np.random.randint(2, 5),
                'is_malware': 0
            }
        
        data.append(features)
    
    df = pd.DataFrame(data)
    return df

def create_feature_engineering(df):
    """Add derived features to improve model accuracy"""
    df_copy = df.copy()
    
    # Derived features
    df_copy['entropy_squared'] = df_copy['entropy'] ** 2
    df_copy['imports_per_section'] = df_copy['num_imports'] / (df_copy['num_sections'] + 1)
    df_copy['indicators_total'] = df_copy['num_urls'] + df_copy['num_ips'] + df_copy['num_registry_keys']
    df_copy['size_per_section'] = df_copy['filesize'] / (df_copy['num_sections'] + 1)
    df_copy['high_entropy'] = (df_copy['entropy'] > 7.0).astype(int)
    df_copy['suspicious_score'] = (
        df_copy['has_yara_match'] * 3 +
        df_copy['high_entropy'] * 2 +
        (df_copy['indicators_total'] > 10).astype(int) * 3 +
        (df_copy['num_imports'] > 100).astype(int) * 2
    )
    
    return df_copy

def train_model():
    """Train the malware detection model"""
    print("=" * 60)
    print("MALWARE DETECTION MODEL TRAINING")
    print("=" * 60)
    
    # 1. Generate training data
    print("\n[1/6] Generating synthetic training data...")
    df = generate_synthetic_data(15000)
    df = create_feature_engineering(df)
    print(f"    Generated {len(df)} samples")
    print(f"    Malware: {df['is_malware'].sum()} ({df['is_malware'].mean()*100:.1f}%)")
    print(f"    Benign: {(df['is_malware']==0).sum()} ({(1-df['is_malware'].mean())*100:.1f}%)")
    
    # 2. Prepare features and target
    print("\n[2/6] Preparing features...")
    feature_columns = [
        'filesize', 'num_sections', 'num_imports', 'entropy',
        'has_yara_match', 'num_urls', 'num_ips', 'num_registry_keys',
        'is_pe', 'header_sections', 'entropy_squared', 'imports_per_section',
        'indicators_total', 'size_per_section', 'high_entropy', 'suspicious_score'
    ]
    
    X = df[feature_columns]
    y = df['is_malware']
    
    print(f"    Features: {len(feature_columns)}")
    print(f"    Feature names: {feature_columns}")
    
    # 3. Split data
    print("\n[3/6] Splitting data into train/test sets...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"    Training set: {len(X_train)} samples")
    print(f"    Test set: {len(X_test)} samples")
    
    # 4. Create and train model
    print("\n[4/6] Training Random Forest classifier...")
    
    # Create pipeline with scaling and classifier
    model = Pipeline([
        ('scaler', StandardScaler()),
        ('classifier', RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        ))
    ])
    
    # Train the model
    model.fit(X_train, y_train)
    print("    Training complete!")
    
    # 5. Evaluate model
    print("\n[5/6] Evaluating model performance...")
    
    # Make predictions
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\n    Model Accuracy: {accuracy*100:.2f}%")
    print(f"\n    Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Malicious']))
    
    # Cross-validation
    cv_scores = cross_val_score(model, X_train, y_train, cv=5)
    print(f"    Cross-validation scores: {cv_scores}")
    print(f"    Average CV score: {cv_scores.mean()*100:.2f}% (+/- {cv_scores.std()*2*100:.2f}%)")
    
    # Feature importance
    classifier = model.named_steps['classifier']
    feature_importance = pd.DataFrame({
        'feature': feature_columns,
        'importance': classifier.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print(f"\n    Top 10 Most Important Features:")
    for idx, row in feature_importance.head(10).iterrows():
        print(f"    - {row['feature']}: {row['importance']*100:.2f}%")
    
    # 6. Save the model
    print("\n[6/6] Saving model...")
    os.makedirs('models', exist_ok=True)
    model_path = 'models/malware_model.pkl'
    joblib.dump(model, model_path)
    
    # Also save feature names for reference
    joblib.dump(feature_columns, 'models/feature_names.pkl')
    
    # Calculate model file size
    model_size = os.path.getsize(model_path)
    print(f"    Model saved to: {model_path}")
    print(f"    Model size: {model_size / 1024:.1f} KB")
    
    # 7. Test prediction on sample cases
    print("\n" + "=" * 60)
    print("SAMPLE PREDICTIONS")
    print("=" * 60)
    
    test_samples = {
        "Typical Malware": {
            'filesize': 500000,
            'num_sections': 5,
            'num_imports': 150,
            'entropy': 7.5,
            'has_yara_match': 1,
            'num_urls': 10,
            'num_ips': 5,
            'num_registry_keys': 8,
            'is_pe': 1,
            'header_sections': 5
        },
        "Typical Benign": {
            'filesize': 2000000,
            'num_sections': 4,
            'num_imports': 30,
            'entropy': 4.5,
            'has_yara_match': 0,
            'num_urls': 1,
            'num_ips': 0,
            'num_registry_keys': 1,
            'is_pe': 1,
            'header_sections': 4
        },
        "Packed Malware": {
            'filesize': 100000,
            'num_sections': 3,
            'num_imports': 5,
            'entropy': 7.8,
            'has_yara_match': 1,
            'num_urls': 2,
            'num_ips': 3,
            'num_registry_keys': 0,
            'is_pe': 1,
            'header_sections': 2
        }
    }
    
    for name, features in test_samples.items():
        # Add derived features
        features_df = pd.DataFrame([features])
        features_df = create_feature_engineering(features_df)
        
        # Select only model features
        X_sample = features_df[feature_columns]
        
        # Predict
        pred = model.predict(X_sample)[0]
        proba = model.predict_proba(X_sample)[0]
        
        result = "MALICIOUS" if pred == 1 else "BENIGN"
        confidence = proba[1] * 100 if pred == 1 else proba[0] * 100
        
        print(f"\n{name}:")
        print(f"  Prediction: {result}")
        print(f"  Confidence: {confidence:.1f}%")
        print(f"  Probabilities: Benign={proba[0]*100:.1f}%, Malicious={proba[1]*100:.1f}%")
    
    print("\n" + "=" * 60)
    print("MODEL TRAINING COMPLETE!")
    print("=" * 60)
    
    return model, feature_columns

if __name__ == "__main__":
    model, features = train_model()

