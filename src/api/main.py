from fastapi import FastAPI
# pyrefly: ignore [missing-import]
from pydantic import BaseModel
import pandas as pd
from pathlib import Path
# pyrefly: ignore [missing-import]
from fastapi.middleware.cors import CORSMiddleware

BASE_DIR = Path(__file__).resolve().parent.parent.parent

DATA_PATH = BASE_DIR / "data" / "engineered_dataset.csv"

import sys
sys.path.append(str(BASE_DIR / "src"))

# from models.hybrid_model import HybridDetector
from models.classification_model import AttackClassifier

# ==========================================
# LOAD HYBRID MODEL
# ==========================================

classifier = AttackClassifier()
classifier.load(
    str(BASE_DIR / "outputs" / "models" / "classifier.pkl")
)

# ==========================================
# FASTAPI APP
# ==========================================

app = FastAPI(
    title="CyberSentinel API",
    version="1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# REQUEST SCHEMA
# ==========================================

class PredictionRequest(BaseModel):

    failure_rate: float
    port_scan_intensity: float
    process_cpu_ratio: float
    packet_spike_ratio: float
    connection_spike_ratio: float
    cpu_spike_ratio: float

# ==========================================
# ROOT
# ==========================================

@app.get("/")
def root():

    return {
        "message": "CyberSentinel Classifier IDS Running"
    }

# ==========================================
# HEALTH
# ==========================================

@app.get("/health")
def health():

    return {
        "status": "healthy"
    }

# ==========================================
# PREDICT
# ==========================================

@app.post("/predict")
def predict(request: PredictionRequest):

    df = pd.DataFrame([request.dict()])

    # Predict attack type
    preds = classifier.predict(df)
    attack_pred = preds[0]

    # Predict confidence
    probas = classifier.predict_proba(df)
    confidence = float(probas.max(axis=1)[0])

    # Unknown handling
    if confidence < 0.65:
        final_prediction = 'suspicious_unknown'
    else:
        final_prediction = attack_pred

    # Determine mock severity based on confidence
    if final_prediction == 'none':
        anomaly_pred = 0
        severity = 'low'
    else:
        anomaly_pred = 1
        if confidence > 0.85:
            severity = 'high'
        elif confidence > 0.70:
            severity = 'medium'
        else:
            severity = 'low'

    return {
        "anomaly_pred": anomaly_pred,
        "attack_pred": attack_pred,
        "final_prediction": final_prediction,
        "confidence": round(confidence, 4),
        "severity": severity
    }


# ==========================================
# SAMPLE ATTACK
# ==========================================

@app.get("/sample_attack/{attack_type}")
def sample_attack(attack_type: str):

    import pandas as pd

    # LOAD DATASET
    df = pd.read_csv(DATA_PATH)

    # FILTER ATTACK
    sample_df = df[df['attack_type'] == attack_type]

    if len(sample_df) == 0:

        return {
            "error": f"No samples found for {attack_type}"
        }

    # RANDOM SAMPLE
    sample = sample_df.sample(1, random_state=None)

    # FEATURES
    features = [
        'failure_rate',
        'port_scan_intensity',
        'process_cpu_ratio',
        'packet_spike_ratio',
        'connection_spike_ratio',
        'cpu_spike_ratio'
    ]

    input_df = sample[features]

    # PREDICT
    preds = classifier.predict(input_df)
    attack_pred = preds[0]

    probas = classifier.predict_proba(input_df)
    confidence = float(probas.max(axis=1)[0])

    if confidence < 0.65:
        final_prediction = 'suspicious_unknown'
    else:
        final_prediction = attack_pred

    if final_prediction == 'none':
        severity = 'low'
        anomaly_score = 0.0
    else:
        anomaly_score = -0.5 # Dummy negative value for frontend
        if confidence > 0.85:
            severity = 'high'
        elif confidence > 0.70:
            severity = 'medium'
        else:
            severity = 'low'

    return {
        "actual_attack": attack_type,
        "prediction": final_prediction,
        "confidence": round(confidence, 4),
        "severity": severity,
        "anomaly_score": anomaly_score
    }