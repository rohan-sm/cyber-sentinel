from fastapi import FastAPI
from pydantic import BaseModel
import pandas as pd
from pathlib import Path
from fastapi.middleware.cors import CORSMiddleware

BASE_DIR = Path(__file__).resolve().parent.parent.parent

DATA_PATH = BASE_DIR / "data" / "engineered_dataset.csv"



from models.hybrid_model import HybridDetector

# ==========================================
# LOAD HYBRID MODEL
# ==========================================

hybrid = HybridDetector.load(
    "../outputs/models/hybrid_model.pkl"
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
        "message": "CyberSentinel Hybrid IDS Running"
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

    result = hybrid.predict(df)

    row = result.iloc[0]

    return {
        "anomaly_pred": int(row["anomaly_pred"]),
        "attack_pred": row["attack_pred"],
        "final_prediction": row["final_prediction"],
        "confidence": float(row["confidence"]),
        "severity": row["severity"]
    }



# ==========================================
# @app.get("/sample_attack/{attack_type}")
# def sample_attack(attack_type: str):

#     import pandas as pd

#     # LOAD DATASET
#     df = pd.read_csv(DATA_PATH)

#     # FILTER ATTACK
#     sample_df = df[df['attack_type'] == attack_type]

#     if len(sample_df) == 0:

#         return {
#             "error": f"No samples found for {attack_type}"
#         }

#     # RANDOM SAMPLE
#     sample = sample_df.sample(1, random_state=None)

#     # FEATURES
#     features = [
#         'failure_rate',
#         'port_scan_intensity',
#         'process_cpu_ratio',
#         'packet_spike_ratio',
#         'connection_spike_ratio',
#         'cpu_spike_ratio'
#     ]

#     input_df = sample[features]

#     # PREDICT
#     result = hybrid.predict(input_df)

#     output = result.iloc[0]

#     return {
#         "actual_attack": attack_type,
#         "prediction": output["final_prediction"],
#         "confidence": float(output["confidence"]),
#         "severity": output["severity"],
#         "anomaly_score": float(output["anomaly_score"])
#     }