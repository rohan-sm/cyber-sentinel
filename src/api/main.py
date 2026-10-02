
# # # # ==========================================





# from fastapi import FastAPI
# from fastapi.middleware.cors import CORSMiddleware

# import pandas as pd
# from pathlib import Path
# import sys

# # ==========================================
# # BASE PATHS
# # ==========================================

# BASE_DIR = Path(__file__).resolve().parent.parent.parent

# DATA_PATH = (
#     BASE_DIR
#     / "data"
#     / "processed"
#     / "engineered_dataset.csv"
# )

# MODEL_PATH = (
#     BASE_DIR
#     / "outputs"
#     / "models"
#     / "classifier.pkl"
# )

# # ==========================================
# # IMPORT MODEL
# # ==========================================

# sys.path.append(str(BASE_DIR / "src"))

# from models.classification_model import (
#     AttackClassifier
# )

# # ==========================================
# # LOAD MODEL
# # ==========================================

# classifier = AttackClassifier()

# classifier.load(str(MODEL_PATH))

# # ==========================================
# # FASTAPI APP
# # ==========================================

# app = FastAPI(
#     title="CyberSentinel API",
#     version="2.0"
# )

# # ==========================================
# # ENABLE CORS
# # ==========================================

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# # ==========================================
# # FEATURE COLUMNS
# # ==========================================

# FEATURE_COLUMNS = [

#     "failure_rate",

#     "port_scan_intensity",

#     "process_cpu_ratio",

#     "packet_spike_ratio",

#     "connection_spike_ratio",

#     "cpu_spike_ratio"
# ]

# # ==========================================
# # ROOT
# # ==========================================

# @app.get("/")
# def root():

#     return {

#         "message":
#             "CyberSentinel Live IDS Running"
#     }

# # ==========================================
# # HEALTH CHECK
# # ==========================================

# @app.get("/health")
# def health():

#     return {

#         "status": "healthy"
#     }

# # ==========================================
# # LIVE DETECTION
# # ==========================================

# @app.get("/live_detection")
# def live_detection():

#     # ======================================
#     # LOAD DATASET
#     # ======================================

#     df = pd.read_csv(DATA_PATH)

#     # ======================================
#     # RANDOM SAMPLE
#     # ======================================

#     sample = df.sample(1)

#     actual_attack = (
#         sample.iloc[0]["attack_type"]
#     )

#     # ======================================
#     # FEATURE EXTRACTION
#     # ======================================

#     input_df = sample[FEATURE_COLUMNS]

#     # ======================================
#     # PREDICT ATTACK
#     # ======================================

#     preds = classifier.predict(input_df)

#     attack_pred = preds[0]

#     # ======================================
#     # CONFIDENCE
#     # ======================================

#     probas = classifier.predict_proba(
#         input_df
#     )

#     confidence = float(
#         probas.max(axis=1)[0]
#     )

#     # ======================================
#     # UNKNOWN ATTACK HANDLING
#     # ======================================

#     if confidence < 0.65:

#         final_prediction = (
#             "suspicious_unknown"
#         )

#     else:

#         final_prediction = attack_pred

#     # ======================================
#     # SEVERITY LOGIC
#     # ======================================

#     if final_prediction == "none":

#         anomaly_pred = 0

#         severity = "low"

#         anomaly_score = 0.0

#     else:

#         anomaly_pred = 1

#         anomaly_score = round(
#             -confidence,
#             4
#         )

#         if confidence > 0.85:

#             severity = "high"

#         elif confidence > 0.70:

#             severity = "medium"

#         else:

#             severity = "low"

#     # ======================================
#     # FINAL RESPONSE
#     # ======================================

#     return {

#         "actual_attack":
#             actual_attack,

#         "anomaly_pred":
#             anomaly_pred,

#         "attack_pred":
#             attack_pred,

#         "final_prediction":
#             final_prediction,

#         "confidence":
#             round(confidence, 4),

#         "severity":
#             severity,

#         "anomaly_score":
#             anomaly_score
#     }


from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import pandas as pd
from pathlib import Path
import sys

# ==========================================
# BASE PATHS
# ==========================================

BASE_DIR = Path(__file__).resolve().parent.parent.parent

DATA_PATH = (
    BASE_DIR
    / "data"
    / "processed"
    / "engineered_dataset.csv"
)

HYBRID_MODEL_PATH = (
    BASE_DIR
    / "outputs"
    / "models"
    / "hybrid_model.pkl"
)

# ==========================================
# IMPORT MODELS
# ==========================================

sys.path.append(str(BASE_DIR / "src"))

from models.hybrid_model import (
    HybridDetector
)

# ==========================================
# LOAD MODELS
# ==========================================

hybrid = HybridDetector.load(
    str(HYBRID_MODEL_PATH)
)

# ==========================================
# FASTAPI APP
# ==========================================

app = FastAPI(
    title="CyberSentinel API",
    version="2.0"
)

# ==========================================
# ENABLE CORS
# ==========================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# FEATURE COLUMNS
# ==========================================

FEATURE_COLUMNS = [

    "failure_rate",

    "port_scan_intensity",

    "process_cpu_ratio",

    "packet_spike_ratio",

    "connection_spike_ratio",

    "cpu_spike_ratio"
]

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

        "message":
            "CyberSentinel Hybrid IDS Running"
    }

# ==========================================
# HEALTH CHECK
# ==========================================

@app.get("/health")
def health():

    return {

        "status": "healthy"
    }

# ==========================================
# MANUAL PREDICTION
# ==========================================

@app.post("/predict")
def predict(request: PredictionRequest):

    # ======================================
    # CREATE DATAFRAME
    # ======================================

    df = pd.DataFrame(
        [request.model_dump()]
    )

    # ======================================
    # HYBRID CASCADE PREDICTION
    #
    # STAGE 1: ISOLATION FOREST GATES
    # STAGE 2: RANDOM FOREST CLASSIFIES
    #         ONLY THE FLAGGED ROWS
    # ======================================

    row = hybrid.predict(df).iloc[0]

    # ======================================
    # RESPONSE
    # ======================================

    return {

        "anomaly_pred":
            int(row["anomaly_pred"]),

        "anomaly_score":
            round(
                float(row["anomaly_score"]), 4
            ),

        "attack_pred":
            row["attack_pred"],

        "final_prediction":
            row["final_prediction"],

        "confidence":
            round(
                float(row["confidence"]), 4
            ),

        "severity":
            row["severity"]
    }

# ==========================================
# LIVE DETECTION
# ==========================================

@app.get("/live_detection")
def live_detection():

    # ======================================
    # LOAD DATASET
    # ======================================

    df = pd.read_csv(DATA_PATH)

    # ======================================
    # RANDOM SAMPLE
    # ======================================

    sample = df.sample(1)

    actual_attack = (
        sample.iloc[0]["attack_type"]
    )

    # ======================================
    # FEATURE EXTRACTION
    # ======================================

    input_df = sample[FEATURE_COLUMNS]

    # ======================================
    # HYBRID PREDICTION
    # ======================================

    result = hybrid.predict(input_df)

    row = result.iloc[0]

    # ======================================
    # RESPONSE
    # ======================================

    return {

    # ==================================
    # ACTUAL LABEL
    # ==================================

    "actual_attack":
        actual_attack,

    # ==================================
    # INPUT FEATURES USED
    # ==================================

    "input_features": {

        "failure_rate":
            float(
                sample.iloc[0][
                    "failure_rate"
                ]
            ),

        "port_scan_intensity":
            float(
                sample.iloc[0][
                    "port_scan_intensity"
                ]
            ),

        "process_cpu_ratio":
            float(
                sample.iloc[0][
                    "process_cpu_ratio"
                ]
            ),

        "packet_spike_ratio":
            float(
                sample.iloc[0][
                    "packet_spike_ratio"
                ]
            ),

        "connection_spike_ratio":
            float(
                sample.iloc[0][
                    "connection_spike_ratio"
                ]
            ),

        "cpu_spike_ratio":
            float(
                sample.iloc[0][
                    "cpu_spike_ratio"
                ]
            )
    },

    # ==================================
    # PREDICTIONS
    # ==================================

    "anomaly_pred":
        int(row["anomaly_pred"]),

    "anomaly_score":
        float(row["anomaly_score"]),

    "attack_pred":
        row["attack_pred"],

    "final_prediction":
        row["final_prediction"],

    # ==================================
    # CONFIDENCE + SEVERITY
    # ==================================

    "confidence":
        float(row["confidence"]),

    "severity":
        row["severity"]
}