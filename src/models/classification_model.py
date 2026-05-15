import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler


class AttackClassifier:
    def __init__(self):
        self.features = [
            'failure_rate',
            'port_scan_intensity',
            'process_cpu_ratio',
            'packet_spike_ratio',
            'connection_spike_ratio',
            'cpu_spike_ratio'
        ]

        self.model = RandomForestClassifier(
            n_estimators=50,
            max_depth=5,
            min_samples_leaf=3,
            min_samples_split=5,
            random_state=42
        )

        self.scaler = StandardScaler()
        self.encoder = LabelEncoder()

    # ── Preprocessing ───────────────────────────────
    def preprocess(self, df):
        df = df.copy()

        df = df.replace([np.inf, -np.inf], np.nan).fillna(0)

        for col in ['process_cpu_ratio', 'packet_spike_ratio', 'connection_spike_ratio']:
            df[col] = np.log1p(df[col])

        return df

    # ── Training ───────────────────────────────────
    def fit(self, X_train, y_train):
        X_train = self.preprocess(X_train)

        # Encode labels
        y_encoded = self.encoder.fit_transform(y_train)

        # Scale
        X_scaled = self.scaler.fit_transform(X_train[self.features])

        self.model.fit(X_scaled, y_encoded)

    # ── Prediction ─────────────────────────────────
    def predict(self, df):
        df = self.preprocess(df)

        X_scaled = self.scaler.transform(df[self.features])

        preds = self.model.predict(X_scaled)

        return self.encoder.inverse_transform(preds)
    
    # ─ Predict probabilities (for unknown classes) ───────────────────────────────
    
    def predict_proba(self, df):
        df = self.preprocess(df)

        X_scaled = self.scaler.transform(df[self.features])

        return self.model.predict_proba(X_scaled)

    # ── Save / Load ────────────────────────────────
    def save(self, path):
        joblib.dump({
            "model": self.model,
            "scaler": self.scaler,
            "encoder": self.encoder,
            "features": self.features
        }, path)

    def load(self, path):
        data = joblib.load(path)
        self.model = data["model"]
        self.scaler = data["scaler"]
        self.encoder = data["encoder"]
        self.features = data["features"]