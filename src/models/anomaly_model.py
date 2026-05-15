import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class AnomalyDetector:
    def __init__(self):
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.2,
            random_state=42
        )
        self.features = [
            'failure_rate',
            'port_scan_intensity',
            'process_cpu_ratio',
            'packet_spike_ratio',
            'connection_spike_ratio',
            'cpu_spike_ratio'
        ]

    def preprocess(self, df):
        # Fix inf/nan
        df = df.replace([np.inf, -np.inf], np.nan).fillna(0)

        # Log transform
        for col in ['process_cpu_ratio', 'packet_spike_ratio', 'connection_spike_ratio']:
            df[col] = np.log1p(df[col])

        return df

    def fit(self, df):
        df = self.preprocess(df)

        X = df[self.features]
        y = df['is_attack']

        # Train only on normal
        X_train = X[y == 0]

        # Drop zero variance
        zero_var = X_train.columns[X_train.std() == 0]
        X_train = X_train.drop(columns=zero_var)
        X = X.drop(columns=zero_var)

        self.active_features = X.columns

        # Scale
        X_train_scaled = self.scaler.fit_transform(X_train)

        # Train model
        self.model.fit(X_train_scaled)

    def predict(self, df, threshold=-0.02):
        df = self.preprocess(df)

        X = df[self.active_features]
        X_scaled = self.scaler.transform(X)

        scores = self.model.decision_function(X_scaled)

        preds = (scores < threshold).astype(int)

        return preds, scores

    def save(self, path):
        joblib.dump({
            "model": self.model,
            "scaler": self.scaler,
            "features": self.active_features
        }, path)

    def load(self, path):
        data = joblib.load(path)
        self.model = data["model"]
        self.scaler = data["scaler"]
        self.active_features = data["features"]