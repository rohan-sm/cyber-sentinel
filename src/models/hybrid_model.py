import joblib
import pandas as pd

from models.anomaly_model import AnomalyDetector
from models.classification_model import AttackClassifier
from sklearn.metrics import classification_report



class HybridDetector:
    def __init__(self):
        self.anomaly_model = AnomalyDetector()
        self.classifier = AttackClassifier()

    # ── Load sub-models ─────────────────────────────
    def load_models(self, anomaly_path, classifier_path):
        self.anomaly_model.load(anomaly_path)
        self.classifier.load(classifier_path)

    # ── Predict ─────────────────────────────────────
    def predict(self, df):

        df = df.copy()

        # STEP 1 — ANOMALY DETECTION
        anomaly_preds, anomaly_scores = self.anomaly_model.predict(df)

        # PREPARE OUTPUT CONTAINERS
        class_preds = ['not_classified'] * len(df)

        confidence_scores = [0.0] * len(df)

        severity_levels = ['low'] * len(df)

        final_preds = ['none'] * len(df)

        # FIND ANOMALOUS SAMPLES
        anomaly_indices = [
            i for i, val in enumerate(anomaly_preds)
            if val == 1
        ]

        # STEP 2 — CLASSIFY ONLY ANOMALIES
        if anomaly_indices:

            anomaly_df = df.iloc[anomaly_indices]

            # RF predictions
            attack_preds = self.classifier.predict(anomaly_df)

            # RF probabilities
            attack_probs = self.classifier.predict_proba(anomaly_df)

            # PROCESS EACH ANOMALY
            for idx, pred, probs in zip(
                anomaly_indices,
                attack_preds,
                attack_probs
            ):

                confidence = float(max(probs))

                # UNKNOWN ATTACK HANDLING
                if confidence < 0.65:
                    pred = 'suspicious_unknown'

                # SEVERITY LOGIC
                anomaly_score = anomaly_scores[idx]

                if anomaly_score < -0.20:
                    severity = 'high'

                elif anomaly_score < -0.10:
                    severity = 'medium'

                else:
                    severity = 'low'

                # STORE RESULTS
                class_preds[idx] = pred

                confidence_scores[idx] = round(confidence, 4)

                severity_levels[idx] = severity

                final_preds[idx] = pred

        # STORE OUTPUTS
        df['anomaly_pred'] = anomaly_preds
        df['anomaly_score'] = anomaly_scores
        df['attack_pred'] = class_preds
        df['confidence'] = confidence_scores
        df['severity'] = severity_levels
        df['final_prediction'] = final_preds

        return df

    # ── Save whole hybrid system ────────────────────
    def save(self, path):
        joblib.dump(self, path)

    # ── Load whole hybrid system ────────────────────
    @staticmethod
    def load(path):
        return joblib.load(path)