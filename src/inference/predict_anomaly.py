import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pandas as pd
from models.anomaly_model import AnomalyDetector

df = pd.read_csv("../data/processed/engineered_dataset.csv")

detector = AnomalyDetector()
detector.load("../outputs/models/anomaly_model.pkl")

preds, scores = detector.predict(df)

df['anomaly_pred'] = preds

print(df[['anomaly_pred']].head())

print("Anomaly count:", sum(preds))

print(df['attack_type'].value_counts())
print(df.groupby('attack_type')['anomaly_pred'].mean())