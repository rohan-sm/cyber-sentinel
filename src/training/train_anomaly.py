import pandas as pd
from models.anomaly_model import AnomalyDetector

df = pd.read_csv("../data/processed/engineered_dataset.csv")

detector = AnomalyDetector()
detector.fit(df)

detector.save("../outputs/models/anomaly_model.pkl")

print("Model trained and saved")