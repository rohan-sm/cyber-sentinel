import pandas as pd

from models.hybrid_model import HybridDetector
from sklearn.metrics import classification_report

# Load data
df = pd.read_csv("../data/processed/engineered_dataset.csv")

# Load hybrid model
hybrid = HybridDetector.load("../outputs/models/hybrid_model.pkl")

# Predict
results = hybrid.predict(df)

print(results[
    ['attack_type', 'anomaly_pred', 'attack_pred', 'final_prediction']
].head())


print("\n========== FINAL HYBRID REPORT ==========\n")
print(
    classification_report(
        results['attack_type'],
        results['final_prediction'],
        zero_division=0
    )
)
