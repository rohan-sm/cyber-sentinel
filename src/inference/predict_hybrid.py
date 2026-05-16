import pandas as pd

from models.classification_model import AttackClassifier
from sklearn.metrics import classification_report
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Load data
df = pd.read_csv(BASE_DIR / "data" / "engineered_dataset.csv")

# Load classifier model
classifier = AttackClassifier()
classifier.load(str(BASE_DIR / "outputs" / "models" / "classifier.pkl"))

# Predict
df['final_prediction'] = classifier.predict(df)

print(df[
    ['attack_type', 'final_prediction']
].head())

print("\n========== FINAL CLASSIFIER REPORT ==========\n")
print(
    classification_report(
        df['attack_type'],
        df['final_prediction'],
        zero_division=0
    )
)
