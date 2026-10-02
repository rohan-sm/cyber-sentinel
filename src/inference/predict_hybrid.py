import sys
from pathlib import Path

import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(BASE_DIR / "src"))

from models.hybrid_model import HybridDetector

DATA_PATH = BASE_DIR / "data" / "processed" / "engineered_dataset.csv"
MODEL_PATH = BASE_DIR / "outputs" / "models" / "hybrid_model.pkl"

df = pd.read_csv(DATA_PATH)

hybrid = HybridDetector.load(str(MODEL_PATH))

result = hybrid.predict(df.copy())

# ======================================
# STAGE 1 — ANOMALY DETECTION
# ======================================

truth_attack = (df["is_attack"] == 1).astype(int)

tn, fp, fn, tp = confusion_matrix(
    truth_attack, result["anomaly_pred"], labels=[0, 1]
).ravel()

print("========== STAGE 1: ISOLATION FOREST ==========\n")
print(f"Flagged as anomaly : {result['anomaly_pred'].sum()} / {len(result)} "
      f"({result['anomaly_pred'].mean() * 100:.1f}%)")
print(f"Attack recall     : {tp / (tp + fn):.4f}")
print(f"Attack precision  : {tp / (tp + fp):.4f}")
print(f"False positives   : {fp} of {tn + fp} normal rows "
      f"(FPR {fp / (fp + tn):.4f})")
print(f"Attacks missed    : {fn}")

# ======================================
# STAGE 2 — CASCADE END TO END
# ======================================

y_true = result["attack_type"]
y_pred = result["final_prediction"]

print("\n========== CASCADE END-TO-END ==========\n")
print(classification_report(y_true, y_pred, zero_division=0))

normal = y_true == "none"
false_positives = int((normal & (y_pred != "none")).sum())

print(f"\nOverall accuracy : {(y_true == y_pred).mean():.4f}")
print(f"False positives  : {false_positives} of {int(normal.sum())} normal rows")
print("\nPer-class recall :")
for attack_type in ["crypto", "ddos", "portscan"]:
    mask = y_true == attack_type
    print(f"  {attack_type:9s} {(y_pred[mask] == attack_type).mean():.4f} "
          f"(n={int(mask.sum())})")

print("\n========== PREDICTED LABEL DISTRIBUTION ==========\n")
print(y_pred.value_counts().to_string())