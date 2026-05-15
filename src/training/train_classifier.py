import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from models.classification_model import AttackClassifier

# Load
df = pd.read_csv("../data/processed/engineered_dataset.csv")

# Split features/target
df_attack = df[df['attack_type'] != 'none']

X = df_attack.copy()
y = df_attack['attack_type']

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# Train
clf = AttackClassifier()
clf.fit(X_train, y_train)

# Evaluate
y_pred = clf.predict(X_test)

print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))

# Save model
clf.save("../outputs/models/classifier.pkl")

print("\nClassifier trained and saved (production-ready)")