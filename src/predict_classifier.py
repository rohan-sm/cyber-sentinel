import pandas as pd
from classification_model import AttackClassifier

df = pd.read_csv("../data/processed/engineered_dataset.csv")

clf = AttackClassifier()
clf.load("../outputs/models/classifier.pkl")

preds = clf.predict(df)

df['attack_pred'] = preds

print(df[['attack_type', 'attack_pred']].head())
print(df['attack_pred'].value_counts())