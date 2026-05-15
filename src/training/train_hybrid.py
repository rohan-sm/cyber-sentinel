from models.hybrid_model import HybridDetector

hybrid = HybridDetector()

# Load existing trained models
hybrid.load_models(
    "../outputs/models/anomaly_model.pkl",
    "../outputs/models/classifier.pkl"
)

# Save complete hybrid model
hybrid.save("../outputs/models/hybrid_model.pkl")

print("Hybrid model saved")