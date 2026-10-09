from pathlib import Path
import sys
import joblib
import pandas as pd

# --------------------------------------------------
# PATH SETUP
# --------------------------------------------------

CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent.parent

sys.path.insert(0, str(PROJECT_ROOT))

from backend.ml.predict import extract_features


# --------------------------------------------------
# LOAD MODEL
# --------------------------------------------------

MODEL_PATH = CURRENT_DIR / "phishhunt_model.pkl"

model = joblib.load(MODEL_PATH)

print("=" * 70)
print("PHISHHUNT ML MODEL DIAGNOSTIC")
print("=" * 70)

print("\nModel classes:")
print(model.classes_)

print("\nNumber of features:")
print(len(model.feature_names_in_))

print("\nFeatures:")
for i, feature in enumerate(model.feature_names_in_):
    print(f"{i + 1:2}. {feature}")


# --------------------------------------------------
# FEATURE IMPORTANCE
# --------------------------------------------------

print("\n" + "=" * 70)
print("TOP FEATURE IMPORTANCES")
print("=" * 70)

importance_df = pd.DataFrame({
    "feature": model.feature_names_in_,
    "importance": model.feature_importances_
})

importance_df = importance_df.sort_values(
    by="importance",
    ascending=False
)

for _, row in importance_df.head(15).iterrows():
    print(
        f"{row['feature']:<30} "
        f"{row['importance']:.6f}"
    )


# --------------------------------------------------
# TEST URLS
# --------------------------------------------------

test_urls = [
    "https://www.google.com",
    "https://www.microsoft.com",
    "https://github.com",
    "https://www.wikipedia.org",
    "https://web.whatsapp.com",
]


# --------------------------------------------------
# ANALYZE EACH URL
# --------------------------------------------------

for url in test_urls:

    print("\n" + "=" * 70)
    print(f"URL: {url}")
    print("=" * 70)

    features = extract_features(url)

    X = pd.DataFrame(
        [features],
        columns=model.feature_names_in_
    )

    prediction = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]

    print("\nPrediction:")
    print(prediction)

    print("\nClass probabilities:")

    for class_label, probability in zip(
        model.classes_,
        probabilities
    ):
        label_name = (
            "LEGITIMATE"
            if class_label == 0
            else "PHISHING"
        )

        print(
            f"{label_name:<12} "
            f"{probability * 100:.2f}%"
        )

    print("\nFeatures:")

    for feature in model.feature_names_in_:
        print(
            f"{feature:<30} = {features[feature]}"
        )


print("\n" + "=" * 70)
print("DIAGNOSTIC COMPLETE")
print("=" * 70)