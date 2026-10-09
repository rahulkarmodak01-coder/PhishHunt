from pathlib import Path
import joblib
import pandas as pd

from backend.ml.predict import extract_features


# ============================================================
# PHISHHUNT FEATURE ABLATION DIAGNOSTIC
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "phishhunt_model.pkl"

TEST_URLS = [
    "https://www.google.com",
    "https://www.microsoft.com",
    "https://github.com",
    "https://www.wikipedia.org",
    "https://web.whatsapp.com",
]


def predict_with_features(model, url, removed_features=None):
    """
    Predict a URL after setting selected features to neutral values.
    This does NOT retrain the model.
    """

    removed_features = removed_features or []

    features = extract_features(url)

    for feature in removed_features:
        if feature in features:
            features[feature] = 0

    X = pd.DataFrame([features])

    # Make sure feature order is exactly the same as training.
    if hasattr(model, "feature_names_in_"):
        X = X.reindex(columns=model.feature_names_in_)

    prediction = int(model.predict(X)[0])
    probabilities = model.predict_proba(X)[0]

    class_probabilities = {
        int(cls): float(prob)
        for cls, prob in zip(model.classes_, probabilities)
    }

    return prediction, class_probabilities


def print_results(title, model, removed_features):
    print()
    print("=" * 70)
    print(title)
    print("=" * 70)

    if removed_features:
        print("Neutralized features:")
        for feature in removed_features:
            print(f"  - {feature}")
    else:
        print("Neutralized features: NONE")

    print()

    for url in TEST_URLS:

        prediction, probabilities = predict_with_features(
            model,
            url,
            removed_features
        )

        legitimate_probability = probabilities.get(0, 0) * 100
        phishing_probability = probabilities.get(1, 0) * 100

        result = "PHISHING" if prediction == 1 else "LEGITIMATE"

        print(f"URL: {url}")
        print(f"Prediction: {result}")
        print(f"LEGITIMATE: {legitimate_probability:.2f}%")
        print(f"PHISHING:   {phishing_probability:.2f}%")
        print()


def main():

    print("=" * 70)
    print("PHISHHUNT FEATURE ABLATION DIAGNOSTIC")
    print("=" * 70)

    print()
    print("Loading model...")

    model = joblib.load(MODEL_PATH)

    print("Model loaded successfully.")

    print()
    print("Model classes:")
    print(model.classes_)

    print()
    print("Number of features:")
    print(len(model.feature_names_in_))

    # --------------------------------------------------------
    # TEST 1: CURRENT MODEL
    # --------------------------------------------------------

    print_results(
        "TEST 1 - CURRENT MODEL",
        model,
        []
    )

    # --------------------------------------------------------
    # TEST 2: REMOVE HTTPS EFFECT
    # --------------------------------------------------------

    print_results(
        "TEST 2 - NEUTRALIZE uses_https",
        model,
        ["uses_https"]
    )

    # --------------------------------------------------------
    # TEST 3: REMOVE SLASH COUNT EFFECT
    # --------------------------------------------------------

    print_results(
        "TEST 3 - NEUTRALIZE slash_count",
        model,
        ["slash_count"]
    )

    # --------------------------------------------------------
    # TEST 4: REMOVE BOTH
    # --------------------------------------------------------

    print_results(
        "TEST 4 - NEUTRALIZE uses_https + slash_count",
        model,
        [
            "uses_https",
            "slash_count"
        ]
    )

    # --------------------------------------------------------
    # TEST 5: REMOVE HTTPS + SLASH + PATH
    # --------------------------------------------------------

    print_results(
        "TEST 5 - NEUTRALIZE uses_https + slash_count + path_length",
        model,
        [
            "uses_https",
            "slash_count",
            "path_length"
        ]
    )

    print()
    print("=" * 70)
    print("DIAGNOSTIC COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()