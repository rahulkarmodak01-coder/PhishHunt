from pathlib import Path
import re
import math

import pandas as pd
import numpy as np
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)


# ============================================================
# PHISHHUNT ML MODEL TRAINING
# ============================================================


BASE_DIR = Path(__file__).resolve().parents[2]

DATASET_PATH = (
    BASE_DIR.parent
    / "dataset"
    / "urls_large.csv"
)

MODEL_PATH = (
    Path(__file__).resolve().parent
    / "phishhunt_model.pkl"
)


# ============================================================
# FEATURE DEFINITIONS
# ============================================================

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "dot_count",
    "hyphen_count",
    "underscore_count",
    "question_count",
    "equal_count",
    "at_count",
    "digit_count",
    "has_ip",
    "has_at_symbol",
    "has_double_slash",
    "subdomain_count",
    "has_punycode",
    "has_suspicious_word",
    "query_length",
    "fragment_length",
    "digit_ratio",
    "letter_ratio",
    "special_ratio",
    "url_entropy",
    "suspicious_word_count",
    "brand_count",
    "suspicious_tld",
    "path_depth",
    "encoded_character_count",
    "repeated_character",
    "hostname_has_digit",
    "hostname_has_hyphen",
    "hostname_has_underscore",
]


SUSPICIOUS_WORDS = [
    "login",
    "log-in",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "update",
    "password",
    "passwd",
    "payment",
    "bank",
    "wallet",
    "confirm",
    "authentication",
    "authorize",
    "billing",
    "recover",
    "suspended",
    "unlock",
]


BRAND_NAMES = [
    "google",
    "microsoft",
    "apple",
    "amazon",
    "paypal",
    "facebook",
    "instagram",
    "linkedin",
    "netflix",
    "github",
    "whatsapp",
    "wikipedia",
    "bank",
]


SUSPICIOUS_TLDS = [
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".top",
    ".xyz",
    ".click",
    ".work",
    ".zip",
    ".mov",
]


def is_ip_address(hostname):

    import ipaddress

    try:
        ipaddress.ip_address(hostname)
        return 1

    except ValueError:
        return 0


def calculate_entropy(text):

    if not text:
        return 0.0

    length = len(text)

    frequencies = {
        char: text.count(char)
        for char in set(text)
    }

    entropy = 0.0

    for count in frequencies.values():

        probability = count / length

        entropy -= (
            probability
            * math.log2(probability)
        )

    return entropy


def extract_features(url):

    if not isinstance(url, str):
        url = str(url)

    url = url.strip()

    # --------------------------------------------------------
    # Normalize URL
    # --------------------------------------------------------

    normalized_url = url

    if not re.match(
     r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
    normalized_url
    ):

     normalized_url = (
        "http://" + normalized_url
    )

    from urllib.parse import urlparse

    parsed = urlparse(normalized_url)

    hostname = parsed.hostname or ""

    hostname_lower = hostname.lower()

    path = parsed.path or ""

    query = parsed.query or ""

    fragment = parsed.fragment or ""

# --------------------------------------------------------
# Canonicalize ONLY a bare root slash
#
# https://example.com/
# becomes equivalent to:
# https://example.com
#
# But paths such as:
# /login/
# /account/
# /verify/
# remain unchanged.
# --------------------------------------------------------

    feature_url = url

    if (
     parsed.path == "/"
     and not parsed.query
     and not parsed.fragment
    ):
     feature_url = url[:-1]

    # --------------------------------------------------------
    # Basic URL features
    # --------------------------------------------------------

    url_length = len(feature_url)

    hostname_length = len(hostname)

    path = parsed.path

# Treat the root "/" as an empty path.
    if path == "/":
     path = ""

    path_length = len(path)

    dot_count = feature_url.count(".")
    hyphen_count = feature_url.count("-")
    underscore_count = feature_url.count("_")
    question_count = feature_url.count("?")
    equal_count = feature_url.count("=")
    at_count = feature_url.count("@")

    digit_count = sum(
     char.isdigit()
     for char in feature_url
    )
    # --------------------------------------------------------
    # IP
    # --------------------------------------------------------

    has_ip = is_ip_address(hostname)

    # --------------------------------------------------------
    # @ symbol
    # --------------------------------------------------------

    has_at_symbol = int(
        "@" in url
    )

    # --------------------------------------------------------
    # Double slash
    #
    # Only count // inside the PATH.
    # Do NOT count https:// or http://.
    # --------------------------------------------------------

    has_double_slash = int(
        "//" in path
    )

    # --------------------------------------------------------
    # Subdomains
    # --------------------------------------------------------

    subdomain_count = max(
        0,
        hostname.count(".") - 1
    )

    # --------------------------------------------------------
    # Punycode
    # --------------------------------------------------------

    has_punycode = int(
        "xn--" in hostname_lower
    )

    # --------------------------------------------------------
    # Suspicious words
    # --------------------------------------------------------

    url_lower = url.lower()

    found_suspicious_words = []

    for word in SUSPICIOUS_WORDS:

        if word in url_lower:

            found_suspicious_words.append(
                word
            )

    suspicious_word_count = len(
        found_suspicious_words
    )

    has_suspicious_word = int(
        suspicious_word_count > 0
    )

    # --------------------------------------------------------
    # Query / fragment
    # --------------------------------------------------------

    query_length = len(query)

    fragment_length = len(fragment)

    # --------------------------------------------------------
    # Character ratios
    # --------------------------------------------------------

    if url_length > 0:

        digit_ratio = (
            digit_count / url_length
        )

        letter_count = sum(
            char.isalpha()
            for char in feature_url
        )

        letter_ratio = (
            letter_count / url_length
        )

        special_count = sum(
            not char.isalnum()
            for char in feature_url
        )

        special_ratio = (
            special_count / url_length
        )

    else:

        digit_ratio = 0.0

        letter_ratio = 0.0

        special_ratio = 0.0

    # --------------------------------------------------------
    # Entropy
    # --------------------------------------------------------

    url_entropy = calculate_entropy(feature_url)

    # --------------------------------------------------------
    # Brand count
    # --------------------------------------------------------

    found_brands = []

    for brand in BRAND_NAMES:

        if brand in url_lower:

            found_brands.append(
                brand
            )

    brand_count = len(
        found_brands
    )

    # --------------------------------------------------------
    # Suspicious TLD
    # --------------------------------------------------------

    suspicious_tld = int(
        any(
            hostname_lower.endswith(tld)
            for tld in SUSPICIOUS_TLDS
        )
    )

    # --------------------------------------------------------
    # Path depth
    # --------------------------------------------------------

    path_parts = [
        part
        for part in path.split("/")
        if part
    ]

    path_depth = len(path_parts)

    # --------------------------------------------------------
    # Encoded characters
    # --------------------------------------------------------

    encoded_character_count = len(
        re.findall(
            r"%[0-9a-fA-F]{2}",
            url
        )
    )

    # --------------------------------------------------------
    # Repeated character
    #
    # Ignore www.
    # --------------------------------------------------------

    hostname_repeat_check = (
        hostname_lower
    )

    if hostname_repeat_check.startswith(
        "www."
    ):

        hostname_repeat_check = (
            hostname_repeat_check[4:]
        )

    repeated_character = int(
        bool(
            re.search(
                r"(.)\1\1",
                hostname_repeat_check
            )
        )
    )

    # --------------------------------------------------------
    # Hostname indicators
    # --------------------------------------------------------

    hostname_digit_count = sum(
        char.isdigit()
        for char in hostname
    )

    hostname_has_digit = int(
        hostname_digit_count > 0
    )

    hostname_has_hyphen = int(
        "-" in hostname
    )

    hostname_has_underscore = int(
        "_" in hostname
    )

    # --------------------------------------------------------
    # FEATURES
    #
    # 31 TOTAL
    #
    # Removed:
    # uses_https
    # slash_count
    # --------------------------------------------------------

    features = {

        "url_length":
            url_length,

        "hostname_length":
            hostname_length,

        "path_length":
            path_length,

        "dot_count":
            dot_count,

        "hyphen_count":
            hyphen_count,

        "underscore_count":
            underscore_count,

        "question_count":
            question_count,

        "equal_count":
            equal_count,

        "at_count":
            at_count,

        "digit_count":
            digit_count,

        "has_ip":
            has_ip,

        "has_at_symbol":
            has_at_symbol,

        "has_double_slash":
            has_double_slash,

        "subdomain_count":
            subdomain_count,

        "has_punycode":
            has_punycode,

        "has_suspicious_word":
            has_suspicious_word,

        "query_length":
            query_length,

        "fragment_length":
            fragment_length,

        "digit_ratio":
            digit_ratio,

        "letter_ratio":
            letter_ratio,

        "special_ratio":
            special_ratio,

        "url_entropy":
            url_entropy,

        "suspicious_word_count":
            suspicious_word_count,

        "brand_count":
            brand_count,

        "suspicious_tld":
            suspicious_tld,

        "path_depth":
            path_depth,

        "encoded_character_count":
            encoded_character_count,

        "repeated_character":
            repeated_character,

        "hostname_has_digit":
            hostname_has_digit,

        "hostname_has_hyphen":
            hostname_has_hyphen,

        "hostname_has_underscore":
            hostname_has_underscore,
    }

    return features


# ============================================================
# MAIN TRAINING
# ============================================================

print("=" * 60)
print("       PHISHHUNT MODEL TRAINING - 31 FEATURES")
print("=" * 60)


# ------------------------------------------------------------
# LOAD DATASET
# ------------------------------------------------------------

print()
print("Loading large dataset...")

data = pd.read_csv(DATASET_PATH)

print("Dataset loaded successfully!")

print(
    f"Total URLs: {len(data)}"
)


# ------------------------------------------------------------
# SHOW ORIGINAL LABELS
# ------------------------------------------------------------

print()
print("Original label distribution:")

print(
    data["label"].value_counts()
)


# ------------------------------------------------------------
# VERIFY REQUIRED COLUMNS
# ------------------------------------------------------------

if "url" not in data.columns:

    raise ValueError(
        "Dataset does not contain a 'url' column."
    )

if "label" not in data.columns:

    raise ValueError(
        "Dataset does not contain a 'label' column."
    )


# ------------------------------------------------------------
# EXTRACT FEATURES
# ------------------------------------------------------------

print()
print("Extracting URL features...")
print("This may take some time...")


feature_rows = []

total = len(data)

for index, url in enumerate(
    data["url"],
    start=1
):

    feature_rows.append(
        extract_features(url)
    )

    if index % 25000 == 0:

        print(
            f"Processed: {index} of {total}"
        )


X = pd.DataFrame(
    feature_rows,
    columns=FEATURE_NAMES
)


# ------------------------------------------------------------
# LABEL MAPPING
#
# UCI PhiUSIIL:
# 1 = legitimate
# 0 = phishing
#
# PhishHunt:
# 0 = legitimate
# 1 = phishing
# ------------------------------------------------------------

y = data["label"]


# ------------------------------------------------------------
# CHECK LABELS
# ------------------------------------------------------------

if y.isna().any():

    raise ValueError(
        "Unexpected label values found."
    )


print()
print("PhishHunt label distribution:")

print(
    y.value_counts()
)


# ------------------------------------------------------------
# FEATURE VALIDATION
# ------------------------------------------------------------

print()
print("Feature extraction completed!")

print(
    f"Number of features: {X.shape[1]}"
)

print(
    f"Number of samples: {X.shape[0]}"
)


if list(X.columns) != FEATURE_NAMES:

    raise ValueError(
        "Feature order does not match FEATURE_NAMES."
    )


if X.shape[1] != 31:

    raise ValueError(
        f"Expected 31 features, got {X.shape[1]}"
    )


# ------------------------------------------------------------
# TRAIN / TEST SPLIT
# ------------------------------------------------------------

print()
print("Splitting dataset...")

X_train, X_test, y_train, y_test = (
    train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )
)


print(
    f"Training URLs: {len(X_train)}"
)

print(
    f"Testing URLs: {len(X_test)}"
)


# ------------------------------------------------------------
# TRAIN RANDOM FOREST
# ------------------------------------------------------------

print()
print("Training Random Forest model...")

model = RandomForestClassifier(

    n_estimators=100,

    random_state=42,

    n_jobs=-1

)


model.fit(
    X_train,
    y_train
)


print(
    "Model training completed!"
)


# ------------------------------------------------------------
# TEST MODEL
# ------------------------------------------------------------

print()
print("Testing model...")


y_pred = model.predict(
    X_test
)


accuracy = accuracy_score(
    y_test,
    y_pred
)


print()
print("=" * 60)
print("          PHISHHUNT MODEL RESULTS")
print("=" * 60)


print()
print(
    f"Accuracy: {accuracy * 100:.2f} %"
)


# ------------------------------------------------------------
# CLASSIFICATION REPORT
# ------------------------------------------------------------

print()
print("Classification Report:")

print(
    classification_report(
        y_test,
        y_pred,
        target_names=[
            "LEGITIMATE",
            "PHISHING"
        ]
    )
)


# ------------------------------------------------------------
# CONFUSION MATRIX
# ------------------------------------------------------------

cm = confusion_matrix(
    y_test,
    y_pred
)


print()
print("Confusion Matrix:")

print(cm)


print()
print("Matrix format:")
print(
    "[[True Negative, False Positive],"
)
print(
    " [False Negative, True Positive]]"
)


# ------------------------------------------------------------
# FEATURE IMPORTANCE
# ------------------------------------------------------------

print()
print("=" * 60)
print("        TOP FEATURE IMPORTANCES")
print("=" * 60)


importance_df = pd.DataFrame({

    "feature":
        FEATURE_NAMES,

    "importance":
        model.feature_importances_

})


importance_df = (
    importance_df
    .sort_values(
        "importance",
        ascending=False
    )
)


print()

for _, row in (
    importance_df.head(15).iterrows()
):

    print(
        f"{row['feature']:<30}"
        f"{row['importance']:.6f}"
    )


# ------------------------------------------------------------
# SAVE MODEL
# ------------------------------------------------------------

print()
print("Saving model...")


joblib.dump(
    model,
    MODEL_PATH
)


print()
print("=" * 60)
print("       MODEL SAVED SUCCESSFULLY")
print("=" * 60)

print()
print(
    f"Model file: {MODEL_PATH}"
)

print()
print(
    "Feature count: 31"
)

print(
    "Removed features:"
)

print(
    " - uses_https"
)

print(
    " - slash_count"
)