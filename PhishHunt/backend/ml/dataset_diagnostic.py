from pathlib import Path
import pandas as pd


BASE_DIR = Path(__file__).resolve().parents[2]

DATASET_PATH = (
    BASE_DIR.parent
    / "dataset"
    / "urls_large.csv"
)


print("=" * 70)
print("PHISHHUNT RAW DATASET LABEL VERIFICATION")
print("=" * 70)

print()
print("Loading dataset...")

data = pd.read_csv(DATASET_PATH)

print("Dataset loaded successfully!")

print()
print(f"Total rows: {len(data)}")


# ============================================================
# RAW LABEL COUNTS
# ============================================================

print()
print("=" * 70)
print("RAW LABEL COUNTS")
print("=" * 70)

print()

print(
    data["label"].value_counts()
)


# ============================================================
# RAW LABEL 0
# ============================================================

print()
print("=" * 70)
print("RAW LABEL 0 - SAMPLE URLS")
print("=" * 70)

label_0 = data[
    data["label"] == 0
]

print()
print(
    f"Total label 0 rows: {len(label_0)}"
)

print()

for url in label_0["url"].head(30):

    print(
        f"  {url}"
    )


# ============================================================
# RAW LABEL 1
# ============================================================

print()
print("=" * 70)
print("RAW LABEL 1 - SAMPLE URLS")
print("=" * 70)

label_1 = data[
    data["label"] == 1
]

print()
print(
    f"Total label 1 rows: {len(label_1)}"
)

print()

for url in label_1["url"].head(30):

    print(
        f"  {url}"
    )


# ============================================================
# RANDOM SAMPLES
# ============================================================

print()
print("=" * 70)
print("RANDOM SAMPLE - RAW LABEL 0")
print("=" * 70)

print()

for url in label_0.sample(
    n=20,
    random_state=42
)["url"]:

    print(
        f"  {url}"
    )


print()
print("=" * 70)
print("RANDOM SAMPLE - RAW LABEL 1")
print("=" * 70)

print()

for url in label_1.sample(
    n=20,
    random_state=42
)["url"]:

    print(
        f"  {url}"
    )


# ============================================================
# END
# ============================================================

print()
print("=" * 70)
print("RAW LABEL VERIFICATION COMPLETE")
print("=" * 70)