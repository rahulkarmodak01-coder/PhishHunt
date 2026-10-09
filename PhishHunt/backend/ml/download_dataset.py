from ucimlrepo import fetch_ucirepo
import pandas as pd

print("Downloading PhiUSIIL dataset...")

dataset = fetch_ucirepo(id=967)

data = dataset.data.features.copy()
target = dataset.data.targets.copy()

print("Dataset downloaded successfully!")
print("Total rows:", len(data))

urls = data["URL"]
labels = target["label"]

output = pd.DataFrame({
    "url": urls,
    "label": labels.map({1: 0, 0: 1})
})

output = output[["url", "label"]]

output.to_csv(
    "dataset/urls_large.csv",
    index=False
)

print("\nDataset saved successfully!")
print("File: dataset/urls_large.csv")

print("\nLabel counts:")
print(output["label"].value_counts())

print("\nFirst 5 rows:")
print(output.head())