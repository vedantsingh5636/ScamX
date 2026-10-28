"""Data acquisition, deduplication, and stratified train/val/test splitting for ScamShield-AI.
Prevents data leakage by deduplicating before splitting and enforcing strict stratification.
"""

from __future__ import annotations

import io
import os
from pathlib import Path
import urllib.request
import zipfile
import pandas as pd
from sklearn.model_selection import train_test_split

UCI_DATASET_URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"


def download_dataset(raw_dir: Path) -> Path:
    """Download and extract SMS Spam Collection dataset if not already present."""
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_data_file = raw_dir / "SMSSpamCollection"
    zip_path = raw_dir / "sms_spam_collection.zip"

    if not raw_data_file.exists():
        print(f"Downloading dataset from {UCI_DATASET_URL}...")
        urllib.request.urlretrieve(UCI_DATASET_URL, zip_path)
        print("Extracting zip archive...")
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(raw_dir)
        print(f"Extracted to {raw_dir}")
    else:
        print(f"Raw data file already exists at {raw_data_file}")

    if not raw_data_file.exists():
        raise FileNotFoundError(f"Expected extracted file not found: {raw_data_file}")

    return raw_data_file


def clean_text(text: str) -> str:
    """Basic text cleanup: strip leading/trailing spaces and control characters."""
    if not isinstance(text, str):
        return ""
    # Normalize excessive internal whitespace
    return " ".join(text.strip().split())


def load_and_preprocess(raw_file: Path) -> tuple[pd.DataFrame, dict]:
    """Load raw TSV, standardize binary labels, and deduplicate to prevent leakage."""
    # SMS Spam Collection has two tab-separated columns: label and message
    df = pd.read_csv(
        raw_file,
        sep="\t",
        header=None,
        names=["raw_label", "text"],
        quoting=3,  # QUOTE_NONE
        encoding="utf-8",
        on_bad_lines="skip",
    )

    initial_count = len(df)
    df["raw_label"] = df["raw_label"].astype(str).str.strip().str.lower()
    df["text"] = df["text"].apply(clean_text)

    # Filter for valid labels ('ham' or 'spam') and non-empty text
    df = df[df["raw_label"].isin(["ham", "spam"])].copy()
    df = df[df["text"].str.len() > 0].copy()
    valid_count = len(df)

    # Map labels to binary: 0 = legitimate (ham), 1 = scam (spam)
    df["label"] = df["raw_label"].map({"ham": 0, "spam": 1}).astype(int)
    df["label_name"] = df["raw_label"].map({"ham": "legitimate", "spam": "scam"})

    # DEDUPLICATION BEFORE SPLITTING (Prevents data leakage across splits)
    duplicates_count = df.duplicated(subset=["text"]).sum()
    df_dedup = df.drop_duplicates(subset=["text"], keep="first").copy().reset_index(drop=True)
    dedup_count = len(df_dedup)

    stats = {
        "initial_raw_records": initial_count,
        "valid_labeled_records": valid_count,
        "duplicate_text_records_removed": int(duplicates_count),
        "deduplicated_records": dedup_count,
        "legitimate_count": int((df_dedup["label"] == 0).sum()),
        "scam_count": int((df_dedup["label"] == 1).sum()),
        "scam_prevalence_pct": round(float((df_dedup["label"] == 1).mean() * 100), 2),
    }

    print("Data Preprocessing Summary:")
    for k, v in stats.items():
        print(f"  {k}: {v}")

    return df_dedup, stats


def create_stratified_splits(
    df: pd.DataFrame,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    random_state: int = 42,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Perform stratified split into train, validation, and test sets."""
    assert round(train_ratio + val_ratio + test_ratio, 4) == 1.0, "Split ratios must sum to 1.0"

    temp_ratio = val_ratio + test_ratio
    train_df, temp_df = train_test_split(
        df,
        test_size=temp_ratio,
        stratify=df["label"],
        random_state=random_state,
    )

    test_share_of_temp = test_ratio / temp_ratio
    val_df, test_df = train_test_split(
        temp_df,
        test_size=test_share_of_temp,
        stratify=temp_df["label"],
        random_state=random_state,
    )

    return (
        train_df.reset_index(drop=True),
        val_df.reset_index(drop=True),
        test_df.reset_index(drop=True),
    )


def save_splits(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
    processed_dir: Path,
) -> dict:
    """Save processed splits to CSV files."""
    processed_dir.mkdir(parents=True, exist_ok=True)

    cols = ["text", "label", "label_name"]
    train_path = processed_dir / "train.csv"
    val_path = processed_dir / "val.csv"
    test_path = processed_dir / "test.csv"

    train_df[cols].to_csv(train_path, index=False)
    val_df[cols].to_csv(val_path, index=False)
    test_df[cols].to_csv(test_path, index=False)

    split_summary = {
        "train": {
            "path": str(train_path),
            "total": len(train_df),
            "legitimate": int((train_df["label"] == 0).sum()),
            "scam": int((train_df["label"] == 1).sum()),
            "scam_pct": round(float((train_df["label"] == 1).mean() * 100), 2),
        },
        "val": {
            "path": str(val_path),
            "total": len(val_df),
            "legitimate": int((val_df["label"] == 0).sum()),
            "scam": int((val_df["label"] == 1).sum()),
            "scam_pct": round(float((val_df["label"] == 1).mean() * 100), 2),
        },
        "test": {
            "path": str(test_path),
            "total": len(test_df),
            "legitimate": int((test_df["label"] == 0).sum()),
            "scam": int((test_df["label"] == 1).sum()),
            "scam_pct": round(float((test_df["label"] == 1).mean() * 100), 2),
        },
    }
    return split_summary


def write_manifest(manifest_path: Path, stats: dict, split_summary: dict) -> None:
    """Write ML dataset manifest detailing source, license, hygiene, and splits."""
    content = f"""# Dataset Manifest: SMS Spam Collection (ScamShield-AI Baseline)

## 1. Provenance & Attribution
- **Dataset Name:** SMS Spam Collection
- **Source Repository:** UCI Machine Learning Repository
- **URL:** {UCI_DATASET_URL}
- **Original Authors & Citation:**
  Almeida, T.A., Gómez Hidalgo, J.M., Yamakami, A. *Contributions to the Study of SMS Spam Filtering: New Collection and Results.* Proceedings of the 2011 ACM Symposium on Document Engineering (DOCENG'11), Mountain View, CA, USA, 2011.
- **License / Terms of Use:** Publicly available for scientific research, academic, and evaluation purposes with citation.

## 2. Label Mapping (Binary)
- `ham` -> `legitimate` (Numeric label: `0`)
- `spam` -> `scam` (Numeric label: `1`)

## 3. Data Hygiene & Leakage Prevention
- **Deduplication:** Deduplicated on raw text BEFORE splitting to guarantee zero message overlap between train, validation, and test splits.
- **Initial records in raw archive:** {stats['initial_raw_records']}
- **Valid labeled records:** {stats['valid_labeled_records']}
- **Duplicate messages removed:** {stats['duplicate_text_records_removed']}
- **Unique messages retained:** {stats['deduplicated_records']}
- **Overall Class Balance:**
  - Legitimate (`ham`): {stats['legitimate_count']} ({100 - stats['scam_prevalence_pct']}%)
  - Scam (`spam`): {stats['scam_count']} ({stats['scam_prevalence_pct']}%)

## 4. Stratified Split Breakdown (70% Train / 15% Validation / 15% Test)
- **Random Seed:** 42

| Split | Total Samples | Legitimate (0) | Scam (1) | Scam Prevalence |
|---|---|---|---|---|
| **Train (70%)** | {split_summary['train']['total']} | {split_summary['train']['legitimate']} | {split_summary['train']['scam']} | {split_summary['train']['scam_pct']}% |
| **Validation (15%)** | {split_summary['val']['total']} | {split_summary['val']['legitimate']} | {split_summary['val']['scam']} | {split_summary['val']['scam_pct']}% |
| **Test (15%)** | {split_summary['test']['total']} | {split_summary['test']['legitimate']} | {split_summary['test']['scam']} | {split_summary['test']['scam_pct']}% |

## 5. Storage Locations
- Raw file: `ml/data/raw/SMSSpamCollection`
- Train split: `ml/data/processed/train.csv`
- Validation split: `ml/data/processed/val.csv`
- Held-out Test split: `ml/data/processed/test.csv`
"""
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(content, encoding="utf-8")
    print(f"Manifest written to {manifest_path}")


def main():
    base_dir = Path(__file__).resolve().parent.parent
    raw_dir = base_dir / "data" / "raw"
    processed_dir = base_dir / "data" / "processed"
    manifest_path = base_dir / "data" / "MANIFEST.md"

    raw_file = download_dataset(raw_dir)
    df, stats = load_and_preprocess(raw_file)
    train_df, val_df, test_df = create_stratified_splits(df)
    split_summary = save_splits(train_df, val_df, test_df, processed_dir)
    write_manifest(manifest_path, stats, split_summary)
    print("Preprocessing completed successfully.")


if __name__ == "__main__":
    main()
