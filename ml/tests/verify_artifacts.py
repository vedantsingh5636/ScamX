"""Independent verification script to check dataset, splits, and trained model artifact.
Read-only: Does not modify or retrain anything.
"""

import os
from pathlib import Path
import joblib
import pandas as pd
from sklearn.utils.validation import check_is_fitted

ROOT = Path(__file__).resolve().parent.parent.parent
ML_DIR = ROOT / "ml"
RAW_DIR = ML_DIR / "data" / "raw"
PROCESSED_DIR = ML_DIR / "data" / "processed"
MODEL_PATH = ML_DIR / "models" / "model.joblib"


def verify_raw_dataset():
    print("=== 1 & 2. RAW DATASET VERIFICATION ===")
    if not RAW_DIR.exists():
        print(f"[FAIL] Raw directory not found: {RAW_DIR}")
        return

    raw_files = list(RAW_DIR.iterdir())
    print(f"Directory: {RAW_DIR}")
    for f in raw_files:
        size_bytes = f.stat().st_size
        size_kb = size_bytes / 1024
        print(f"  - File: {f.name} | Size: {size_bytes} bytes ({size_kb:.2f} KB)")

    raw_data_file = RAW_DIR / "SMSSpamCollection"
    if raw_data_file.exists():
        with open(raw_data_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        print(f"\n[PASS] SMSSpamCollection exists.")
        print(f"  Total raw lines: {len(lines)}")
        
        # Load through pandas to count parsed records
        df_raw = pd.read_csv(
            raw_data_file,
            sep="\t",
            header=None,
            names=["label", "text"],
            quoting=3,
            encoding="utf-8",
            on_bad_lines="skip",
        )
        print(f"  Total parsed records: {len(df_raw)}")
        print(f"  Label distribution in raw data:\n{df_raw['label'].value_counts().to_string()}")
        print(f"\n  First 3 raw samples:")
        for idx, row in df_raw.head(3).iterrows():
            print(f"    [{row['label']}] {repr(row['text'][:80])}")
    else:
        print("[FAIL] SMSSpamCollection does not exist!")


def verify_processed_splits():
    print("\n=== 4. PROCESSED SPLITS VERIFICATION ===")
    for split_name in ["train", "val", "test"]:
        split_file = PROCESSED_DIR / f"{split_name}.csv"
        if not split_file.exists():
            print(f"[FAIL] {split_name}.csv does not exist!")
            continue

        df = pd.read_csv(split_file)
        size_bytes = split_file.stat().st_size
        legit = (df["label"] == 0).sum()
        scam = (df["label"] == 1).sum()
        total = len(df)
        print(f"  {split_name}.csv:")
        print(f"    File size: {size_bytes} bytes ({size_bytes / 1024:.2f} KB)")
        print(f"    Total rows (records): {total}")
        print(f"    Legitimate (0): {legit}")
        print(f"    Scam (1): {scam}")
        print(f"    Scam %: {scam / total * 100:.2f}%")
        print(f"    Columns: {list(df.columns)}")


def verify_model_artifact():
    print("\n=== 6. MODEL ARTIFACT VERIFICATION ===")
    if not MODEL_PATH.exists():
        print(f"[FAIL] Model artifact not found at {MODEL_PATH}")
        return

    size_bytes = MODEL_PATH.stat().st_size
    print(f"Model file: {MODEL_PATH}")
    print(f"  File size: {size_bytes} bytes ({size_bytes / 1024:.2f} KB)")

    try:
        pipeline = joblib.load(MODEL_PATH)
        print("  [PASS] Pipeline loaded successfully via joblib.load().")
        print(f"  Pipeline steps: {[name for name, _ in pipeline.steps]}")

        # Check vectorizer
        tfidf = pipeline.named_steps.get("tfidf")
        if tfidf is not None:
            check_is_fitted(tfidf, attributes=["vocabulary_"])
            print(f"  [PASS] TF-IDF vectorizer is FITTED.")
            print(f"    Vocabulary size: {len(tfidf.vocabulary_)} features")
            print(f"    Stop words enabled: {tfidf.stop_words is not None}")
            print(f"    N-gram range: {tfidf.ngram_range}")

        # Check classifier
        clf = pipeline.named_steps.get("clf")
        if clf is not None:
            check_is_fitted(clf, attributes=["coef_", "intercept_", "classes_"])
            print(f"  [PASS] LogisticRegression classifier is FITTED.")
            print(f"    Classes: {clf.classes_}")
            print(f"    Coefficients shape: {clf.coef_.shape}")
            print(f"    Intercept: {clf.intercept_}")
            print(f"    Class weight: {clf.class_weight}")
            
            # Show top scam-predictive terms from learned weights
            if tfidf is not None:
                feature_names = tfidf.get_feature_names_out()
                coefs = clf.coef_[0]
                top_scam_indices = coefs.argsort()[-10:][::-1]
                top_legit_indices = coefs.argsort()[:10]
                print("\n    Learned Top 5 Scam Indicators (highest positive weights):")
                for rank, i in enumerate(top_scam_indices[:5], 1):
                    print(f"      {rank}. '{feature_names[i]}' (weight: {coefs[i]:.4f})")
                print("    Learned Top 5 Legitimate Indicators (lowest negative weights):")
                for rank, i in enumerate(top_legit_indices[:5], 1):
                    print(f"      {rank}. '{feature_names[i]}' (weight: {coefs[i]:.4f})")

    except Exception as e:
        print(f"  [FAIL] Error verifying model artifact: {e}")


if __name__ == "__main__":
    verify_raw_dataset()
    verify_processed_splits()
    verify_model_artifact()
