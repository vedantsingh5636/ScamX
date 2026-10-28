# ScamShield-AI: Machine Learning Component

Baseline text classification engine for detecting scam and phishing messages using TF-IDF vectorization and Logistic Regression.

## 1. Architecture Overview
- **Representation:** TF-IDF with unigrams + bigrams (`ngram_range=(1, 2)`), sublinear TF scaling, max 10,000 features.
- **Classifier:** Balanced Logistic Regression (`class_weight='balanced'`, `solver='lbfgs'`).
- **Data Hygiene:** Deduplication performed strictly **before** splitting.
- **Data Splitting:** Stratified 70% Train, 15% Validation, 15% Test.
- **Test Set Isolation:** Held-out test set is never seen during training or tuning.
- **Probability Calibration:** Baseline delivers standard uncalibrated logistic sigmoid outputs (`calibrated=False`).

## 2. Directory Layout
```
ml/
├── data/
│   ├── raw/                  # Downloaded raw dataset (SMSSpamCollection)
│   ├── processed/            # train.csv, val.csv, test.csv
│   └── MANIFEST.md           # Dataset provenance, license, hygiene stats
├── models/
│   └── model.joblib          # Serialized scikit-learn pipeline artifact
├── reports/
│   └── baseline_metrics.json # Precision, recall, F1, ROC-AUC, confusion matrix
├── src/
│   ├── __init__.py
│   ├── preprocess.py         # Download, deduplication, stratified splits
│   ├── train.py              # Fit on train.csv, validate on val.csv, export model
│   ├── evaluate.py           # Evaluate model.joblib on test.csv, export metrics
│   └── predict.py            # predict(text: str) -> dict inference interface
├── tests/
│   ├── __init__.py
│   └── test_predict.py       # Unit and sanity test suite
└── requirements-ml.txt       # scikit-learn, joblib, pandas, numpy
```

## 3. Quickstart & Execution

### Activate Virtual Environment
```bash
# Windows
.\.venv\Scripts\activate
```

### Preprocess Data (Download, Deduplicate, Split)
```bash
python ml/src/preprocess.py
```

### Train Baseline Model
```bash
python ml/src/train.py
```

### Evaluate on Held-out Test Split
```bash
python ml/src/evaluate.py
```

### Run Unit Tests
```bash
python -m unittest discover -s ml/tests -p "test_*.py"
```

## 4. Backend Integration Interface
Import `predict` from `ml.src.predict`:

```python
from ml.src.predict import predict

result = predict("URGENT! Claim your 1000 cash prize now by calling 09061743806.")
print(result)
```

### Response Schema:
```json
{
  "text": "URGENT! Claim your 1000 cash prize now by calling 09061743806.",
  "label": "scam",
  "is_scam": true,
  "scam_probability": 0.9852,
  "probabilities": {
    "legitimate": 0.0148,
    "scam": 0.9852
  },
  "confidence": 0.9852,
  "model_version": "v1.0.0-baseline-tfidf-lr",
  "calibrated": false
}
```
