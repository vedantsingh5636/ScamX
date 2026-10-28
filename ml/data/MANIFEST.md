# Dataset Manifest: SMS Spam Collection (ScamShield-AI Baseline)

## 1. Provenance & Attribution
- **Dataset Name:** SMS Spam Collection
- **Source Repository:** UCI Machine Learning Repository
- **URL:** https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip
- **Original Authors & Citation:**
  Almeida, T.A., Gómez Hidalgo, J.M., Yamakami, A. *Contributions to the Study of SMS Spam Filtering: New Collection and Results.* Proceedings of the 2011 ACM Symposium on Document Engineering (DOCENG'11), Mountain View, CA, USA, 2011.
- **License / Terms of Use:** Publicly available for scientific research, academic, and evaluation purposes with citation.

## 2. Label Mapping (Binary)
- `ham` -> `legitimate` (Numeric label: `0`)
- `spam` -> `scam` (Numeric label: `1`)

## 3. Data Hygiene & Leakage Prevention
- **Deduplication:** Deduplicated on raw text BEFORE splitting to guarantee zero message overlap between train, validation, and test splits.
- **Initial records in raw archive:** 5574
- **Valid labeled records:** 5574
- **Duplicate messages removed:** 414
- **Unique messages retained:** 5160
- **Overall Class Balance:**
  - Legitimate (`ham`): 4518 (87.56%)
  - Scam (`spam`): 642 (12.44%)

## 4. Stratified Split Breakdown (70% Train / 15% Validation / 15% Test)
- **Random Seed:** 42

| Split | Total Samples | Legitimate (0) | Scam (1) | Scam Prevalence |
|---|---|---|---|---|
| **Train (70%)** | 3612 | 3163 | 449 | 12.43% |
| **Validation (15%)** | 774 | 677 | 97 | 12.53% |
| **Test (15%)** | 774 | 678 | 96 | 12.4% |

## 5. Storage Locations
- Raw file: `ml/data/raw/SMSSpamCollection`
- Train split: `ml/data/processed/train.csv`
- Validation split: `ml/data/processed/val.csv`
- Held-out Test split: `ml/data/processed/test.csv`
