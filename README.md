# LAMPS — Reproduction Study
**IE105 · UIT · HK2 2025–2026**

Reproduction of *"Many hands make light work: An LLM-based multi-agent system for detecting malicious PyPI packages"* (Zeshan et al., JSS 2026).

## Results

| Dataset | Ours | Paper | Gap |
|---------|------|-------|-----|
| D1 (6 000 setup.py) | **96.76%** | 97.7% | −0.94 pp |
| D2 (multi-file, t = 0.90) | **98.09%** | 99.5% | −1.41 pp |

D2 package-level **Recall = 100 %** (0 false negatives).

## Structure

```
evaluation/   – D1 & D2 evaluation protocols
scripts/      – D2 dataset reconstruction pipeline
llms/         – CodeBERT classifier wrapper
tools/        – PyPI download & extraction utilities
outputs/      – Reports and metrics
docs/         – Planning documents
tests/        – Unit tests
```

## Reproducing D2

```bash
# 1. Clone DataDog (sparse – PyPI samples only)
git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/DataDog/malicious-software-packages-dataset.git
cd malicious-software-packages-dataset
git sparse-checkout set samples/pypi && git checkout
cd ..

# 2. Build D1 hash set (dedup)
python scripts/build_d1_hashes.py

# 3. Extract malicious .py files from encrypted ZIPs
python scripts/extract_datadog.py --max-packages 300

# 4. Content-based labeling with CodeBERT
python scripts/codebert_label.py --model-id KevinPhamH/codebert-finetuned

# 5. Assemble final dataset
python scripts/build_d2_final.py

# 6. Run evaluation
python -m evaluation.run_d2_protocol \
    --model_id KevinPhamH/codebert-finetuned \
    --threshold 0.9 \
    --output outputs/d2_metrics.json
```

## Key Finding

The original D2 reconstruction failed (72.8% accuracy) due to **package-level labeling** — assigning `label=1` to all files in a malicious package, including benign utility code. The fix is **content-based labeling**: only files where CodeBERT assigns malicious probability ≥ 0.90 are labeled malicious.

## Setup

```bash
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env   # fill in API keys
```

## Report

See [`outputs/bao_cao_reproduce_LAMPS.md`](outputs/bao_cao_reproduce_LAMPS.md) for the full Vietnamese reproduction report.
