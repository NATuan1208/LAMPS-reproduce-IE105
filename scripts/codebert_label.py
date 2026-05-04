"""
Content-based labeling of extracted Python files using CodeBERT classifier.

Reads scripts/datadog_raw_metadata.json (from extract_datadog.py),
loads each .py file, runs CodeBERT inference, assigns labels:
  prob >= 0.90  -> label=1  (malicious, high confidence)
  prob <= 0.10  -> label=0  (benign,    high confidence)
  otherwise     -> label=-1 (needs manual review)

After running:
  - Review scripts/labeled_metadata.json for entries with label_int == -1
  - Manually set label_int to 0 or 1 for those entries

Usage:
    cd <LAMPS root>
    python scripts/codebert_label.py [--model-id MODEL] [--batch-size N]

Output:
    scripts/labeled_metadata.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import torch
from tqdm import tqdm
from transformers import AutoModelForSequenceClassification, AutoTokenizer

SCRIPTS_DIR = Path(__file__).parent
DEFAULT_METADATA = SCRIPTS_DIR / "datadog_raw_metadata.json"
EXTRACTED_DIR = SCRIPTS_DIR / "extracted_malicious"
OUTPUT = SCRIPTS_DIR / "labeled_metadata.json"

DEFAULT_MODEL = "KevinPhamH/codebert-finetuned"
MAX_LENGTH = 512
THRESHOLD_MAL = 0.90
THRESHOLD_BEN = 0.10


def _load_model(model_id: str, device: torch.device):
    print(f"Loading model: {model_id}")
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForSequenceClassification.from_pretrained(model_id).to(device)
    model.eval()
    return tokenizer, model


def _predict_batch(texts: list[str], tokenizer, model, device: torch.device) -> list[float]:
    encoded = tokenizer(
        texts,
        max_length=MAX_LENGTH,
        truncation=True,
        padding=True,
        return_tensors="pt",
    ).to(device)
    with torch.no_grad():
        logits = model(**encoded).logits
        if logits.shape[-1] == 1:
            probs = torch.sigmoid(logits).squeeze(-1)
        else:
            probs = torch.sigmoid(logits[:, 1])
    return probs.cpu().tolist()


def label_files(metadata_path: Path, model_id: str, batch_size: int) -> list[dict]:
    records: list[dict] = json.loads(metadata_path.read_text(encoding="utf-8"))
    print(f"Loaded {len(records)} file records from {metadata_path}")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")
    tokenizer, model = _load_model(model_id, device)

    # Read file contents
    contents: list[str | None] = []
    for rec in records:
        py_path = EXTRACTED_DIR / rec["filename"]
        try:
            contents.append(py_path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            contents.append(None)

    readable_idx = [i for i, c in enumerate(contents) if c is not None]
    readable_texts = [contents[i] for i in readable_idx]
    print(f"Readable files: {len(readable_texts)} / {len(records)}")

    # Batch inference
    probs: dict[int, float] = {}
    for i in tqdm(range(0, len(readable_texts), batch_size), desc="CodeBERT inference"):
        batch_idx = readable_idx[i : i + batch_size]
        batch_texts = readable_texts[i : i + batch_size]
        batch_probs = _predict_batch(batch_texts, tokenizer, model, device)
        for idx, prob in zip(batch_idx, batch_probs):
            probs[idx] = prob

    # Assign labels
    for i, rec in enumerate(records):
        if i not in probs:
            rec.update({"malicious_prob": None, "label_int": -1, "label": "review", "confidence": "read_error"})
            continue

        prob = round(probs[i], 4)
        if prob >= THRESHOLD_MAL:
            label_int, label, confidence = 1, "malicious", "high"
        elif prob <= THRESHOLD_BEN:
            label_int, label, confidence = 0, "benign", "high"
        else:
            label_int, label, confidence = -1, "review", "low"

        rec.update({
            "malicious_prob": prob,
            "label_int": label_int,
            "label": label,
            "confidence": confidence,
        })

    # Summary
    auto_mal = sum(1 for r in records if r["label_int"] == 1)
    auto_ben = sum(1 for r in records if r["label_int"] == 0)
    need_review = sum(1 for r in records if r["label_int"] == -1)

    OUTPUT.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\n=== LABELING SUMMARY ===")
    print(f"  Auto MALICIOUS (prob >= {THRESHOLD_MAL}): {auto_mal}")
    print(f"  Auto BENIGN    (prob <= {THRESHOLD_BEN}): {auto_ben}")
    print(f"  Needs review   (other)         : {need_review}")
    print(f"  Results saved  : {OUTPUT}")

    if need_review > 0:
        print(f"\n[ACTION NEEDED] Edit {OUTPUT}")
        print(f"  Filter label_int == -1 and set each to 0 or 1 manually.")
        print(f"  Set 'confidence' to 'manual' after reviewing.")

    return records


def check_package_consistency(records: list[dict]) -> None:
    """Report packages with zero malicious files (will be dropped in build step)."""
    from collections import defaultdict
    pkgs: dict[str, list] = defaultdict(list)
    for r in records:
        pkgs[r["package"]].append(r)

    valid = [p for p, files in pkgs.items() if any(f["label_int"] == 1 for f in files)]
    invalid = [p for p, files in pkgs.items() if not any(f["label_int"] == 1 for f in files)]

    print(f"\n=== PACKAGE CONSISTENCY ===")
    print(f"  Packages with >= 1 malicious file: {len(valid)}")
    print(f"  Packages with no malicious file  : {len(invalid)} (will be dropped)")
    if invalid:
        print(f"  Dropped: {', '.join(invalid[:10])}{'...' if len(invalid) > 10 else ''}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Label extracted files with CodeBERT.")
    parser.add_argument("--model-id", default=DEFAULT_MODEL)
    parser.add_argument("--metadata", type=Path, default=DEFAULT_METADATA)
    parser.add_argument("--batch-size", type=int, default=32)
    args = parser.parse_args()

    if not args.metadata.exists():
        print(f"[ERROR] Metadata not found: {args.metadata}")
        print("  Run scripts/extract_datadog.py first.")
        return

    records = label_files(args.metadata, args.model_id, args.batch_size)
    check_package_consistency(records)


if __name__ == "__main__":
    main()
