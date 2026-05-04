import argparse
import json
import logging
import subprocess
import csv
from pathlib import Path
from tqdm import tqdm
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer
from evaluation.metrics import compute_metrics

logger = logging.getLogger(__name__)

def load_d1_records_from_git(repo_path: Path) -> list[dict]:
    cmd = ['git', '-C', str(repo_path), 'cat-file', '-p', 'f8e282b33eb1f8b55dbac68df39340eab3d4e8cd']
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, encoding='utf-8')
    reader = csv.DictReader(proc.stdout)
    records = []
    for idx, row in enumerate(reader):
        text = row.get("Setup.py", "")
        # Remove surrounding quotes if they exist, though DictReader typically handles them
        if not text.strip():
            continue
        try:
            label_int = int(row.get("Label", 0))
        except ValueError:
            continue
        records.append({
            "idx": f"pkg_{row.get('Package', 'unknown')}_row_{idx}",
            "text": text,
            "label": label_int,
        })
    return records

def predict_binary_batch(model_id: str, records: list[dict], batch_size: int = 64, max_length: int = 400, threshold: float = 0.5) -> list[int]:
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"Using device: {device}")
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForSequenceClassification.from_pretrained(model_id).to(device)
    model.eval()

    preds = []
    for i in tqdm(range(0, len(records), batch_size), desc="Predicting D1"):
        batch = [r["text"] for r in records[i:i+batch_size]]
        encoded = tokenizer(
            batch,
            max_length=max_length,
            truncation=True,
            padding=True,
            return_tensors="pt"
        ).to(device)
        
        with torch.no_grad():
            logits = model(**encoded).logits
            if logits.shape[-1] == 1:
                probs = torch.sigmoid(logits).squeeze(-1)
            else:
                # If model was trained with CrossEntropyLoss and 2 labels, it outputs logits of shape (B, 2)
                # We specifically use sigmoid and threshold on the positive class as originally dictated.
                probs = torch.sigmoid(logits[:, 1])
                
            probs = probs.cpu().numpy()
            
        for prob in probs:
            preds.append(1 if prob >= threshold else 0)

    return preds

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model_id", required=True, type=str)
    parser.add_argument("--repo_path", type=str, default="tmp_lamps_jss")
    parser.add_argument("--output", type=str, default="outputs/d1_metrics.json")
    parser.add_argument("--max_length", type=int, default=400,
                        help="Tokenizer max_length. Must match training block_size (400).")
    parser.add_argument("--batch_size", type=int, default=64)
    args = parser.parse_args()

    repo_path = Path(args.repo_path).resolve()
    output = Path(args.output).resolve()

    print(f"Loading datasets via git cat-file from {repo_path} ...")
    records = load_d1_records_from_git(repo_path)
    if not records:
        raise RuntimeError("No records found.")
    
    print(f"Loaded {len(records)} records.")

    y_true = [r["label"] for r in records]
    y_pred = predict_binary_batch(args.model_id, records,
                                  batch_size=args.batch_size,
                                  max_length=args.max_length)
    metrics = compute_metrics(y_true, y_pred)

    payload = {
        "records": len(records),
        "dataset": "D1",
        "metrics": {
            "accuracy": metrics.accuracy,
            "precision": metrics.precision,
            "recall": metrics.recall,
            "f1": metrics.f1,
            "balanced_accuracy": metrics.balanced_accuracy,
            "tp": metrics.tp,
            "tn": metrics.tn,
            "fp": metrics.fp,
            "fn": metrics.fn,
        },
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
