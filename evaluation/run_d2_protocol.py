"""
D2 dataset evaluation protocol for LAMPS replication.

Evaluates CodeBERT classifier on the full D2 dataset (1296 files, 533 packages)
at both file-level and package-level (conservative verdict).

Paper claim: D2 accuracy 99.5%, balanced accuracy 99.5%.

Usage:
    python evaluation/run_d2_protocol.py --model_id KevinPhamH/codebert-finetuned
    python evaluation/run_d2_protocol.py --model_id KevinPhamH/codebert-finetuned --dry_run
"""
from __future__ import annotations

import argparse
import json
import logging
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import torch
from tqdm import tqdm
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from evaluation.metrics import ClassificationMetrics, compute_metrics

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

DATASET_ROOT = Path("D2_dataset")
METADATA_FILE = DATASET_ROOT / "metadata.json"

MAX_LENGTH = 512
DEFAULT_THRESHOLD = 0.5


def _resolve_local_path(metadata_filepath: str) -> Path:
    """Map metadata filepath ('output/D2_dataset/...') to local path ('D2_dataset/...')."""
    p = Path(metadata_filepath)
    # Strip leading 'output/' if present
    parts = p.parts
    if parts[0] == "output":
        return Path(*parts[1:])
    return p


def _load_metadata(metadata_path: Path) -> list[dict]:
    with open(metadata_path, encoding="utf-8") as f:
        meta = json.load(f)
    return meta["files"]


def _read_file_safe(path: Path) -> tuple[str | None, str | None]:
    """Return (content, error). error is None on success."""
    try:
        return path.read_text(encoding="utf-8", errors="ignore"), None
    except Exception as exc:
        return None, str(exc)


def _load_model(model_id: str, device: torch.device):
    logger.info("Loading tokenizer and model: %s", model_id)
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForSequenceClassification.from_pretrained(model_id).to(device)
    model.eval()
    return tokenizer, model


def _predict_batch(
    texts: list[str],
    tokenizer,
    model,
    device: torch.device,
    threshold: float,
) -> list[float]:
    """Return per-sample malicious probabilities."""
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


def run_d2_evaluation(
    model_id: str,
    output_path: Path,
    batch_size: int = 32,
    threshold: float = DEFAULT_THRESHOLD,
    dry_run: bool = False,
) -> dict:
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info("Device: %s", device)

    # ── Load dataset ──────────────────────────────────────────────────────────
    files_meta = _load_metadata(METADATA_FILE)
    logger.info("Loaded metadata: %d files", len(files_meta))

    # Group files by package, resolve local paths
    pkg_files: dict[str, list[dict]] = defaultdict(list)
    for fm in files_meta:
        pkg_files[fm["package"]].append({
            "filename": fm["filename"],
            "local_path": _resolve_local_path(fm["filepath"]),
            "true_label": fm["label_int"],  # 1=malicious, 0=benign
        })

    all_packages = sorted(pkg_files.keys())
    logger.info("Total packages: %d", len(all_packages))
    logger.info(
        "Malicious packages: %d | Benign packages: %d",
        sum(1 for p in all_packages if any(f["true_label"] == 1 for f in pkg_files[p])),
        sum(1 for p in all_packages if all(f["true_label"] == 0 for f in pkg_files[p])),
    )

    if dry_run:
        logger.info("Dry run complete — skipping inference.")
        return {}

    # ── Load model ────────────────────────────────────────────────────────────
    tokenizer, model = _load_model(model_id, device)

    # ── Read all files ────────────────────────────────────────────────────────
    # Build flat list: [{filename, pkg, true_label, content, read_error}]
    logger.info("Reading %d files ...", len(files_meta))
    flat_records: list[dict] = []
    read_failed = 0
    for pkg, file_list in pkg_files.items():
        for finfo in file_list:
            content, err = _read_file_safe(finfo["local_path"])
            flat_records.append({
                "filename": finfo["filename"],
                "package": pkg,
                "true_label": finfo["true_label"],
                "content": content,
                "read_error": err,
            })
            if err:
                read_failed += 1

    logger.info("Files read OK: %d | Read failures: %d", len(flat_records) - read_failed, read_failed)

    # ── Batch inference on readable files ─────────────────────────────────────
    readable = [r for r in flat_records if r["content"] is not None]
    logger.info("Running inference on %d readable files (batch_size=%d) ...", len(readable), batch_size)

    # predicted_prob[filename] = malicious probability
    predicted_prob: dict[str, float] = {}
    for i in tqdm(range(0, len(readable), batch_size), desc="Predicting D2"):
        batch = readable[i : i + batch_size]
        texts = [r["content"] for r in batch]
        probs = _predict_batch(texts, tokenizer, model, device, threshold)
        for rec, prob in zip(batch, probs):
            predicted_prob[rec["filename"]] = prob

    # ── Build per-file results ────────────────────────────────────────────────
    file_results = []
    for rec in flat_records:
        fname = rec["filename"]
        if rec["read_error"] is not None:
            # Fail-safe: unreadable file treated as MALICIOUS
            prob = 1.0
            pred = 1
            status = "read_failed"
        else:
            prob = predicted_prob[fname]
            pred = 1 if prob >= threshold else 0
            status = "ok"
        file_results.append({
            "filename": fname,
            "package": rec["package"],
            "true_label": rec["true_label"],
            "predicted_label": pred,
            "probability": round(prob, 6),
            "status": status,
        })

    # ── File-level metrics ────────────────────────────────────────────────────
    file_true = [r["true_label"] for r in file_results]
    file_pred = [r["predicted_label"] for r in file_results]
    file_metrics: ClassificationMetrics = compute_metrics(file_true, file_pred)

    # ── Package-level conservative verdict ────────────────────────────────────
    # Ground truth: any malicious file in package → package is malicious
    # Prediction: any predicted-malicious file (including read_failed) → package MALICIOUS
    pkg_true_list: list[int] = []
    pkg_pred_list: list[int] = []
    pkg_summary: list[dict] = []

    for pkg in all_packages:
        pkg_file_results = [r for r in file_results if r["package"] == pkg]
        pkg_true = 1 if any(r["true_label"] == 1 for r in pkg_file_results) else 0
        pkg_pred = 1 if any(r["predicted_label"] == 1 for r in pkg_file_results) else 0
        pkg_true_list.append(pkg_true)
        pkg_pred_list.append(pkg_pred)
        pkg_summary.append({
            "package": pkg,
            "true_label": pkg_true,
            "predicted_label": pkg_pred,
            "file_count": len(pkg_file_results),
            "malicious_file_predictions": sum(1 for r in pkg_file_results if r["predicted_label"] == 1),
            "read_failures": sum(1 for r in pkg_file_results if r["status"] == "read_failed"),
        })

    pkg_metrics: ClassificationMetrics = compute_metrics(pkg_true_list, pkg_pred_list)

    # ── Assemble output payload ───────────────────────────────────────────────
    payload = {
        "dataset": "D2",
        "model_id": model_id,
        "evaluated_at_utc": datetime.now(timezone.utc).isoformat(),
        "config": {
            "max_length": MAX_LENGTH,
            "threshold": threshold,
            "batch_size": batch_size,
            "device": str(device),
        },
        "data_summary": {
            "total_files": len(flat_records),
            "total_packages": len(all_packages),
            "read_failures": read_failed,
            "files_inferred": len(readable),
        },
        "file_level_metrics": {
            "accuracy": file_metrics.accuracy,
            "precision": file_metrics.precision,
            "recall": file_metrics.recall,
            "f1": file_metrics.f1,
            "balanced_accuracy": file_metrics.balanced_accuracy,
            "tp": file_metrics.tp,
            "tn": file_metrics.tn,
            "fp": file_metrics.fp,
            "fn": file_metrics.fn,
        },
        "package_level_metrics": {
            "accuracy": pkg_metrics.accuracy,
            "precision": pkg_metrics.precision,
            "recall": pkg_metrics.recall,
            "f1": pkg_metrics.f1,
            "balanced_accuracy": pkg_metrics.balanced_accuracy,
            "tp": pkg_metrics.tp,
            "tn": pkg_metrics.tn,
            "fp": pkg_metrics.fp,
            "fn": pkg_metrics.fn,
        },
        "package_verdicts": pkg_summary,
        "file_results": file_results,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.info("Results saved to: %s", output_path)

    _print_summary(payload)
    return payload


def _print_summary(payload: dict) -> None:
    sep = "=" * 60
    print(f"\n{sep}")
    print("LAMPS D2 EVALUATION RESULTS")
    print(sep)

    ds = payload["data_summary"]
    print(f"Dataset:  D2 | Files: {ds['total_files']} | Packages: {ds['total_packages']}")
    print(f"Model:    {payload['model_id']}")
    if ds["read_failures"] > 0:
        print(f"WARNING:  {ds['read_failures']} files could not be read (treated as MALICIOUS)")

    def _row(label: str, m: dict) -> None:
        print(
            f"  Acc={m['accuracy']:.4f}  BA={m['balanced_accuracy']:.4f}"
            f"  P={m['precision']:.4f}  R={m['recall']:.4f}  F1={m['f1']:.4f}"
            f"  TP={m['tp']} TN={m['tn']} FP={m['fp']} FN={m['fn']}"
        )

    print("\nFile-level metrics (raw classifier):")
    _row("file", payload["file_level_metrics"])
    print("\nPackage-level metrics (conservative verdict):")
    _row("pkg", payload["package_level_metrics"])
    print("\nPaper D2 claims: Accuracy=0.9950  Balanced_Accuracy=0.9950")
    print(sep)


def main() -> None:
    parser = argparse.ArgumentParser(description="LAMPS D2 dataset evaluation protocol.")
    parser.add_argument("--model_id", required=True, type=str, help="HuggingFace model ID")
    parser.add_argument("--output", type=str, default="outputs/d2_metrics.json")
    parser.add_argument("--batch_size", type=int, default=32)
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    parser.add_argument("--dry_run", action="store_true", help="Load dataset only, skip inference")
    args = parser.parse_args()

    run_d2_evaluation(
        model_id=args.model_id,
        output_path=Path(args.output),
        batch_size=args.batch_size,
        threshold=args.threshold,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
