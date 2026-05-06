"""
G3 — Real-World Class Imbalance Evaluation for LAMPS.

Vấn đề (Gap G3):
  Paper báo cáo D2 accuracy=99.5% trên dataset cân bằng (~1:3.7).
  Ngoài đời thực tỷ lệ package độc hại trên PyPI chỉ ~0.5% (~1:200).
  Paper không đề cập đến sự suy giảm precision khi imbalance tăng.

Phương pháp:
  1. Chạy inference MỘT LẦN trên toàn bộ D2 (1328 files).
  2. Với mỗi tỷ lệ imbalance (1:3.7, 1:7, 1:10, 1:20, 1:50):
     - Giữ nguyên toàn bộ benign packages (396 packages).
     - Subsample ngẫu nhiên malicious packages để đạt tỷ lệ mong muốn.
     - Lặp 5 seeds → lấy mean ± std cho ổn định.
  3. Bayesian extrapolation → tính precision kỳ vọng tại 1:100, 1:200.

Usage:
    python evaluation/run_d2_imbalanced.py \\
        --model_id KevinPhamH/codebert-finetuned --dry_run

    python evaluation/run_d2_imbalanced.py \\
        --model_id KevinPhamH/codebert-finetuned \\
        --output outputs/g3_imbalance_results.json
"""
from __future__ import annotations

import argparse
import json
import logging
import math
import random
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import torch
from tqdm import tqdm
from transformers import AutoModelForSequenceClassification, AutoTokenizer

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from evaluation.metrics import (  # noqa: E402
    compute_average_precision,
    compute_bayesian_precision,
    compute_expected_fdr,
    compute_metrics,
    compute_pr_curve,
)

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

DATASET_ROOT = ROOT_DIR / "D2_dataset"
METADATA_FILE = DATASET_ROOT / "metadata.json"
MAX_LENGTH = 512

# Tỷ lệ imbalanced cần đánh giá thực nghiệm (benign:malicious)
IMBALANCE_RATIOS = [3.7, 7, 10, 20, 50]

# Priors Bayesian (fraction of malicious in real world)
BAYESIAN_PRIORS = {
    "1_in_10":  1 / 10,
    "1_in_50":  1 / 50,
    "1_in_100": 1 / 100,
    "1_in_200": 1 / 200,
}

# Seeds cho bootstrap sampling
BOOTSTRAP_SEEDS = [42, 123, 456, 789, 1024]


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def _resolve_local_path(raw: str) -> Path:
    p = Path(raw)
    if p.parts and p.parts[0] == "output":
        p = Path(*p.parts[1:])
    if not p.is_absolute():
        p = ROOT_DIR / p
    return p


def load_full_dataset(metadata_path: Path = METADATA_FILE) -> dict[str, Any]:
    """Load toàn bộ dataset từ metadata.json.

    Returns:
      {
        "all_files":   list[dict]  — mỗi file có filename, package, label_int, local_path
        "mal_packages": list[str] — tên packages malicious
        "ben_packages": list[str] — tên packages benign
        "pkg_files":   dict[str, list[dict]] — package → files
      }
    """
    meta = json.loads(metadata_path.read_text(encoding="utf-8"))
    all_files: list[dict] = []
    pkg_files: dict[str, list[dict]] = defaultdict(list)

    for rec in meta["files"]:
        entry = {
            "filename":  rec["filename"],
            "package":   rec["package"],
            "label_int": rec["label_int"],
            "local_path": _resolve_local_path(rec["filepath"]),
        }
        all_files.append(entry)
        pkg_files[rec["package"]].append(entry)

    mal_packages = sorted({f["package"] for f in all_files if f["label_int"] == 1})
    ben_packages = sorted({f["package"] for f in all_files if f["label_int"] == 0})

    logger.info(
        "Dataset loaded: %d files | %d mal pkgs | %d ben pkgs",
        len(all_files), len(mal_packages), len(ben_packages),
    )
    return {
        "all_files":    all_files,
        "mal_packages": mal_packages,
        "ben_packages": ben_packages,
        "pkg_files":    dict(pkg_files),
    }


# ---------------------------------------------------------------------------
# Inference (chạy 1 lần trên toàn bộ dataset)
# ---------------------------------------------------------------------------

def run_full_inference(
    all_files: list[dict],
    model_id: str,
    batch_size: int,
    device: torch.device,
    threshold: float = 0.5,
) -> dict[str, float]:
    """Chạy inference 1 lần, trả về dict filename → probability."""
    logger.info("Loading model: %s on %s", model_id, device)
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForSequenceClassification.from_pretrained(model_id).to(device)
    model.eval()

    # Đọc nội dung tất cả files
    readable_files: list[dict] = []
    readable_texts: list[str] = []
    failed_files: list[str] = []

    for f in all_files:
        try:
            text = f["local_path"].read_text(encoding="utf-8", errors="ignore")
            readable_files.append(f)
            readable_texts.append(text)
        except Exception:
            failed_files.append(f["filename"])

    if failed_files:
        logger.warning("%d files could not be read (will be treated as MALICIOUS)", len(failed_files))

    # Batch inference
    prob_map: dict[str, float] = {}
    logger.info("Running inference on %d files ...", len(readable_files))

    for i in tqdm(range(0, len(readable_files), batch_size), desc="Inference"):
        batch_files = readable_files[i: i + batch_size]
        batch_texts = readable_texts[i: i + batch_size]

        encoded = tokenizer(
            batch_texts,
            max_length=MAX_LENGTH,
            truncation=True,
            padding=True,
            return_tensors="pt",
        )
        encoded = {k: v.to(device) for k, v in encoded.items()}

        with torch.no_grad():
            logits = model(**encoded).logits
            if logits.shape[-1] == 1:
                probs = torch.sigmoid(logits).squeeze(-1)
            else:
                probs = torch.sigmoid(logits[:, 1])

        for finfo, prob in zip(batch_files, probs.cpu().tolist()):
            prob_map[finfo["filename"]] = float(prob)

    # Fail-safe: unreadable file → prob=1.0 (conservative)
    for fname in failed_files:
        prob_map[fname] = 1.0

    logger.info("Inference complete. %d probabilities cached.", len(prob_map))
    return prob_map


# ---------------------------------------------------------------------------
# Package-level conservative verdict
# ---------------------------------------------------------------------------

def _pkg_verdict(files: list[dict], prob_map: dict[str, float], threshold: float) -> dict:
    """Conservative verdict cho 1 package: 1 file malicious → cả package MALICIOUS."""
    true_label  = 1 if any(f["label_int"] == 1 for f in files) else 0
    probs = [prob_map.get(f["filename"], 1.0) for f in files]
    max_prob = max(probs)
    pred_label = 1 if max_prob >= threshold else 0
    return {
        "true_label":   true_label,
        "predicted":    pred_label,
        "max_prob":     max_prob,
        "file_count":   len(files),
    }


# ---------------------------------------------------------------------------
# Evaluate tại 1 tỷ lệ imbalance với 1 seed
# ---------------------------------------------------------------------------

def _evaluate_at_ratio(
    ratio: float,
    mal_packages: list[str],
    ben_packages: list[str],
    pkg_files: dict[str, list[dict]],
    prob_map: dict[str, float],
    seed: int,
    threshold: float = 0.5,
) -> dict:
    """Subsample malicious để đạt tỷ lệ ratio, đánh giá package-level metrics."""
    rng = random.Random(seed)

    # Số malicious packages cần lấy để đạt tỷ lệ ben:mal = ratio
    n_mal_needed = max(1, round(len(ben_packages) / ratio))
    n_mal_needed = min(n_mal_needed, len(mal_packages))

    sampled_mal = rng.sample(mal_packages, n_mal_needed)
    eval_packages = sampled_mal + ben_packages

    # Package-level verdicts
    pkg_results = []
    for pkg in eval_packages:
        files = pkg_files.get(pkg, [])
        if not files:
            continue
        v = _pkg_verdict(files, prob_map, threshold)
        pkg_results.append(v)

    y_true  = [r["true_label"] for r in pkg_results]
    y_pred  = [r["predicted"]  for r in pkg_results]
    y_score = [r["max_prob"]   for r in pkg_results]

    m = compute_metrics(y_true, y_pred)
    ap = compute_average_precision(y_true, y_score)
    fpr = m.fp / (m.fp + m.tn) if (m.fp + m.tn) > 0 else 0.0
    actual_ratio = len(ben_packages) / n_mal_needed if n_mal_needed > 0 else 0

    return {
        "seed":           seed,
        "n_mal_packages": n_mal_needed,
        "n_ben_packages": len(ben_packages),
        "actual_ratio":   round(actual_ratio, 1),
        "tp": m.tp, "tn": m.tn, "fp": m.fp, "fn": m.fn,
        "precision":  round(m.precision, 6),
        "recall":     round(m.recall,    6),
        "f1":         round(m.f1,        6),
        "accuracy":   round(m.accuracy,  6),
        "balanced_accuracy": round(m.balanced_accuracy, 6),
        "fpr":        round(fpr,         6),
        "average_precision": ap,
    }


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def _mean(vals: list[float]) -> float:
    return sum(vals) / len(vals) if vals else 0.0

def _std(vals: list[float]) -> float:
    if len(vals) < 2:
        return 0.0
    m = _mean(vals)
    return math.sqrt(sum((v - m) ** 2 for v in vals) / (len(vals) - 1))


def run_g3_evaluation(
    model_id: str,
    output_path: Path,
    batch_size: int = 32,
    threshold: float = 0.5,
    dry_run: bool = False,
) -> dict:
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info("Device: %s", device)

    # Load dataset
    ds = load_full_dataset()
    mal_packages = ds["mal_packages"]
    ben_packages = ds["ben_packages"]
    pkg_files    = ds["pkg_files"]

    if dry_run:
        logger.info("Dry run OK — %d mal pkgs | %d ben pkgs | %d total files",
                    len(mal_packages), len(ben_packages), len(ds["all_files"]))
        logger.info("Ratios to evaluate: %s", IMBALANCE_RATIOS)
        return {}

    # Inference 1 lần
    prob_map = run_full_inference(ds["all_files"], model_id, batch_size, device, threshold)

    # ── Baseline: toàn bộ D2 (tỷ lệ thực của dataset) ─────────────────────
    logger.info("Computing baseline (full D2 dataset) ...")
    baseline_results = [
        _evaluate_at_ratio(
            ratio=len(ben_packages) / len(mal_packages),
            mal_packages=mal_packages,
            ben_packages=ben_packages,
            pkg_files=pkg_files,
            prob_map=prob_map,
            seed=seed,
            threshold=threshold,
        )
        for seed in BOOTSTRAP_SEEDS
    ]
    baseline_mean = {
        "ratio":      f"1:{len(ben_packages)/len(mal_packages):.1f}",
        "n_mal":      len(mal_packages),
        "n_ben":      len(ben_packages),
        "precision":  round(_mean([r["precision"] for r in baseline_results]), 4),
        "recall":     round(_mean([r["recall"]    for r in baseline_results]), 4),
        "f1":         round(_mean([r["f1"]        for r in baseline_results]), 4),
        "fpr":        round(_mean([r["fpr"]       for r in baseline_results]), 4),
        "average_precision": round(_mean([r["average_precision"] for r in baseline_results]), 4),
    }

    # ── Imbalanced evaluation ──────────────────────────────────────────────
    logger.info("Evaluating %d imbalance ratios × %d seeds ...", len(IMBALANCE_RATIOS), len(BOOTSTRAP_SEEDS))
    ratio_summaries: list[dict] = []

    for ratio in IMBALANCE_RATIOS:
        seed_results = []
        for seed in BOOTSTRAP_SEEDS:
            r = _evaluate_at_ratio(ratio, mal_packages, ben_packages, pkg_files, prob_map, seed, threshold)
            seed_results.append(r)

        n_mal_mean = _mean([r["n_mal_packages"] for r in seed_results])
        ratio_summaries.append({
            "target_ratio":     f"1:{ratio}",
            "actual_ratio":     f"1:{seed_results[0]['actual_ratio']}",
            "n_mal_packages_approx": round(n_mal_mean),
            "n_ben_packages":   len(ben_packages),
            "precision_mean":   round(_mean([r["precision"] for r in seed_results]), 4),
            "precision_std":    round(_std( [r["precision"] for r in seed_results]), 4),
            "recall_mean":      round(_mean([r["recall"]    for r in seed_results]), 4),
            "recall_std":       round(_std( [r["recall"]    for r in seed_results]), 4),
            "f1_mean":          round(_mean([r["f1"]        for r in seed_results]), 4),
            "f1_std":           round(_std( [r["f1"]        for r in seed_results]), 4),
            "fpr_mean":         round(_mean([r["fpr"]       for r in seed_results]), 4),
            "ap_mean":          round(_mean([r["average_precision"] for r in seed_results]), 4),
            "ap_std":           round(_std( [r["average_precision"] for r in seed_results]), 4),
            "per_seed":         seed_results,
        })

    # ── Bayesian extrapolation (dùng TPR/FPR từ baseline) ─────────────────
    base_tpr = baseline_mean["recall"]
    base_fpr = baseline_mean["fpr"]
    bayesian: dict[str, dict] = {}
    for label, prior in BAYESIAN_PRIORS.items():
        bp  = compute_bayesian_precision(base_tpr, base_fpr, prior)
        fdr = compute_expected_fdr(base_tpr, base_fpr, prior)
        n_malicious = round(1 / prior)
        bayesian[label] = {
            "prior":              prior,
            "ratio":              f"1:{n_malicious}",
            "expected_precision": round(bp,  4),
            "expected_fdr":       round(fdr, 4),
            "interpretation":     f"Cứ {round(1/bp) if bp > 0 else 'vô hạn'} cảnh báo thì có 1 là thật",
        }

    payload = {
        "experiment":      "G3_real_world_imbalance",
        "model_id":        model_id,
        "evaluated_at_utc": datetime.now(timezone.utc).isoformat(),
        "config": {
            "batch_size":   batch_size,
            "threshold":    threshold,
            "max_length":   MAX_LENGTH,
            "device":       str(device),
            "bootstrap_seeds": BOOTSTRAP_SEEDS,
        },
        "paper_claim": {
            "dataset":  "D2",
            "accuracy": 0.995,
            "ratio":    "~1:3.7",
            "note":     "Paper không báo cáo AP, FDR, hay real-world precision.",
        },
        "baseline_full_d2": baseline_mean,
        "imbalanced_results": ratio_summaries,
        "bayesian_extrapolation": bayesian,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.info("Saved to: %s", output_path)

    _print_summary(payload)
    return payload


# ---------------------------------------------------------------------------
# Pretty print
# ---------------------------------------------------------------------------

def _print_summary(p: dict) -> None:
    sep = "=" * 72
    print(f"\n{sep}")
    print("G3 — Real-World Class Imbalance Evaluation (LAMPS / CodeBERT D2)")
    print(sep)
    print(f"Model : {p['model_id']}")
    print(f"Device: {p['config']['device']}")

    bl = p["baseline_full_d2"]
    print(f"\nBaseline (full D2, {bl['ratio']}, {bl['n_mal']} mal / {bl['n_ben']} ben pkgs):")
    print(f"  Precision={bl['precision']*100:.1f}%  Recall={bl['recall']*100:.1f}%  "
          f"F1={bl['f1']*100:.1f}%  AP={bl['average_precision']:.4f}  FPR={bl['fpr']*100:.2f}%")

    print(f"\nImbalanced evaluation (package-level, {len(BOOTSTRAP_SEEDS)} bootstrap seeds):")
    print(f"{'Ratio':>8} | {'#Mal':>5} | {'Precision':>12} | {'Recall':>9} | {'F1':>9} | {'AP':>7}")
    print("-" * 72)
    # Baseline row
    print(f"{bl['ratio']:>8} | {bl['n_mal']:>5} | "
          f"{bl['precision']*100:>10.1f}%  | "
          f"{bl['recall']*100:>7.1f}%  | "
          f"{bl['f1']*100:>7.1f}%  | "
          f"{bl['average_precision']:>7.4f}  <- paper D2")
    for r in p["imbalanced_results"]:
        print(f"{r['target_ratio']:>8} | {r['n_mal_packages_approx']:>5} | "
              f"{r['precision_mean']*100:>9.1f}±{r['precision_std']*100:.1f}% | "
              f"{r['recall_mean']*100:>7.1f}%  | "
              f"{r['f1_mean']*100:>7.1f}%  | "
              f"{r['ap_mean']:>7.4f}")

    print(f"\nBayesian extrapolation (TPR={bl['recall']*100:.1f}%, FPR={bl['fpr']*100:.2f}%):")
    print(f"{'Prior':>8} | {'Exp. Precision':>16} | {'Exp. FDR':>10} | {'Interpretation'}")
    print("-" * 72)
    for key, v in p["bayesian_extrapolation"].items():
        print(f"{v['ratio']:>8} | {v['expected_precision']*100:>15.1f}% | "
              f"{v['expected_fdr']*100:>9.1f}% | {v['interpretation']}")

    print(f"\nPaper D2 claim: Accuracy=99.5% trên dataset cân bằng ~{bl['ratio']}")
    print("Key finding   : Precision suy giảm mạnh khi tỷ lệ imbalance tăng.")
    print(sep)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="G3: Real-world imbalance evaluation for LAMPS.")
    parser.add_argument("--model_id", required=True, type=str)
    parser.add_argument("--output", type=str, default="outputs/g3_imbalance_results.json")
    parser.add_argument("--batch_size", type=int, default=32)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--dry_run", action="store_true")
    args = parser.parse_args()

    run_g3_evaluation(
        model_id=args.model_id,
        output_path=Path(args.output),
        batch_size=args.batch_size,
        threshold=args.threshold,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
