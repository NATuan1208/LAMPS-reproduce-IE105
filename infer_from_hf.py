#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
from typing import Dict, List

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer


def _resolve_device(device_name: str) -> torch.device:
    if device_name == "cpu":
        return torch.device("cpu")
    if device_name == "cuda":
        return torch.device("cuda")
    if device_name == "mps":
        return torch.device("mps")

    if torch.cuda.is_available():
        return torch.device("cuda")
    if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        return torch.device("mps")
    return torch.device("cpu")


def _load_inputs(args: argparse.Namespace) -> List[Dict]:
    records: List[Dict] = []

    if args.text:
        for idx, text in enumerate(args.text):
            records.append({"idx": f"cli-{idx}", args.field_name: text})

    if args.input_jsonl:
        input_path = Path(args.input_jsonl)
        with input_path.open("r", encoding="utf-8") as f:
            for line_number, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                if args.field_name not in obj:
                    raise KeyError(
                        f"Missing field '{args.field_name}' in {input_path} at line {line_number + 1}"
                    )
                idx = obj.get("idx", f"line-{line_number + 1}")
                records.append({"idx": idx, args.field_name: obj[args.field_name]})

    if not records:
        raise RuntimeError("No input provided. Use --text or --input_jsonl.")

    return records


def predict(
    model_id: str,
    records: List[Dict],
    field_name: str,
    threshold: float,
    max_length: int,
    batch_size: int,
    device: torch.device,
    hf_token: str,
    cache_dir: str,
    revision: str,
) -> List[Dict]:
    common_kwargs = {}
    if hf_token:
        common_kwargs["token"] = hf_token
    if cache_dir:
        common_kwargs["cache_dir"] = cache_dir
    if revision:
        common_kwargs["revision"] = revision

    tokenizer = AutoTokenizer.from_pretrained(model_id, **common_kwargs)
    model = AutoModelForSequenceClassification.from_pretrained(model_id, **common_kwargs)
    model.to(device)
    model.eval()

    outputs: List[Dict] = []
    for start in range(0, len(records), batch_size):
        batch = records[start : start + batch_size]
        texts = [item[field_name] for item in batch]

        encoded = tokenizer(
            texts,
            max_length=max_length,
            truncation=True,
            padding=True,
            return_tensors="pt",
        )
        encoded = {k: v.to(device) for k, v in encoded.items()}

        with torch.no_grad():
            logits = model(**encoded).logits.squeeze(-1)
            probs = torch.sigmoid(logits).detach().cpu().tolist()

        for item, prob in zip(batch, probs):
            pred = int(prob >= threshold)
            outputs.append(
                {
                    "idx": item["idx"],
                    "probability_vulnerable": round(float(prob), 6),
                    "prediction": pred,
                }
            )

    return outputs


def main() -> None:
    parser = argparse.ArgumentParser(description="Run inference with a model hosted on Hugging Face Hub.")
    parser.add_argument("--model_id", required=True, type=str, help="Hub model id, e.g. username/codebert-vuln-baseline")
    parser.add_argument("--text", action="append", default=[], help="Inline input text (repeatable)")
    parser.add_argument("--input_jsonl", type=str, default="", help="Optional JSONL input file")
    parser.add_argument("--output_jsonl", type=str, default="", help="Optional JSONL output file")
    parser.add_argument("--field_name", type=str, default="func", help="Field containing source code text")
    parser.add_argument("--threshold", type=float, default=0.5, help="Decision threshold for binary prediction")
    parser.add_argument("--max_length", type=int, default=400, help="Tokenizer max length")
    parser.add_argument("--batch_size", type=int, default=8, help="Inference batch size")
    parser.add_argument("--hf_token", type=str, default="", help="Optional HF token for private/gated repos")
    parser.add_argument("--cache_dir", type=str, default="", help="Optional Hugging Face cache directory")
    parser.add_argument("--revision", type=str, default="", help="Optional model revision/tag/commit")
    parser.add_argument(
        "--device",
        type=str,
        choices=["auto", "cpu", "cuda", "mps"],
        default="auto",
        help="Execution device",
    )

    args = parser.parse_args()

    if "your-username/" in args.model_id:
        raise ValueError(
            "Invalid placeholder model id detected. Set a real CODEBERT_MODEL_ID from your fine-tuned Hugging Face repo."
        )

    hf_token = (args.hf_token or os.getenv("HF_TOKEN") or "").strip()

    device = _resolve_device(args.device)
    print(f"Using device: {device}")

    records = _load_inputs(args)
    predictions = predict(
        model_id=args.model_id,
        records=records,
        field_name=args.field_name,
        threshold=args.threshold,
        max_length=args.max_length,
        batch_size=args.batch_size,
        device=device,
        hf_token=hf_token,
        cache_dir=args.cache_dir,
        revision=args.revision,
    )

    for item in predictions:
        print(json.dumps(item, ensure_ascii=False))

    if args.output_jsonl:
        output_path = Path(args.output_jsonl)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as f:
            for item in predictions:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
        print(f"Saved predictions to: {output_path}")


if __name__ == "__main__":
    main()
