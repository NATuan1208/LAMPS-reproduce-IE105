"""LAMPS demo scanner — CodeBERT inference for web demo."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from .payload_inspector import inspect_payloads

MODEL_ID = "KevinPhamH/codebert-finetuned"
MAX_LENGTH = 512
HEAD_TOKENS = 256
TAIL_TOKENS = 256
THRESHOLD = 0.9  # matches D2 evaluation config (threshold=0.9)

_ROOT = Path(__file__).parent.parent.parent  # LAMPS project root

PACKAGES: dict[str, dict] = {
    "aio3": {
        "display_name": "aio3",
        "version": "0.2.8",
        "type": "malicious",
        "description": "Typosquat của aiohttp. Đánh cắp environment variables và gửi về server của attacker.",
        "files": [_ROOT / "D2_dataset/malicious/aio3_014_93b5dfbe.py"],
        "sample_source": "local D2 malicious fixture",
        "strategy_demo": False,
    },
    "dfdfdfdfhhh": {
        "display_name": "dfdfdfdfhhh",
        "version": "1.0.0",
        "type": "malicious",
        "description": "Middle-zone evasion: whitespace padding đẩy exec(base64.b64decode(...)) vào token 256–511.",
        "files": [_ROOT / "D2_dataset/malicious/dfdfdfdfhhh_000_092363ea.py"],
        "sample_source": "local D2 malicious fixture",
        "strategy_demo": True,
    },
    "click": {
        "display_name": "click-8.3.2",
        "version": "8.3.2",
        "type": "benign",
        "description": "CLI framework của Pallets Project. Dùng trong Flask, pip, AWS CLI. Hoàn toàn sạch.",
        "files": [
            _ROOT / "D2_dataset/benign/click-8.3.2_000_b8af114e.py",
            _ROOT / "D2_dataset/benign/click-8.3.2_001_bdbf270e.py",
            _ROOT / "D2_dataset/benign/click-8.3.2_002_7a180614.py",
        ],
        "sample_source": "local D2 benign fixture",
        "strategy_demo": False,
    },
}

_tokenizer = None
_model = None
_device: torch.device | None = None


def load_model() -> None:
    global _tokenizer, _model, _device
    _device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    _tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    _model = AutoModelForSequenceClassification.from_pretrained(MODEL_ID).to(_device)
    _model.eval()
    _dummy = _tokenizer("warmup", return_tensors="pt", max_length=8, truncation=True).to(_device)
    with torch.no_grad():
        _model(**_dummy)


def _head_tail_text(text: str) -> str:
    ids = _tokenizer.encode(text, add_special_tokens=False, truncation=False)
    if len(ids) <= HEAD_TOKENS + TAIL_TOKENS:
        return text
    head = _tokenizer.decode(ids[:HEAD_TOKENS], skip_special_tokens=True)
    tail = _tokenizer.decode(ids[-TAIL_TOKENS:], skip_special_tokens=True)
    return head + "\n" + tail


def _infer(text: str, strategy: str) -> float:
    processed = _head_tail_text(text) if strategy == "head_tail" else text
    enc = _tokenizer(
        processed,
        max_length=MAX_LENGTH,
        truncation=True,
        padding=True,
        return_tensors="pt",
    ).to(_device)
    with torch.no_grad():
        logits = _model(**enc).logits
        prob = torch.sigmoid(
            logits[:, 1] if logits.shape[-1] > 1 else logits.squeeze(-1)
        ).item()
    return prob


def scan_package(package_id: str, strategy: Literal["head", "head_tail"] = "head") -> dict:
    pkg = PACKAGES[package_id]
    file_results = []
    payload_evidence = []
    loaded_files: list[tuple[Path, str]] = []
    for fpath in pkg["files"]:
        content = fpath.read_text(encoding="utf-8", errors="ignore")
        loaded_files.append((fpath, content))
        token_ids = _tokenizer.encode(content, add_special_tokens=False, truncation=False)
        token_count = len(token_ids)
        prob = _infer(content, strategy)
        file_evidence = _demo_payload_evidence(inspect_payloads(content, filename=fpath.name))
        payload_evidence.extend(file_evidence)
        file_results.append({
            "filename": fpath.name,
            "sha256": hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest(),
            "token_count": token_count,
            "is_truncated": token_count > MAX_LENGTH,
            "probability": round(prob, 4),
            "label": "malicious" if prob >= THRESHOLD else "benign",
            "preview": content[:500].strip(),
            "payload_evidence_count": len(file_evidence),
        })

    verdict = "malicious" if any(r["label"] == "malicious" for r in file_results) else "benign"
    response = {
        "package_id": package_id,
        "display_name": pkg["display_name"],
        "description": pkg["description"],
        "strategy": strategy,
        "strategy_demo": pkg["strategy_demo"],
        "provenance": {
            "sample_source": pkg["sample_source"],
            "package": pkg["display_name"],
            "version": pkg["version"],
            "local_paths": [_relative_path(fpath) for fpath, _ in loaded_files],
        },
        "sandbox": {
            "analysis_mode": "static",
            "executed": False,
            "network_blocked": True,
        },
        "payload_evidence": payload_evidence,
        "files": file_results,
        "verdict": verdict,
        "file_count": len(file_results),
        "truncated_count": sum(1 for r in file_results if r["is_truncated"]),
    }
    comparison = _strategy_comparison(pkg, loaded_files)
    if comparison is not None:
        response["strategy_comparison"] = comparison
    return response


def _strategy_comparison(pkg: dict, loaded_files: list[tuple[Path, str]]) -> dict | None:
    if not pkg["strategy_demo"] or not loaded_files:
        return None
    _, content = loaded_files[0]
    head = _infer(content, "head")
    head_tail = _infer(content, "head_tail")
    return {
        "head": round(head, 4),
        "head_tail": round(head_tail, 4),
        "threshold": THRESHOLD,
        "head_label": "malicious" if head >= THRESHOLD else "benign",
        "head_tail_label": "malicious" if head_tail >= THRESHOLD else "benign",
    }


def _relative_path(path: Path) -> str:
    try:
        return path.relative_to(_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _demo_payload_evidence(evidence: list[dict]) -> list[dict]:
    has_payload_anchor = any(
        item["kind"] in {"decoded_base64", "base64_decode_error", "base64_skipped", "persistence_indicator"}
        or item.get("source") == "decoded"
        for item in evidence
    )
    return evidence if has_payload_anchor else []
