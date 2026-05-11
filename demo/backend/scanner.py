"""LAMPS demo scanner — CodeBERT inference for web demo."""
from __future__ import annotations

from pathlib import Path
from typing import Literal

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

MODEL_ID = "KevinPhamH/codebert-finetuned"
MAX_LENGTH = 512
HEAD_TOKENS = 256
TAIL_TOKENS = 256
THRESHOLD = 0.9  # matches D2 evaluation config (threshold=0.9)

_ROOT = Path(__file__).parent.parent.parent  # LAMPS project root

PACKAGES: dict[str, dict] = {
    "aio3": {
        "display_name": "aio3",
        "type": "malicious",
        "description": "Typosquat của aiohttp. Đánh cắp environment variables và gửi về server của attacker.",
        "files": [_ROOT / "D2_dataset/malicious/aio3_014_93b5dfbe.py"],
        "strategy_demo": False,
    },
    "dfdfdfdfhhh": {
        "display_name": "dfdfdfdfhhh",
        "type": "malicious",
        "description": "Middle-zone evasion: whitespace padding đẩy exec(base64.b64decode(...)) vào token 256–511.",
        "files": [_ROOT / "D2_dataset/malicious/dfdfdfdfhhh_000_092363ea.py"],
        "strategy_demo": True,
    },
    "click": {
        "display_name": "click-8.3.2",
        "type": "benign",
        "description": "CLI framework của Pallets Project. Dùng trong Flask, pip, AWS CLI. Hoàn toàn sạch.",
        "files": [
            _ROOT / "D2_dataset/benign/click-8.3.2_000_b8af114e.py",
            _ROOT / "D2_dataset/benign/click-8.3.2_001_bdbf270e.py",
            _ROOT / "D2_dataset/benign/click-8.3.2_002_7a180614.py",
        ],
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
    for fpath in pkg["files"]:
        content = fpath.read_text(encoding="utf-8", errors="ignore")
        token_ids = _tokenizer.encode(content, add_special_tokens=False, truncation=False)
        token_count = len(token_ids)
        prob = _infer(content, strategy)
        file_results.append({
            "filename": fpath.name,
            "token_count": token_count,
            "is_truncated": token_count > MAX_LENGTH,
            "probability": round(prob, 4),
            "label": "malicious" if prob >= THRESHOLD else "benign",
            "preview": content[:500].strip(),
        })

    verdict = "malicious" if any(r["label"] == "malicious" for r in file_results) else "benign"
    return {
        "package_id": package_id,
        "display_name": pkg["display_name"],
        "description": pkg["description"],
        "strategy": strategy,
        "strategy_demo": pkg["strategy_demo"],
        "files": file_results,
        "verdict": verdict,
        "file_count": len(file_results),
        "truncated_count": sum(1 for r in file_results if r["is_truncated"]),
    }
