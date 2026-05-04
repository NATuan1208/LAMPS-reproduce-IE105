from __future__ import annotations

import json
import os
from threading import Lock
from typing import Any, ClassVar, Dict, Iterable, Optional

import torch
from pydantic import PrivateAttr
from transformers import AutoModelForSequenceClassification, AutoTokenizer

try:
    from crewai import BaseLLM
except ImportError:  # pragma: no cover - fallback for older/newer CrewAI package layouts
    from crewai.llms.base_llm import BaseLLM


class CodeBERTClassifierLLM(BaseLLM):
    """CrewAI BaseLLM wrapper for a binary CodeBERT sequence classifier."""

    MAX_LENGTH: ClassVar[int] = 400

    threshold: float = 0.5
    device_name: str = "auto"
    hf_token: Optional[str] = None

    _device: torch.device = PrivateAttr()
    _model_obj: Any = PrivateAttr(default=None)
    _tokenizer_obj: Any = PrivateAttr(default=None)
    _load_lock: Lock = PrivateAttr(default_factory=Lock)

    def __init__(
        self,
        model_id: Optional[str] = None,
        threshold: float = 0.5,
        device: str = "auto",
        hf_token: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        resolved_model_id = model_id or os.getenv("CODEBERT_MODEL_ID")
        if not resolved_model_id:
            raise ValueError("CODEBERT_MODEL_ID is required to initialize CodeBERTClassifierLLM.")

        super().__init__(
            model=resolved_model_id,
            temperature=0,
            threshold=threshold,
            device_name=device,
            hf_token=hf_token or os.getenv("HF_TOKEN"),
            **kwargs,
        )
        self._device = self._resolve_device(self.device_name)

    def supports_function_calling(self) -> bool:
        return False

    def get_context_window_size(self) -> int:
        return self.MAX_LENGTH

    def call(self, prompt: Any, *args: Any, **kwargs: Any) -> str:
        """
        Return JSON string: {"prediction": "MALICIOUS|BENIGN", "probability": float}

        The prompt may be:
        - Raw source code string.
        - JSON string/object containing a "code" field.
        - A list of chat messages from CrewAI.
        """
        code_text = self._extract_code(prompt)
        if not code_text.strip():
            raise ValueError("CodeBERTClassifierLLM received empty code input.")

        probability = self._predict_probability(code_text)
        prediction = "MALICIOUS" if probability >= self.threshold else "BENIGN"

        return json.dumps(
            {
                "prediction": prediction,
                "probability": round(probability, 6),
            },
            ensure_ascii=False,
        )

    def _load_model(self) -> None:
        if self._model_obj is not None and self._tokenizer_obj is not None:
            return

        with self._load_lock:
            if self._model_obj is not None and self._tokenizer_obj is not None:
                return

            model_kwargs = self._hf_auth_kwargs()
            self._tokenizer_obj = AutoTokenizer.from_pretrained(self.model, **model_kwargs)
            self._model_obj = AutoModelForSequenceClassification.from_pretrained(self.model, **model_kwargs)
            self._model_obj.to(self._device)
            self._model_obj.eval()

    def _predict_probability(self, code_text: str) -> float:
        self._load_model()

        encoded = self._tokenizer_obj(
            [code_text],
            max_length=self.MAX_LENGTH,
            truncation=True,
            padding=True,
            return_tensors="pt",
        )
        encoded = {key: value.to(self._device) for key, value in encoded.items()}

        with torch.no_grad():
            logits = self._model_obj(**encoded).logits
            probability_tensor = torch.sigmoid(logits).squeeze(-1)

        if probability_tensor.ndim == 0:
            return float(probability_tensor.item())

        return float(probability_tensor[0].item())

    def _extract_code(self, prompt: Any) -> str:
        if isinstance(prompt, str):
            return self._extract_code_from_text(prompt)

        if isinstance(prompt, dict):
            return self._extract_code_from_payload(prompt)

        if isinstance(prompt, Iterable):
            chunks = []
            for item in prompt:
                if isinstance(item, dict):
                    content = item.get("content", "")
                    if isinstance(content, list):
                        for part in content:
                            if isinstance(part, dict):
                                chunks.append(str(part.get("text", "")))
                            else:
                                chunks.append(str(part))
                    else:
                        chunks.append(str(content))
                else:
                    chunks.append(str(item))
            return self._extract_code_from_text("\n".join(chunks))

        return self._extract_code_from_text(str(prompt))

    def _extract_code_from_text(self, text: str) -> str:
        stripped = text.strip()
        if not stripped:
            return ""

        try:
            payload = json.loads(stripped)
            if isinstance(payload, dict):
                return self._extract_code_from_payload(payload)
        except json.JSONDecodeError:
            pass

        return stripped

    @staticmethod
    def _extract_code_from_payload(payload: Dict[str, Any]) -> str:
        for candidate_key in ("code", "source", "text", "input"):
            value = payload.get(candidate_key)
            if isinstance(value, str):
                return value

        return json.dumps(payload, ensure_ascii=False)

    @staticmethod
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

    def _hf_auth_kwargs(self) -> Dict[str, Any]:
        if not self.hf_token:
            return {}

        return {
            "token": self.hf_token,
        }
