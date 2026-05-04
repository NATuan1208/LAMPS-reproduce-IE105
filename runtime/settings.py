from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field, model_validator


class ReasoningProvider(str, Enum):
    AUTO = "auto"
    OPENAI = "openai"
    OPENROUTER = "openrouter"


class EvaluationMode(str, Enum):
    D1 = "D1"
    D2 = "D2"


class LampsSettings(BaseModel):
    codebert_model_id: str = Field(..., description="Fine-tuned CodeBERT model id on Hugging Face Hub.")
    codebert_device: str = Field(default="auto", description="CodeBERT device selection.")
    hf_token: Optional[str] = Field(default=None, description="Optional HF token for private models.")

    reasoning_model: str = Field(default="openai/gpt-4o-mini", description="Reasoning model id.")
    reasoning_provider: ReasoningProvider = Field(default=ReasoningProvider.AUTO)
    reasoning_api_key: str = Field(..., description="Resolved reasoning provider API key.")
    reasoning_base_url: Optional[str] = Field(default=None, description="Optional OpenAI-compatible base URL.")

    empty_selection_policy: str = Field(default="MALICIOUS", description="Policy when extractor yields no selected files.")
    evaluation_mode: EvaluationMode = Field(default=EvaluationMode.D1)

    output_dir: Path = Field(default_factory=lambda: Path("outputs"))
    classification_retries: int = Field(default=1, ge=0, le=3)

    @model_validator(mode="after")
    def validate_selection_policy(self) -> "LampsSettings":
        if self.empty_selection_policy not in {"MALICIOUS", "BENIGN"}:
            raise ValueError("LAMPS_EMPTY_SELECTION_POLICY must be MALICIOUS or BENIGN.")
        return self

    @classmethod
    def from_env(cls) -> "LampsSettings":
        codebert_model_id = (os.getenv("CODEBERT_MODEL_ID") or "").strip()
        if not codebert_model_id:
            raise ValueError("Missing CODEBERT_MODEL_ID.")
        if "your-username/" in codebert_model_id:
            raise ValueError(
                "CODEBERT_MODEL_ID is still a placeholder. Replace it with your friend's real fine-tuned HF repo id."
            )

        provider_raw = (os.getenv("LAMPS_REASONING_PROVIDER_PROFILE", "auto") or "auto").strip().lower()
        try:
            provider = ReasoningProvider(provider_raw)
        except ValueError as exc:
            raise ValueError(
                "LAMPS_REASONING_PROVIDER_PROFILE must be one of: auto, openai, openrouter."
            ) from exc

        reasoning_model = (os.getenv("LAMPS_REASONING_MODEL") or "openai/gpt-4o-mini").strip()
        configured_base_url = (os.getenv("LAMPS_REASONING_BASE_URL") or os.getenv("OPENROUTER_BASE_URL") or "").strip()
        openai_key = (os.getenv("OPENAI_API_KEY") or "").strip()
        openrouter_key = (os.getenv("OPENROUTER_API_KEY") or "").strip()
        generic_key = (os.getenv("LAMPS_REASONING_API_KEY") or "").strip()

        resolved_provider = provider
        resolved_base_url = configured_base_url or None
        resolved_key = ""

        if provider == ReasoningProvider.OPENROUTER:
            resolved_key = generic_key or openrouter_key
            resolved_base_url = resolved_base_url or "https://openrouter.ai/api/v1"
            if not resolved_key:
                raise ValueError(
                    "OpenRouter profile requires LAMPS_REASONING_API_KEY or OPENROUTER_API_KEY."
                )
        elif provider == ReasoningProvider.OPENAI:
            resolved_key = generic_key or openai_key
            if not resolved_key:
                raise ValueError(
                    "OpenAI profile requires LAMPS_REASONING_API_KEY or OPENAI_API_KEY."
                )
            if resolved_base_url and "openrouter" in resolved_base_url.lower():
                raise ValueError(
                    "OpenAI profile is incompatible with OpenRouter base URL."
                )
        else:
            if resolved_base_url and "openrouter" in resolved_base_url.lower():
                resolved_provider = ReasoningProvider.OPENROUTER
                resolved_key = generic_key or openrouter_key
                resolved_base_url = resolved_base_url or "https://openrouter.ai/api/v1"
            elif openrouter_key and not openai_key:
                resolved_provider = ReasoningProvider.OPENROUTER
                resolved_key = generic_key or openrouter_key
                resolved_base_url = resolved_base_url or "https://openrouter.ai/api/v1"
            else:
                resolved_provider = ReasoningProvider.OPENAI
                resolved_key = generic_key or openai_key

            if not resolved_key:
                raise ValueError(
                    "Unable to resolve reasoning credentials. Set LAMPS_REASONING_API_KEY or provider-specific keys."
                )

            if resolved_provider == ReasoningProvider.OPENAI and resolved_base_url and "openrouter" in resolved_base_url.lower():
                raise ValueError(
                    "Auto-detected OpenAI profile conflicts with OpenRouter base URL."
                )

        eval_mode_raw = (os.getenv("LAMPS_EVALUATION_MODE") or "D1").strip().upper()
        try:
            evaluation_mode = EvaluationMode(eval_mode_raw)
        except ValueError as exc:
            raise ValueError("LAMPS_EVALUATION_MODE must be D1 or D2.") from exc

        return cls(
            codebert_model_id=codebert_model_id,
            codebert_device=(os.getenv("CODEBERT_DEVICE") or "auto").strip(),
            hf_token=(os.getenv("HF_TOKEN") or "").strip() or None,
            reasoning_model=reasoning_model,
            reasoning_provider=resolved_provider,
            reasoning_api_key=resolved_key,
            reasoning_base_url=resolved_base_url,
            empty_selection_policy=(os.getenv("LAMPS_EMPTY_SELECTION_POLICY") or "MALICIOUS").strip().upper(),
            evaluation_mode=evaluation_mode,
            output_dir=Path((os.getenv("LAMPS_OUTPUT_DIR") or "outputs").strip() or "outputs"),
            classification_retries=int((os.getenv("LAMPS_CLASSIFICATION_RETRIES") or "1").strip()),
        )
