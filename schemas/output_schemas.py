from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import List, Sequence

from pydantic import BaseModel, Field, model_validator


class BinaryVerdict(str, Enum):
    MALICIOUS = "MALICIOUS"
    BENIGN = "BENIGN"


class FetchProvenance(BaseModel):
    retrieved_at_utc: str = Field(..., description="UTC timestamp when artifact retrieval completed.")
    source: str = Field(default="pip_download", description="Artifact retrieval source.")
    archive_sha256: str = Field(..., description="SHA256 checksum of downloaded archive.")
    run_id: str = Field(..., description="Unique run identifier for traceability.")


class FetchResult(BaseModel):
    name: str = Field(..., description="Canonical package name.")
    version: str = Field(..., description="Resolved package version.")
    archive_path: str = Field(..., description="Absolute path to downloaded archive.")
    url: str = Field(..., description="Resolved package URL.")
    resolved_spec: str | None = Field(default=None, description="Resolved package spec (name or name==version).")
    note: str | None = Field(default=None, description="Optional fetcher note about corrections/disambiguation.")
    provenance: FetchProvenance | None = Field(default=None, description="Retrieval provenance metadata.")


class ExcludedFileRecord(BaseModel):
    file_path: str = Field(..., description="Absolute path of excluded Python file.")
    reason: str = Field(..., description="Exclusion reason, e.g., test, docs, config, or mode_filter.")


class ExtractionResult(BaseModel):
    selected_files: List[str] = Field(
        default_factory=list,
        description="Executable .py files selected for classification.",
    )
    excluded_files: List[str] = Field(
        default_factory=list,
        description="Files excluded from analysis due to policy filters.",
    )
    excluded_details: List[ExcludedFileRecord] = Field(
        default_factory=list,
        description="Excluded files with explicit reason for auditability.",
    )
    selection_mode: str = Field(
        default="D2",
        description="Extraction mode, e.g., D1_SETUP_ONLY or D2.",
    )


class FileClassificationResult(BaseModel):
    file_path: str = Field(..., description="Absolute path to analyzed Python file.")
    prediction: BinaryVerdict = Field(..., description="Binary file-level verdict.")
    probability: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Probability of MALICIOUS class from CodeBERT sigmoid output.",
    )
    evidence: List[str] = Field(
        default_factory=list,
        description="Optional evidence tags or notes produced during classification.",
    )
    error: str | None = Field(
        default=None,
        description="Optional error note if fallback logic was needed.",
    )


class ClassifierBatchResult(BaseModel):
    results: List[FileClassificationResult] = Field(
        default_factory=list,
        description="Classification output for each selected Python file.",
    )
    selected_file_count: int = Field(
        default=0,
        ge=0,
        description="Number of files expected to be classified.",
    )
    missing_files: List[str] = Field(
        default_factory=list,
        description="Selected files that were not returned by classifier.",
    )
    duplicate_result_files: List[str] = Field(
        default_factory=list,
        description="Files that appeared multiple times in classifier output.",
    )
    unexpected_files: List[str] = Field(
        default_factory=list,
        description="Classifier outputs for files not present in selected list.",
    )


class FinalVerdictResult(BaseModel):
    package_name: str = Field(..., description="Resolved package name.")
    package_version: str = Field(..., description="Resolved package version.")
    final_verdict: BinaryVerdict = Field(..., description="Package-level conservative verdict.")
    justification: str = Field(
        ...,
        min_length=5,
        description="Natural language explanation of final verdict.",
    )
    file_results: List[FileClassificationResult] = Field(
        default_factory=list,
        description="All file-level classifications used in verdict aggregation.",
    )
    trace_id: str = Field(..., description="Trace identifier for this package verdict.")
    created_at_utc: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="UTC timestamp of final verdict generation.",
    )

    @model_validator(mode="after")
    def validate_conservative_policy(self) -> "FinalVerdictResult":
        if self.file_results:
            computed_verdict = compute_conservative_verdict(self.file_results)
            if self.final_verdict != computed_verdict:
                raise ValueError(
                    "Conservative aggregation violation: final_verdict does not match file-level conservative policy."
                )

        return self


def compute_conservative_verdict(
    file_results: Sequence[FileClassificationResult],
    empty_policy: BinaryVerdict = BinaryVerdict.MALICIOUS,
) -> BinaryVerdict:
    if not file_results:
        return empty_policy

    if any(item.prediction == BinaryVerdict.MALICIOUS for item in file_results):
        return BinaryVerdict.MALICIOUS

    return BinaryVerdict.BENIGN


def validate_classification_coverage(
    selected_files: Sequence[str],
    file_results: Sequence[FileClassificationResult],
) -> tuple[list[str], list[str], list[str]]:
    selected_map: dict[str, str] = {path.lower(): path for path in selected_files}

    result_counts: dict[str, int] = {}
    result_originals: dict[str, str] = {}
    for item in file_results:
        key = item.file_path.lower()
        result_counts[key] = result_counts.get(key, 0) + 1
        result_originals[key] = item.file_path

    missing_files = sorted(
        [original for lowered, original in selected_map.items() if lowered not in result_counts],
        key=str.lower,
    )
    duplicate_files = sorted(
        [result_originals[key] for key, count in result_counts.items() if count > 1],
        key=str.lower,
    )
    unexpected_files = sorted(
        [result_originals[key] for key in result_counts if key not in selected_map],
        key=str.lower,
    )

    return missing_files, duplicate_files, unexpected_files
