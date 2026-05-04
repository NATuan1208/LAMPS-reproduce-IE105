from __future__ import annotations

import argparse
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid

from dotenv import load_dotenv
from crewai import Agent, Crew, LLM, Process, Task

from llms.codebert_llm import CodeBERTClassifierLLM
from runtime.settings import LampsSettings
from schemas.output_schemas import (
    BinaryVerdict,
    ClassifierBatchResult,
    ExtractionResult,
    FileClassificationResult,
    FetchResult,
    FinalVerdictResult,
    compute_conservative_verdict,
    validate_classification_coverage,
)
from tools.archive_extractor import ArchiveExtractorTool
from tools.pypi_downloader import PyPIDownloaderTool
from tools.python_file_reader import PythonFileReaderTool


def _build_reasoning_llm(settings: LampsSettings) -> LLM:
    if not settings.reasoning_api_key:
        raise ValueError("Missing reasoning API key in resolved settings.")

    llm_kwargs: Dict[str, Any] = {
        "model": settings.reasoning_model,
        "api_key": settings.reasoning_api_key,
        "temperature": 0,
    }
    if settings.reasoning_base_url:
        llm_kwargs["base_url"] = settings.reasoning_base_url

    return LLM(**llm_kwargs)


def _build_codebert_llm(settings: LampsSettings) -> CodeBERTClassifierLLM:
    return CodeBERTClassifierLLM(
        model_id=settings.codebert_model_id,
        threshold=0.5,
        device=settings.codebert_device,
        hf_token=settings.hf_token,
    )


def _normalize_package_inputs(
    package_spec: Optional[str],
    package_name: Optional[str],
    package_version: Optional[str],
) -> Dict[str, str]:
    spec = (package_spec or "").strip()
    name = (package_name or "").strip()
    version = (package_version or "").strip()

    if spec:
        resolved_spec = spec
    elif name and version:
        resolved_spec = f"{name}=={version}"
    elif name:
        resolved_spec = name
    else:
        raise ValueError("Provide either --package_spec or --package_name (optionally with --package_version).")

    return {
        "package_spec": resolved_spec,
        "package_name": name,
        "package_version": version,
    }


def build_crew(settings: Optional[LampsSettings] = None) -> Crew:
    settings = settings or LampsSettings.from_env()
    reasoning_llm = _build_reasoning_llm(settings)
    codebert_llm = _build_codebert_llm(settings)

    fetcher_agent = Agent(
        role="FetcherAgent",
        goal="Resolve package identity and download its archive from PyPI.",
        backstory=(
            "You are precise in resolving package specs and always return strict structured output."
        ),
        llm=reasoning_llm,
        tools=[PyPIDownloaderTool()],
        allow_delegation=False,
        verbose=True,
    )

    extractor_agent = Agent(
        role="ExtractorAgent",
        goal="Extract archives and keep only executable Python files for static analysis.",
        backstory=(
            "You apply strict selection policy: exclude tests, docs, and config-focused files."
        ),
        llm=reasoning_llm,
        tools=[ArchiveExtractorTool()],
        allow_delegation=False,
        verbose=True,
    )

    classifier_agent = Agent(
        role="ClassifierAgent",
        goal="Classify each selected Python file as MALICIOUS or BENIGN.",
        backstory=(
            "You are powered by a fine-tuned CodeBERT binary classifier and must produce deterministic JSON."
        ),
        llm=codebert_llm,
        tools=[PythonFileReaderTool()],
        allow_delegation=False,
        verbose=True,
    )

    verdict_agent = Agent(
        role="VerdictAgent",
        goal="Aggregate file-level decisions into a package-level conservative verdict.",
        backstory=(
            "You prioritize safety: one malicious file is enough to mark the full package as malicious."
        ),
        llm=reasoning_llm,
        allow_delegation=False,
        verbose=True,
    )

    fetch_task = Task(
        description=(
            "Resolve the target package from provided inputs.\n"
            "Inputs:\n"
            "- package_spec: {package_spec}\n"
            "- package_name: {package_name}\n"
            "- package_version: {package_version}\n\n"
            "Rules:\n"
            "1) Use package_spec if provided.\n"
            "2) If package_spec is empty, build spec from package_name and package_version.\n"
            "3) Call tool 'pypi_downloader' exactly once with final spec.\n"
            "4) Return only JSON with keys: name, version, archive_path, url."
        ),
        expected_output="JSON object that matches FetchResult schema.",
        agent=fetcher_agent,
        output_pydantic=FetchResult,
    )

    extract_task = Task(
        description=(
            "Read archive_path from FetchResult in context and analyze package archive.\n"
            "Use tool 'archive_python_extractor' once with archive_path.\n"
            "Select only executable .py files and exclude tests/docs/config files.\n"
            "Return only JSON with keys: selected_files, excluded_files."
        ),
        expected_output="JSON object that matches ExtractionResult schema.",
        agent=extractor_agent,
        context=[fetch_task],
        output_pydantic=ExtractionResult,
    )

    classify_task = Task(
        description=(
            "Process ExtractionResult.selected_files from context.\n"
            "For EACH path in selected_files, do this loop explicitly:\n"
            "1) Use tool 'python_file_reader' to read file content.\n"
            "2) Classify that file individually with binary output MALICIOUS or BENIGN and confidence score.\n"
            "3) Add one JSON item with file_path, prediction, probability.\n"
            "Return only JSON object with key 'results' containing the full array."
        ),
        expected_output="JSON object that matches ClassifierBatchResult schema.",
        agent=classifier_agent,
        context=[extract_task],
        output_pydantic=ClassifierBatchResult,
    )

    verdict_task = Task(
        description=(
            "Aggregate ClassifierBatchResult from context using Conservative Aggregation Policy.\n"
            "Critical rule: if ANY file prediction is MALICIOUS, final package verdict MUST be MALICIOUS.\n"
            "If all files are BENIGN, final verdict is BENIGN.\n"
            "Produce natural language justification that references evidence from file_results.\n"
            "Return only JSON with keys: package_name, package_version, final_verdict, justification, file_results."
        ),
        expected_output="JSON object that matches FinalVerdictResult schema.",
        agent=verdict_agent,
        context=[fetch_task, classify_task],
        output_pydantic=FinalVerdictResult,
    )

    return Crew(
        agents=[fetcher_agent, extractor_agent, classifier_agent, verdict_agent],
        tasks=[fetch_task, extract_task, classify_task, verdict_task],
        process=Process.sequential,
        verbose=True,
    )


def _result_to_dict(result: Any) -> Dict[str, Any]:
    if hasattr(result, "pydantic") and result.pydantic is not None:
        model_obj = result.pydantic
        if hasattr(model_obj, "model_dump"):
            return model_obj.model_dump()
        if hasattr(model_obj, "dict"):
            return model_obj.dict()

    raw = getattr(result, "raw", None)
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"raw": raw}

    if isinstance(raw, dict):
        return raw

    return {"raw": str(result)}


def _json_or_none(payload: str) -> Dict[str, Any] | None:
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return None


def _fallback_justification(
    package_name: str,
    package_version: str,
    final_verdict: BinaryVerdict,
    file_results: List[FileClassificationResult],
    missing_files: List[str],
) -> str:
    malicious_files = [item.file_path for item in file_results if item.prediction == BinaryVerdict.MALICIOUS]
    if final_verdict == BinaryVerdict.MALICIOUS:
        detail = ", ".join(malicious_files[:3]) if malicious_files else "no file-level evidence was produced"
        if missing_files:
            return (
                f"Package {package_name}=={package_version} is MALICIOUS because at least one file is malicious "
                f"or classification coverage is incomplete. Evidence: {detail}. Missing files: {len(missing_files)}."
            )
        return (
            f"Package {package_name}=={package_version} is MALICIOUS because at least one analyzed file was "
            f"classified as MALICIOUS. Evidence: {detail}."
        )

    return (
        f"Package {package_name}=={package_version} is BENIGN because all selected files were classified as BENIGN "
        "under deterministic conservative aggregation."
    )


def _try_reasoning_justification(
    reasoning_llm: LLM,
    package_name: str,
    package_version: str,
    final_verdict: BinaryVerdict,
    file_results: List[FileClassificationResult],
    missing_files: List[str],
) -> str:
    suspicious = [item for item in file_results if item.prediction == BinaryVerdict.MALICIOUS]
    evidence_lines = [
        f"- {item.file_path} => {item.prediction} ({item.probability:.4f})"
        for item in suspicious[:8]
    ]
    if missing_files:
        evidence_lines.append(f"- missing_classifications={len(missing_files)}")

    prompt = (
        "You are VerdictAgent in a software supply-chain security pipeline. "
        "Write a concise plain-text justification (2-4 sentences). "
        "Reference concrete file paths from evidence when possible. "
        f"Package: {package_name}=={package_version}\n"
        f"Final deterministic verdict: {final_verdict}\n"
        f"Evidence:\n{os.linesep.join(evidence_lines) if evidence_lines else '- no malicious evidence'}"
    )

    try:
        response = reasoning_llm.call(prompt)
        if isinstance(response, str) and response.strip():
            return response.strip()
    except Exception:
        pass

    return _fallback_justification(package_name, package_version, final_verdict, file_results, missing_files)


def _run_deterministic_pipeline(
    settings: LampsSettings,
    package_spec: str,
    trace_id: str,
) -> Dict[str, Any]:
    fetch_tool = PyPIDownloaderTool()
    extract_tool = ArchiveExtractorTool()
    read_tool = PythonFileReaderTool()
    codebert_llm = _build_codebert_llm(settings)
    reasoning_enabled = (os.getenv("LAMPS_ENABLE_REASONING_JUSTIFICATION", "false") or "false").strip().lower() == "true"

    fetch_raw = fetch_tool._run(package=package_spec)
    fetch_data = _json_or_none(fetch_raw)
    if not fetch_data:
        raise RuntimeError("Fetcher tool did not return valid JSON.")
    fetch_result = FetchResult.model_validate(fetch_data)

    extract_raw = extract_tool._run(archive_path=fetch_result.archive_path)
    extract_data = _json_or_none(extract_raw)
    if not extract_data:
        raise RuntimeError("Extractor tool did not return valid JSON.")
    extraction_result = ExtractionResult.model_validate(extract_data)

    selected_files = extraction_result.selected_files
    empty_policy = BinaryVerdict(settings.empty_selection_policy)

    file_results: List[FileClassificationResult] = []
    missing_files: List[str] = []
    duplicate_files: List[str] = []
    unexpected_files: List[str] = []

    if selected_files:
        for file_path in selected_files:
            code_text = read_tool._run(file_path=file_path)
            last_error: str | None = None

            for _ in range(settings.classification_retries + 1):
                try:
                    response_raw = codebert_llm.call(json.dumps({"file_path": file_path, "code": code_text}))
                    response_data = _json_or_none(response_raw)
                    if not response_data:
                        raise ValueError("Classifier output is not valid JSON.")

                    prediction = str(response_data.get("prediction", "")).upper().strip()
                    probability = float(response_data.get("probability", 0.0))
                    if prediction not in {BinaryVerdict.MALICIOUS.value, BinaryVerdict.BENIGN.value}:
                        raise ValueError(f"Unsupported prediction label: {prediction}")

                    file_results.append(
                        FileClassificationResult(
                            file_path=file_path,
                            prediction=BinaryVerdict(prediction),
                            probability=probability,
                            evidence=[],
                            error=None,
                        )
                    )
                    last_error = None
                    break
                except Exception as exc:
                    last_error = str(exc)

            if last_error:
                file_results.append(
                    FileClassificationResult(
                        file_path=file_path,
                        prediction=BinaryVerdict.MALICIOUS,
                        probability=1.0,
                        evidence=["classification_fallback"],
                        error=last_error,
                    )
                )

        missing_files, duplicate_files, unexpected_files = validate_classification_coverage(selected_files, file_results)

        if missing_files:
            for missing_path in missing_files:
                file_results.append(
                    FileClassificationResult(
                        file_path=missing_path,
                        prediction=BinaryVerdict.MALICIOUS,
                        probability=1.0,
                        evidence=["coverage_fallback_missing_file"],
                        error="Missing classifier output. Forced MALICIOUS by safety policy.",
                    )
                )

    batch_result = ClassifierBatchResult(
        results=file_results,
        selected_file_count=len(selected_files),
        missing_files=missing_files,
        duplicate_result_files=duplicate_files,
        unexpected_files=unexpected_files,
    )

    final_verdict = compute_conservative_verdict(file_results, empty_policy=empty_policy)
    if reasoning_enabled:
        reasoning_llm = _build_reasoning_llm(settings)
        justification = _try_reasoning_justification(
            reasoning_llm=reasoning_llm,
            package_name=fetch_result.name,
            package_version=fetch_result.version,
            final_verdict=final_verdict,
            file_results=file_results,
            missing_files=missing_files,
        )
    else:
        justification = _fallback_justification(
            package_name=fetch_result.name,
            package_version=fetch_result.version,
            final_verdict=final_verdict,
            file_results=file_results,
            missing_files=missing_files,
        )

    final_result = FinalVerdictResult(
        package_name=fetch_result.name,
        package_version=fetch_result.version,
        final_verdict=final_verdict,
        justification=justification,
        file_results=file_results,
        trace_id=trace_id,
    )

    return {
        "trace_id": trace_id,
        "fetch": fetch_result.model_dump(),
        "extraction": extraction_result.model_dump(),
        "classification": batch_result.model_dump(),
        "final": final_result.model_dump(),
    }


def _default_output_path() -> Path:
    output_dir = Path(os.getenv("LAMPS_OUTPUT_DIR", "outputs")).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return output_dir / f"lamps_verdict_{ts}.json"


def run_pipeline(
    package_spec: Optional[str],
    package_name: Optional[str],
    package_version: Optional[str],
    output_path: Optional[str],
    use_crewai: bool = False,
) -> Dict[str, Any]:
    load_dotenv()
    settings = LampsSettings.from_env()
    normalized_inputs = _normalize_package_inputs(package_spec, package_name, package_version)
    trace_id = uuid.uuid4().hex

    if use_crewai:
        crew = build_crew(settings)
        result = crew.kickoff(inputs=normalized_inputs)
        final_payload = _result_to_dict(result)
    else:
        final_payload = _run_deterministic_pipeline(
            settings=settings,
            package_spec=normalized_inputs["package_spec"],
            trace_id=trace_id,
        )

    save_path = Path(output_path).resolve() if output_path else (settings.output_dir.resolve() / _default_output_path().name)
    save_path.parent.mkdir(parents=True, exist_ok=True)
    save_path.write_text(json.dumps(final_payload, ensure_ascii=False, indent=2), encoding="utf-8")

    print(json.dumps(final_payload, ensure_ascii=False, indent=2))
    print(f"Saved final verdict to: {save_path}")

    return final_payload


def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(description="LAMPS CrewAI sequential orchestrator.")
    parser.add_argument("--package_spec", type=str, default="", help="Package spec, e.g. requests==2.31.0")
    parser.add_argument("--package_name", type=str, default="", help="Package name only")
    parser.add_argument("--package_version", type=str, default="", help="Package version")
    parser.add_argument(
        "--use_crewai",
        action="store_true",
        help="Use direct CrewAI kickoff path. Default path is deterministic orchestrator.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="",
        help="Optional output file path. If omitted, writes to outputs/lamps_verdict_*.json",
    )

    args = parser.parse_args()
    run_pipeline(
        package_spec=args.package_spec,
        package_name=args.package_name,
        package_version=args.package_version,
        output_path=args.output or None,
        use_crewai=args.use_crewai,
    )


if __name__ == "__main__":
    main()
