from __future__ import annotations

import json
import os
import tarfile
import uuid
import zipfile
from pathlib import Path
from typing import List

from pydantic import BaseModel, Field

try:
    from crewai.tools import BaseTool
except ImportError:  # pragma: no cover
    from crewai_tools import BaseTool


class ArchiveExtractorInput(BaseModel):
    archive_path: str = Field(..., description="Absolute path to downloaded package archive.")


class ArchiveExtractorTool(BaseTool):
    name: str = "archive_python_extractor"
    description: str = (
        "Extract a package archive and select executable Python files while excluding tests/docs/config files."
    )
    args_schema: type[BaseModel] = ArchiveExtractorInput

    def _run(self, archive_path: str) -> str:
        src_archive = Path(archive_path).resolve()
        if not src_archive.exists() or not src_archive.is_file():
            raise FileNotFoundError(f"Archive not found: {src_archive}")

        selection_mode = (
            os.getenv("LAMPS_EXTRACT_MODE")
            or os.getenv("LAMPS_EVALUATION_MODE")
            or "D2"
        ).strip().upper()

        extract_base = Path(os.getenv("LAMPS_EXTRACT_DIR", "artifacts/extracted")).resolve()
        work_dir = extract_base / f"run_{uuid.uuid4().hex[:8]}"
        work_dir.mkdir(parents=True, exist_ok=True)

        self._extract_archive(src_archive, work_dir)

        selected_files: List[str] = []
        excluded_files: List[str] = []
        excluded_details: List[dict[str, str]] = []

        for py_file in sorted(
            work_dir.rglob("*.py"),
            key=lambda p: p.relative_to(work_dir).as_posix().lower(),
        ):
            rel_path = py_file.relative_to(work_dir)
            rel_str = rel_path.as_posix().lower()
            abs_path = str(py_file.resolve())

            reason = self._exclusion_reason(rel_str, selection_mode)
            if reason:
                excluded_files.append(abs_path)
                excluded_details.append(
                    {
                        "file_path": abs_path,
                        "reason": reason,
                    }
                )
            else:
                selected_files.append(abs_path)

        payload = {
            "selected_files": sorted(selected_files),
            "excluded_files": sorted(excluded_files),
            "excluded_details": sorted(excluded_details, key=lambda item: item["file_path"].lower()),
            "selection_mode": selection_mode,
        }
        return json.dumps(payload, ensure_ascii=False)

    def _extract_archive(self, archive_path: Path, target_dir: Path) -> None:
        lower_name = archive_path.name.lower()

        if lower_name.endswith(".whl") or lower_name.endswith(".zip"):
            with zipfile.ZipFile(archive_path, "r") as zf:
                self._safe_extract_zip(zf, target_dir)
            return

        if lower_name.endswith((".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".tar")):
            with tarfile.open(archive_path, "r:*") as tf:
                self._safe_extract_tar(tf, target_dir)
            return

        raise ValueError(f"Unsupported archive format: {archive_path}")

    @staticmethod
    def _safe_extract_zip(zf: zipfile.ZipFile, target_dir: Path) -> None:
        for member in zf.infolist():
            member_path = (target_dir / member.filename).resolve()
            if not ArchiveExtractorTool._is_relative_to(member_path, target_dir):
                raise ValueError(f"Unsafe zip member path detected: {member.filename}")
        zf.extractall(target_dir)

    @staticmethod
    def _safe_extract_tar(tf: tarfile.TarFile, target_dir: Path) -> None:
        for member in tf.getmembers():
            member_path = (target_dir / member.name).resolve()
            if not ArchiveExtractorTool._is_relative_to(member_path, target_dir):
                raise ValueError(f"Unsafe tar member path detected: {member.name}")
        tf.extractall(target_dir)

    @staticmethod
    def _is_relative_to(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False

    @staticmethod
    def _exclusion_reason(relative_path_lower: str, selection_mode: str) -> str | None:
        parts = relative_path_lower.split("/")
        filename = parts[-1]

        if selection_mode == "D1":
            if filename != "setup.py":
                return "mode_filter_non_setup"
            return None

        excluded_dirs = {
            "tests",
            "test",
            "testing",
            "docs",
            "doc",
            "examples",
            "example",
            "benchmarks",
            "benchmark",
            ".github",
            "ci",
            "configs",
            "config",
        }

        if any(part in excluded_dirs for part in parts):
            return "excluded_directory"

        if filename.startswith("test_") or filename.endswith("_test.py"):
            return "test_naming_pattern"

        config_files = {
            "conftest.py",
            "noxfile.py",
            "toxfile.py",
            "sphinx_conf.py",
            "manage.py",
        }

        if filename in config_files:
            return "config_script"

        return None
